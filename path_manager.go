package quic

import (
	"errors"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type pathManager struct {
	pconnMgr  *pconnManager
	sess      *session
	nxtPathID protocol.PathID
	// Number of paths, excluding the initial one
	nbPaths uint8

	remoteAddrs4 []net.UDPAddr
	remoteAddrs6 []net.UDPAddr

	advertisedLocAddrs map[string]bool

	// TODO (QDC): find a cleaner way
	oliaSenders map[protocol.PathID]*congestion.OliaSender

	handshakeCompleted chan struct{}
	runClosed          chan struct{}
	timer              *time.Timer
}

func (pm *pathManager) setup(conn connection) {
	// Initial PathID is 0
	// PathIDs of client-initiated paths are even
	// those of server-initiated paths odd
	if pm.sess.perspective == protocol.PerspectiveClient {
		pm.nxtPathID = 1
	} else {
		pm.nxtPathID = 2
	}

	pm.remoteAddrs4 = make([]net.UDPAddr, 0)
	pm.remoteAddrs6 = make([]net.UDPAddr, 0)
	pm.advertisedLocAddrs = make(map[string]bool)
	pm.handshakeCompleted = make(chan struct{}, 1)
	pm.runClosed = make(chan struct{}, 1)
	pm.timer = time.NewTimer(0)
	pm.nbPaths = 0

	pm.oliaSenders = make(map[protocol.PathID]*congestion.OliaSender)

	// Setup the first path of the connection
	pm.sess.paths[protocol.InitialPathID] = &path{
		pathID: protocol.InitialPathID,
		sess:   pm.sess,
		conn:   conn,
	}

	// Setup this first path
	pm.sess.paths[protocol.InitialPathID].setup(pm.oliaSenders)

	// With the initial path, get the remoteAddr to create paths accordingly
	if conn.RemoteAddr() != nil {
		remAddr, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
		if err != nil {
			utils.Errorf("path manager: encountered error while parsing remote addr: %v", remAddr)
		}

		if remAddr.IP.To4() != nil {
			pm.remoteAddrs4 = append(pm.remoteAddrs4, *remAddr)
		} else {
			pm.remoteAddrs6 = append(pm.remoteAddrs6, *remAddr)
		}
	}

	// Launch the path manager
	go pm.run()
}

func (pm *pathManager) run() {
	// Close immediately if requested
	select {
	case <-pm.runClosed:
		return
	case <-pm.handshakeCompleted:
		if pm.sess.createPaths {
			err := pm.createPaths()
			if err != nil {
				pm.closePaths()
				return
			}
		}
	}

runLoop:
	for {
		select {
		case <-pm.runClosed:
			break runLoop
		case <-pm.pconnMgr.changePaths:
			if pm.sess.createPaths {
				pm.createPaths()
			}
		}
	}
	// Close paths
	pm.closePaths()
}

func getIPVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func (pm *pathManager) advertiseAddresses() {
	pm.pconnMgr.mutex.Lock()
	if utils.Debug() {
		utils.Debugf("advertising addresses to remote")
	}
	defer pm.pconnMgr.mutex.Unlock()
	for _, locAddr := range pm.pconnMgr.localAddrs {
		_, sent := pm.advertisedLocAddrs[locAddr.String()]
		if !sent {
			version := getIPVersion(locAddr.IP)
			pm.sess.streamFramer.AddAddressForTransmission(uint8(version), locAddr)
			pm.advertisedLocAddrs[locAddr.String()] = true
		}
	}
}

func (pm *pathManager) createPath(locAddr net.UDPAddr, remAddr net.UDPAddr) error {
	// First check that the path does not exist yet
	pm.sess.pathsLock.Lock()
	defer pm.sess.pathsLock.Unlock()
	paths := pm.sess.paths
	for _, pth := range paths {
		locAddrPath := pth.conn.LocalAddr().String()
		remAddrPath := pth.conn.RemoteAddr().String()
		if locAddr.String() == locAddrPath && remAddr.String() == remAddrPath {
			// Path already exists, so don't create it again
			return nil
		}
	}
	// No matching path, so create it
	pth := &path{
		pathID: pm.nxtPathID,
		sess:   pm.sess,
		conn:   &conn{pconn: pm.pconnMgr.pconns[locAddr.String()], currentAddr: &remAddr},
	}
	pth.setup(pm.oliaSenders)
	pm.sess.paths[pm.nxtPathID] = pth
	if utils.Debug() {
		utils.Debugf("Created path %x on %s to %s", pm.nxtPathID, locAddr.String(), remAddr.String())
	}
	pm.nxtPathID += 2
	// Send a PING frame to get latency info about the new path and informing the
	// peer of its existence
	// Because we hold pathsLock, it is safe to send packet now
	return pm.sess.sendPing(pth)
}

func (pm *pathManager) createPaths() error {
	if utils.Debug() {
		utils.Debugf("Path manager tries to create paths")
	}

	// XXX (QDC): don't let the server create paths for now
	if pm.sess.perspective == protocol.PerspectiveServer {
		pm.advertiseAddresses()
		return nil
	}
	// TODO (QDC): clearly not optimali
	pm.pconnMgr.mutex.Lock()
	defer pm.pconnMgr.mutex.Unlock()
	for _, locAddr := range pm.pconnMgr.localAddrs {
		version := getIPVersion(locAddr.IP)
		if version == 4 {
			for _, remAddr := range pm.remoteAddrs4 {
				err := pm.createPath(locAddr, remAddr)
				if err != nil {
					return err
				}
			}
		} else {
			for _, remAddr := range pm.remoteAddrs6 {
				err := pm.createPath(locAddr, remAddr)
				if err != nil {
					return err
				}
			}
		}
	}
	pm.sess.schedulePathsFrame()
	return nil
}

func (pm *pathManager) createPathFromRemote(p *receivedPacket) (*path, error) {
	pm.sess.pathsLock.Lock()
	defer pm.sess.pathsLock.Unlock()
	localPconn := p.rcvPconn
	remoteAddr := p.remoteAddr
	pathID := p.publicHeader.PathID

	// Sanity check: pathID should not exist yet
	_, ko := pm.sess.paths[pathID]
	if ko {
		return nil, errors.New("trying to create already existing path")
	}

	// Sanity check: odd is client initiated, even for server initiated
	if pm.sess.perspective == protocol.PerspectiveClient && pathID%2 != 0 {
		return nil, errors.New("server tries to create odd pathID")
	}
	if pm.sess.perspective == protocol.PerspectiveServer && pathID%2 == 0 {
		return nil, errors.New("client tries to create even pathID")
	}

	pth := &path{
		pathID: pathID,
		sess:   pm.sess,
		conn:   &conn{pconn: localPconn, currentAddr: remoteAddr},
	}

	pth.setup(pm.oliaSenders)
	pm.sess.paths[pathID] = pth

	if utils.Debug() {
		utils.Debugf("Created remote path %x on %s to %s", pathID, localPconn.LocalAddr().String(), remoteAddr.String())
	}

	return pth, nil
}

func (pm *pathManager) handleAddAddressFrame(f *wire.AddAddressFrame) error {
	switch f.IPVersion {
	case 4:
		pm.remoteAddrs4 = append(pm.remoteAddrs4, f.Addr)
	case 6:
		pm.remoteAddrs6 = append(pm.remoteAddrs6, f.Addr)
	default:
		return wire.ErrUnknownIPVersion
	}
	if pm.sess.createPaths {
		return pm.createPaths()
	}
	return nil
}

func (pm *pathManager) closePath(pthID protocol.PathID) error {
	pm.sess.pathsLock.RLock()
	defer pm.sess.pathsLock.RUnlock()

	pth, ok := pm.sess.paths[pthID]
	if !ok {
		// XXX (QDC) Unknown path, what should we do?
		return nil
	}

	if pth.open.Get() {
		pth.closeChan <- nil
	}

	return nil
}

func (pm *pathManager) closePaths() {
	pm.sess.pathsLock.RLock()
	paths := pm.sess.paths
	for _, pth := range paths {
		if pth.open.Get() {
			select {
			case pth.closeChan <- nil:
			default:
				// Don't remain stuck here!
			}
		}
	}
	pm.sess.pathsLock.RUnlock()
}
