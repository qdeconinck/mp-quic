package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

// packetHandler handles packets
type packetHandler interface {
	Session
	handlePacket(*receivedPacket)
	GetVersion() protocol.VersionNumber
	run() error
	closeRemote(error)
}

// A Listener of QUIC
type server struct {
	tlsConf *tls.Config
	config  *Config

	pconnMgr *pconnManager

	certChain crypto.CertChain
	scfg      *handshake.ServerConfig

	sessions                  map[protocol.ConnectionID]packetHandler
	sessionsMutex             sync.RWMutex
	deleteClosedSessionsAfter time.Duration

	serverError  error
	sessionQueue chan Session
	errorChan    chan struct{}

	newSession func(conn connection, pconnMgr *pconnManager, createPaths bool, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, tlsConf *tls.Config, config *Config) (packetHandler, <-chan handshakeEvent, error)
}

var _ Listener = &server{}

// ListenAddr creates a QUIC server listening on a given address.
// The listener is not active until Serve() is called.
// The tls.Config must not be nil, the quic.Config may be nil.
func ListenAddr(addr string, tlsConf *tls.Config, config *Config) (Listener, error) {
	return ListenAddrImpl(addr, tlsConf, config, nil)
}

// ListenAddrImpl creates a QUIC server listening on a given address.
// The listener is not active until Serve() is called.
// The tls.Config must not be nil, the quic.Config may be nil.
// The pconnManager may be nil
func ListenAddrImpl(addr string, tlsConf *tls.Config, config *Config, pconnMgrArg *pconnManager) (Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	var pconnMgr *pconnManager

	if pconnMgrArg == nil {
		// Create the pconnManager here. It will be used to start udp connections
		pconnMgr = &pconnManager{perspective: protocol.PerspectiveServer}
		// XXX (QDC): make this cleaner
		pconn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			utils.Errorf("pconn_manager: %v", err)
			// Format for expected consistency
			operr := &net.OpError{Op: "listen", Net: "udp", Source: udpAddr, Addr: udpAddr, Err: err}
			return nil, operr
		}
		err = pconnMgr.setup(pconn, udpAddr)
		if err != nil {
			return nil, err
		}
	} else {
		pconnMgr = pconnMgrArg
	}
	return ListenImpl(pconnMgr.pconnAny, tlsConf, config, pconnMgr)
}

// Listen listens for QUIC connections on a given net.PacketConn.
// The listener is not active until Serve() is called.
// The tls.Config must not be nil, the quic.Config may be nil.
func Listen(pconn net.PacketConn, tlsConf *tls.Config, config *Config) (Listener, error) {
	// Create the pconnManager here. It will be used to start udp connections
	pconnMgr := &pconnManager{perspective: protocol.PerspectiveServer}
	err := pconnMgr.setup(pconn, nil)
	if err != nil {
		return nil, err
	}
	return ListenImpl(pconn, tlsConf, config, pconnMgr)
}

// ListenImpl listens for QUIC connections on a given net.PacketConn.
// The listener is not active until Serve() is called.
// The tls.Config must not be nil, the quic.Config may be nil.
// pconnManager may be nil
func ListenImpl(pconn net.PacketConn, tlsConf *tls.Config, config *Config, pconnMgrArg *pconnManager) (Listener, error) {
	certChain := crypto.NewCertChain(tlsConf)
	kex, err := crypto.NewCurve25519KEX()
	if err != nil {
		return nil, err
	}
	scfg, err := handshake.NewServerConfig(kex, certChain)
	if err != nil {
		return nil, err
	}

	var pconnMgr *pconnManager

	if pconnMgrArg == nil {
		pconnMgr = &pconnManager{perspective: protocol.PerspectiveServer}
		err := pconnMgr.setup(pconn, nil)
		if err != nil {
			return nil, err
		}
	} else {
		pconnMgr = pconnMgrArg
	}

	s := &server{
		pconnMgr:                  pconnMgr,
		tlsConf:                   tlsConf,
		config:                    populateServerConfig(config),
		certChain:                 certChain,
		scfg:                      scfg,
		sessions:                  map[protocol.ConnectionID]packetHandler{},
		newSession:                newSession,
		deleteClosedSessionsAfter: protocol.ClosedSessionDeleteTimeout,
		sessionQueue:              make(chan Session, 5),
		errorChan:                 make(chan struct{}),
	}
	go s.serve()
	utils.Debugf("Listening for %s connections on %s", pconn.LocalAddr().Network(), pconn.LocalAddr().String())
	return s, nil
}

var defaultAcceptCookie = func(clientAddr net.Addr, cookie *Cookie) bool {
	if cookie == nil {
		return false
	}
	if time.Now().After(cookie.SentTime.Add(protocol.CookieExpiryTime)) {
		return false
	}
	var sourceAddr string
	if udpAddr, ok := clientAddr.(*net.UDPAddr); ok {
		sourceAddr = udpAddr.IP.String()
	} else {
		sourceAddr = clientAddr.String()
	}
	return sourceAddr == cookie.RemoteAddr
}

// populateServerConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateServerConfig(config *Config) *Config {
	if config == nil {
		config = &Config{
			CreatePaths: true, // Grant this ability by default for a server
		}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}

	vsa := defaultAcceptCookie
	if config.AcceptCookie != nil {
		vsa = config.AcceptCookie
	}

	handshakeTimeout := protocol.DefaultHandshakeTimeout
	if config.HandshakeTimeout != 0 {
		handshakeTimeout = config.HandshakeTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.IdleTimeout != 0 {
		idleTimeout = config.IdleTimeout
	}

	maxReceiveStreamFlowControlWindow := config.MaxReceiveStreamFlowControlWindow
	if maxReceiveStreamFlowControlWindow == 0 {
		maxReceiveStreamFlowControlWindow = protocol.DefaultMaxReceiveStreamFlowControlWindowServer
	}
	maxReceiveConnectionFlowControlWindow := config.MaxReceiveConnectionFlowControlWindow
	if maxReceiveConnectionFlowControlWindow == 0 {
		maxReceiveConnectionFlowControlWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindowServer
	}

	return &Config{
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		IdleTimeout:                           idleTimeout,
		AcceptCookie:                          vsa,
		KeepAlive:                             config.KeepAlive,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
	}
}

// serve listens on an existing PacketConn
func (s *server) serve() {
	for {
		select {
		case err := <-s.pconnMgr.errorConn:
			s.serverError = err
			close(s.errorChan)
			_ = s.Close()
			return
		case rcvRawPacket := <-s.pconnMgr.rcvRawPackets:
			if err := s.handlePacket(rcvRawPacket); err != nil {
				utils.Errorf("error handling packet: %s", err.Error())
			}
		}
	}
}

// Accept returns newly openend sessions
func (s *server) Accept() (Session, error) {
	var sess Session
	select {
	case sess = <-s.sessionQueue:
		return sess, nil
	case <-s.errorChan:
		return nil, s.serverError
	}
}

// Close the server
func (s *server) Close() error {
	s.sessionsMutex.Lock()
	for _, session := range s.sessions {
		if session != nil {
			s.sessionsMutex.Unlock()
			_ = session.Close(nil)
			s.sessionsMutex.Lock()
		}
	}
	s.sessionsMutex.Unlock()

	s.pconnMgr.closeConns <- struct{}{}
	if s.pconnMgr != nil && s.pconnMgr.closed != nil {
		select {
		case <-s.pconnMgr.closed:
		default:
			// We never know...
		}
		// Wait that connections are closed
		<-s.pconnMgr.closed
	}
	return nil
}

// Addr returns the server's network address
func (s *server) Addr() net.Addr {
	if s.pconnMgr == nil {
		addr, _ := net.ResolveUDPAddr("udp", "1.2.3.4:5678")
		return addr
	}
	if s.pconnMgr.pconnAny == nil {
		addr, _ := net.ResolveUDPAddr("udp", "5.6.7.8:9101")
		return addr
	}
	return s.pconnMgr.pconnAny.LocalAddr()
}

func (s *server) handlePacket(rcvRawPacket *receivedRawPacket) error {
	pconn := rcvRawPacket.rcvPconn
	remoteAddr := rcvRawPacket.remoteAddr
	packet := rcvRawPacket.data
	rcvTime := rcvRawPacket.rcvTime

	r := bytes.NewReader(packet)
	connID, err := wire.PeekConnectionID(r, protocol.PerspectiveClient)
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}

	s.sessionsMutex.RLock()
	session, ok := s.sessions[connID]
	s.sessionsMutex.RUnlock()

	if ok && session == nil {
		// Late packet for closed session
		return nil
	}

	version := protocol.VersionUnknown
	if ok {
		version = session.GetVersion()
	}

	hdr, err := wire.ParsePublicHeader(r, protocol.PerspectiveClient, version)
	if err == wire.ErrPacketWithUnknownVersion {
		_, err = pconn.WriteTo(wire.WritePublicReset(connID, 0, 0), remoteAddr)
		return err
	}
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	// ignore all Public Reset packets
	if hdr.ResetFlag {
		if ok {
			var pr *wire.PublicReset
			pr, err = wire.ParsePublicReset(r)
			if err != nil {
				utils.Infof("Received a Public Reset for connection %x. An error occurred parsing the packet.")
			} else {
				utils.Infof("Received a Public Reset for connection %x, rejected packet number: 0x%x.", hdr.ConnectionID, pr.RejectedPacketNumber)
			}
		} else {
			utils.Infof("Received Public Reset for unknown connection %x.", hdr.ConnectionID)
		}
		return nil
	}

	// a session is only created once the client sent a supported version
	// if we receive a packet for a connection that already has session, it's probably an old packet that was sent by the client before the version was negotiated
	// it is safe to drop it
	if ok && hdr.VersionFlag && !protocol.IsSupportedVersion(s.config.Versions, hdr.VersionNumber) {
		return nil
	}

	// Send Version Negotiation Packet if the client is speaking a different protocol version
	if hdr.VersionFlag && !protocol.IsSupportedVersion(s.config.Versions, hdr.VersionNumber) {
		// drop packets that are too small to be valid first packets
		if len(packet) < protocol.ClientHelloMinimumSize+len(hdr.Raw) {
			return errors.New("dropping small packet with unknown version")
		}
		utils.Infof("Client offered version %s, sending VersionNegotiationPacket", hdr.VersionNumber)
		_, err = pconn.WriteTo(wire.ComposeVersionNegotiation(hdr.ConnectionID, s.config.Versions), remoteAddr)
		return err
	}

	if !ok {
		version := hdr.VersionNumber
		if !protocol.IsSupportedVersion(s.config.Versions, version) {
			return errors.New("Server BUG: negotiated version not supported")
		}

		utils.Infof("Serving new connection: %x, version %s from %v", hdr.ConnectionID, version, remoteAddr)
		// It's the responsibility of the server to give a proper connection
		conn := &conn{pconn: pconn, currentAddr: remoteAddr}
		var handshakeChan <-chan handshakeEvent
		session, handshakeChan, err = s.newSession(
			conn,
			s.pconnMgr,
			s.config.CreatePaths,
			version,
			hdr.ConnectionID,
			s.scfg,
			s.tlsConf,
			s.config,
		)
		if err != nil {
			return err
		}
		s.sessionsMutex.Lock()
		s.sessions[connID] = session
		s.sessionsMutex.Unlock()

		go func() {
			// session.run() returns as soon as the session is closed
			_ = session.run()
			s.removeConnection(hdr.ConnectionID)
		}()

		go func() {
			for {
				ev := <-handshakeChan
				if ev.err != nil {
					return
				}
				if ev.encLevel == protocol.EncryptionForwardSecure {
					break
				}
			}
			s.sessionQueue <- session
		}()
	}
	session.handlePacket(&receivedPacket{
		remoteAddr:   remoteAddr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
		rcvPconn:     pconn,
	})
	return nil
}

func (s *server) removeConnection(id protocol.ConnectionID) {
	s.sessionsMutex.Lock()
	s.sessions[id] = nil
	s.sessionsMutex.Unlock()

	time.AfterFunc(s.deleteClosedSessionsAfter, func() {
		s.sessionsMutex.Lock()
		delete(s.sessions, id)
		s.sessionsMutex.Unlock()
	})
}
