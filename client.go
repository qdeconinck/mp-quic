package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type client struct {
	mutex sync.Mutex

	pconnMgr *pconnManager
	hostname string

	handshakeChan <-chan handshakeEvent

	versionNegotiationChan           chan struct{} // the versionNegotiationChan is closed as soon as the server accepted the suggested version
	versionNegotiated                bool          // has version negotiation completed yet
	receivedVersionNegotiationPacket bool

	tlsConf *tls.Config
	config  *Config

	connectionID protocol.ConnectionID
	version      protocol.VersionNumber

	closeListen chan error

	session packetHandler
}

var (
	// make it possible to mock connection ID generation in the tests
	generateConnectionID         = utils.GenerateConnectionID
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// DialAddr establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddr(addr string, tlsConf *tls.Config, config *Config) (Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	// Create the pconnManager here. It will be used to manage UDP connections
	pconnMgr := &pconnManager{perspective: protocol.PerspectiveClient}
	err = pconnMgr.setup(nil, nil)
	if err != nil {
		return nil, err
	}
	return Dial(pconnMgr.pconnAny, udpAddr, addr, tlsConf, config, pconnMgr)
}

// DialAddrNonFWSecure establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddrNonFWSecure(
	addr string,
	tlsConf *tls.Config,
	config *Config,
) (NonFWSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	// Create the pconnManager here. It will be used to manage UDP connections
	pconnMgr := &pconnManager{perspective: protocol.PerspectiveClient}
	err = pconnMgr.setup(nil, nil)
	if err != nil {
		return nil, err
	}
	return DialNonFWSecure(pconnMgr.pconnAny, udpAddr, addr, tlsConf, config, pconnMgr)
}

// DialNonFWSecure establishes a new non-forward-secure QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func DialNonFWSecure(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
	pconnMgrArg *pconnManager,
) (NonFWSession, error) {
	connID, err := generateConnectionID()
	if err != nil {
		return nil, err
	}

	var hostname string
	if tlsConf != nil {
		hostname = tlsConf.ServerName
	}

	if hostname == "" {
		hostname, _, err = net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
	}

	var pconnMgr *pconnManager

	if pconnMgrArg == nil {
		pconnMgr = &pconnManager{perspective: protocol.PerspectiveClient}
		err := pconnMgr.setup(pconn, nil)
		if err != nil {
			return nil, err
		}
	} else {
		pconnMgr = pconnMgrArg
	}

	clientConfig := populateClientConfig(config)
	c := &client{
		pconnMgr:               pconnMgr,
		connectionID:           connID,
		hostname:               hostname,
		tlsConf:                tlsConf,
		config:                 clientConfig,
		version:                clientConfig.Versions[0],
		versionNegotiationChan: make(chan struct{}),
	}
	// It's the responsibility of the client to give a proper connection
	conn := &conn{pconn: c.pconnMgr.pconnAny, currentAddr: remoteAddr}

	utils.Infof("Starting new connection to %s (%s -> %s), connectionID %x, version %s", hostname, conn.LocalAddr().String(), conn.RemoteAddr().String(), c.connectionID, c.version)

	if err := c.establishSecureConnection(conn); err != nil {
		return nil, err
	}
	return c.session.(NonFWSession), nil
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func Dial(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
	pconnMgrArg *pconnManager,
) (Session, error) {
	sess, err := DialNonFWSecure(pconn, remoteAddr, host, tlsConf, config, pconnMgrArg)
	if err != nil {
		return nil, err
	}
	if err := sess.WaitUntilHandshakeComplete(); err != nil {
		return nil, err
	}
	return sess, nil
}

// populateClientConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateClientConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
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
		maxReceiveStreamFlowControlWindow = protocol.DefaultMaxReceiveStreamFlowControlWindowClient
	}
	maxReceiveConnectionFlowControlWindow := config.MaxReceiveConnectionFlowControlWindow
	if maxReceiveConnectionFlowControlWindow == 0 {
		maxReceiveConnectionFlowControlWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindowClient
	}

	return &Config{
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		IdleTimeout:                           idleTimeout,
		RequestConnectionIDTruncation:         config.RequestConnectionIDTruncation,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
		KeepAlive:                             config.KeepAlive,
		CacheHandshake:                        config.CacheHandshake,
		CreatePaths:                           config.CreatePaths,
	}
}

// establishSecureConnection returns as soon as the connection is secure (as opposed to forward-secure)
func (c *client) establishSecureConnection(conn connection) error {
	if err := c.createNewSession(nil, conn); err != nil {
		return err
	}
	go c.listen()

	var runErr error
	errorChan := make(chan struct{})
	go func() {
		// session.run() returns as soon as the session is closed
		runErr = c.session.run()
		if runErr == errCloseSessionForNewVersion {
			// run the new session
			runErr = c.session.run()
		}
		close(errorChan)
		utils.Infof("Connection %x closed.", c.connectionID)
		c.pconnMgr.closePconns()
		select {
		case c.closeListen <- runErr:
			// It's possible to have the client having closed its run loop before...
		default:
		}
	}()

	// wait until the server accepts the QUIC version (or an error occurs)
	select {
	case <-errorChan:
		return runErr
	case <-c.versionNegotiationChan:
	}

	select {
	case <-errorChan:
		return runErr
	case ev := <-c.handshakeChan:
		if ev.err != nil {
			return ev.err
		}
		if !c.version.UsesTLS() && ev.encLevel != protocol.EncryptionSecure {
			return fmt.Errorf("Client BUG: Expected encryption level to be secure, was %s", ev.encLevel)
		}
		return nil
	}
}

// Listen listens
func (c *client) listen() {
	var err error

listenLoop:
	for {
		select {
		case <-c.closeListen:
			break listenLoop
		case err = <-c.pconnMgr.errorConn:
			c.session.Close(err)
			break listenLoop
		case rcvRawPacket := <-c.pconnMgr.rcvRawPackets:
			c.handlePacket(rcvRawPacket)
		}

	}
}

func (c *client) handlePacket(rcvRawPacket *receivedRawPacket) {
	var remoteAddr net.Addr
	var packet []byte
	var rcvTime time.Time
	var pconn net.PacketConn

	if rcvRawPacket.remoteAddr != nil {
		remoteAddr = rcvRawPacket.remoteAddr
	}
	if rcvRawPacket.data != nil {
		packet = rcvRawPacket.data
	}
	if !rcvRawPacket.rcvTime.IsZero() {
		rcvTime = rcvRawPacket.rcvTime
	}
	if rcvRawPacket.rcvPconn != nil {
		pconn = rcvRawPacket.rcvPconn
	}

	r := bytes.NewReader(packet)
	hdr, err := wire.ParsePublicHeader(r, protocol.PerspectiveServer, c.version)
	if err != nil {
		utils.Errorf("error parsing packet from %s: %s", remoteAddr.String(), err.Error())
		// drop this packet if we can't parse the Public Header
		return
	}
	// reject packets with truncated connection id if we didn't request truncation
	if hdr.TruncateConnectionID && !c.config.RequestConnectionIDTruncation {
		return
	}
	// reject packets with the wrong connection ID
	if !hdr.TruncateConnectionID && hdr.ConnectionID != c.connectionID {
		return
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if hdr.ResetFlag {
		cr := c.session.RemoteAddr()
		// check if the remote address and the connection ID match
		// otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
		if cr.Network() != remoteAddr.Network() || cr.String() != remoteAddr.String() || hdr.ConnectionID != c.connectionID {
			utils.Infof("Received a spoofed Public Reset. Ignoring.")
			return
		}
		pr, err := wire.ParsePublicReset(r)
		if err != nil {
			utils.Infof("Received a Public Reset for connection %x. An error occurred parsing the packet.", hdr.ConnectionID)
			return
		}
		utils.Infof("Received Public Reset, rejected packet number: %#x.", pr.RejectedPacketNumber)
		c.session.closeRemote(qerr.Error(qerr.PublicReset, fmt.Sprintf("Received a Public Reset for packet number %#x", pr.RejectedPacketNumber)))
		return
	}

	// ignore delayed / duplicated version negotiation packets
	if (c.receivedVersionNegotiationPacket || c.versionNegotiated) && hdr.VersionFlag {
		return
	}

	// this is the first packet after the client sent a packet with the VersionFlag set
	// if the server doesn't send a version negotiation packet, it supports the suggested version
	if !hdr.VersionFlag && !c.versionNegotiated {
		c.versionNegotiated = true
		close(c.versionNegotiationChan)
	}

	if hdr.VersionFlag {
		// version negotiation packets have no payload
		if err := c.handlePacketWithVersionFlag(hdr, remoteAddr); err != nil {
			c.session.Close(err)
		}
		return
	}

	c.session.handlePacket(&receivedPacket{
		remoteAddr:   remoteAddr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
		rcvPconn:     pconn,
	})
}

func (c *client) handlePacketWithVersionFlag(hdr *wire.PublicHeader, remoteAddr net.Addr) error {
	for _, v := range hdr.SupportedVersions {
		if v == c.version {
			// the version negotiation packet contains the version that we offered
			// this might be a packet sent by an attacker (or by a terribly broken server implementation)
			// ignore it
			return nil
		}
	}

	c.receivedVersionNegotiationPacket = true

	newVersion := protocol.ChooseSupportedVersion(c.config.Versions, hdr.SupportedVersions)
	if newVersion == protocol.VersionUnsupported {
		return qerr.InvalidVersion
	}

	// switch to negotiated version
	c.version = newVersion
	var err error
	c.connectionID, err = utils.GenerateConnectionID()
	if err != nil {
		return err
	}
	utils.Infof("Switching to QUIC version %s. New connection ID: %x", newVersion, c.connectionID)

	// create a new session and close the old one
	// the new session must be created first to update client member variables
	oldSession := c.session
	defer oldSession.Close(errCloseSessionForNewVersion)
	// It's the responsibility of the client to give a proper connection
	conn := &conn{pconn: c.pconnMgr.pconnAny, currentAddr: remoteAddr}
	return c.createNewSession(hdr.SupportedVersions, conn)
}

func (c *client) createNewSession(negotiatedVersions []protocol.VersionNumber, conn connection) error {
	var err error
	c.session, c.handshakeChan, err = newClientSession(
		conn,
		c.pconnMgr,
		c.config.CreatePaths,
		c.hostname,
		c.version,
		c.connectionID,
		c.tlsConf,
		c.config,
		negotiatedVersions,
	)
	return err
}
