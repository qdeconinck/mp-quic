package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"

	quic "github.com/lucas-clemente/quic-go"

	"gitlab.com/yawning/obfs4.git/common/log"
)

func serverSetup(mp bool) (bool, quic.Listener, error) {
	var err error

	cert, err := generateTLSCertificate()
	if err != nil {
		return false, nil, err
	}

	if mp {
		log.Infof("enabling multipath")
	}

	// Make a QUIC listener atop the serverPacketConn.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{quicALPN},
	}
	quicConfig := &quic.Config{
		IdleTimeout: quicIdleTimeout,
		CreatePaths: mp,
	}

	// listen should init the pconnManager with configured packet-conns (or default)
	listener, err := quic.ListenAddr(serverBindAddr, tlsConfig, quicConfig)
	if err != nil {
		return false, nil, err
	}

	go func() {
		_ = serverAcceptLoop(listener)
	}()

	log.Infof("registered listener(s): %s", log.ElideAddr(listener.Addr().String()))

	return true, listener, err
}

func serverAcceptLoop(ln quic.Listener) error {
	defer ln.Close()
	for {
		sess, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go func() {
			_ = serverSessionHandler(sess)
		}()
	}
}

func serverSessionHandler(sess quic.Session) error {
	var err error
	defer sess.Close(err)
	for {
		var stream quic.Stream
		stream, err = sess.AcceptStream()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go serverStreamHandler(stream, sess.RemoteAddr().String())
	}
}

func generateTLSCertificate() (*tls.Certificate, error) {
	// https://golang.org/src/crypto/tls/generate_cert.go
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	return &cert, err
}

// getStaticForwardHandler takes in raw bytes from the connection and forwards
// those bytes to a remote address (i.e. transparent proxy). Closes both sides
// on err from either side. Failed write on close is an example err.
func getStaticForwardHandler(forwardAddr string) func(io.ReadWriteCloser, string) {
	return func(remote io.ReadWriteCloser, addrStr string) {
		defer remote.Close()
		termMon.onHandlerStart()
		defer termMon.onHandlerFinish()

		log.Infof("%s - new connection", addrStr)

		// Connect to the static forward host (e.g. squid proxy).
		// orConn, err := pt.DialOr(info, conn.RemoteAddr().String(), name)
		fwdConn, err := net.Dial("tcp", forwardAddr)
		if err != nil {
			log.Errorf("%s - failed to connect to ORPort: %s", addrStr, err)
			return
		}
		defer fwdConn.Close()

		if err = copyLoop(fwdConn, remote); err != nil {
			log.Warnf("%s - closed connection: %s", addrStr, err)
		} else {
			log.Infof("%s - closed connection", addrStr)
		}
	}
}

func echoHandler(remote io.ReadWriteCloser, addrStr string) {
	defer remote.Close()
	termMon.onHandlerStart()
	defer termMon.onHandlerFinish()

	log.Infof("%s - new connection", addrStr)

	if err := copyLoop(remote, remote); err != nil {
		log.Warnf("%s - closed connection: %s", addrStr, err)
	} else {
		log.Infof("%s - closed connection", addrStr)
	}
}
