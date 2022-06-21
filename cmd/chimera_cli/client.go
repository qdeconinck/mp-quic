package main

import (
	"crypto/tls"
	"fmt"
	"net"

	quic "github.com/lucas-clemente/quic-go"

	"gitlab.com/yawning/obfs4.git/common/log"
)

func clientSetup(clientHandler func(net.Conn)) (launched bool, ln net.Listener, err error) {

	ln, err = net.Listen("tcp", clientListenAddr)
	if err != nil {
		err = fmt.Errorf("error launching listener: %s", err.Error())
		// err = fmt.Errorf("error launching listener (%s): %s", name, err.Error())
	}

	go func() {
		_ = clientAcceptLoop(ln, clientHandler)
	}()

	log.Infof("registered listener: %s", ln.Addr())

	launched = true

	return
}

func clientAcceptLoop(ln net.Listener, clientHandler func(net.Conn)) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go clientHandler(conn)
	}
}

func getChimeraClientHandler(mp bool) func(net.Conn) {
	if mp {
		log.Infof("enabling multipath")
	}
	return func(conn net.Conn) {
		defer conn.Close()
		termMon.onHandlerStart()
		defer termMon.onHandlerFinish()

		quicConfig := &quic.Config{
			IdleTimeout: quicIdleTimeout,
			CreatePaths: mp,
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}

		sess, err := quic.DialAddr(clientConnectAdr, tlsConfig, quicConfig)
		if err != nil {
			log.Errorf("%s - outgoing connection failed: %s", clientConnectAdr, err)
			return
		}
		log.Infof("%s - New inner connection", clientConnectAdr)

		stream, err := sess.OpenStream()
		if err != nil {
			log.Errorf("%s - failed to open stream: %s", clientConnectAdr, err)
			return
		}
		defer stream.Close()
		log.Infof("%s - New stream", clientConnectAdr)

		if err = copyLoop(conn, stream); err != nil {
			log.Warnf("%s - closed connection: %s", clientConnectAdr, err)
		} else {
			log.Infof("%s - closed connection", clientConnectAdr)
		}
	}
}
