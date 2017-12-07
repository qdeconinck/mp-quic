package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var addr = "localhost:4242"

const (
	MsgLen    = 750
	MinFields = 5
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to bind")
	verbose := flag.Bool("v", false, "Verbose mode")
	flag.Parse()
	addr = *addrF
	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	err := echoServer()
	if err != nil {
		panic(err)
	}
}

// Start a server that performs similar traffic to Siri servers
func echoServer() error {
	cfgServer := &quic.Config{}
	tlsConfig := generateTLSConfig()
	listener, err := quic.ListenAddr(addr, tlsConfig, cfgServer)
	if err != nil {
		return err
	}
	sess, err := listener.Accept()
	if err != nil {
		return err
	}
	stream, err := sess.AcceptStream()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, MsgLen)
	for {
		read, err := io.ReadFull(stream, buf)
		if err != nil {
			stream.Close()
			stream.Close()
			return err
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		expectedReqSize, _ := strconv.Atoi(splitMsg[1])
		if read != expectedReqSize {
			stream.Close()
			stream.Close()
			return errors.New("Did not read the expected size; " + strconv.Itoa(read) + " != " + splitMsg[1])
		}
		sleepTimeSec, _ := strconv.Atoi(splitMsg[3])
		if sleepTimeSec > 0 {
			time.Sleep(time.Duration(sleepTimeSec) * time.Second)
		}
		msgID := splitMsg[0]
		resSize, _ := strconv.Atoi(splitMsg[2])
		res := msgID + "&" + strings.Repeat("0", resSize-len(msgID)-2) + "\n"
		_, err = stream.Write([]byte(res))
		if err != nil {
			stream.Close()
			stream.Close()
			return err
		}
	}
	return err
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
