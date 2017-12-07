package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const (
	intervalTime = 400 * time.Millisecond
	maxID        = 100
)

var (
	addr        = "localhost:4242"
	counter     int
	counterLock sync.Mutex
	delays      = make([]time.Duration, 0)
	messageID   int
	missed      int
	printChan   = make(chan struct{}, 1)
	querySize   = 750
	resSize     = 750
	runTime     = 30 * time.Second
	sentTime    = make(map[int]time.Time)
	startTime   time.Time
	stream      quic.Stream
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to dial")
	runTimeF := flag.Duration("runTime", 30*time.Second, "Running time of test")
	multipath := flag.Bool("m", false, "multipath")
	verbose := flag.Bool("v", false, "Verbose mode")
	flag.Parse()
	addr = *addrF
	runTime = *runTimeF + 200*time.Millisecond
	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	printChan <- struct{}{}
	err := clientMain(*multipath)
	fmt.Printf("Exiting client main with error %v\n", err)
	printer()
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func printer() {
	<-printChan
	fmt.Printf("Missed: %d\n", missed)
	for _, d := range delays {
		fmt.Println(int64(d / time.Millisecond))
	}
	time.Sleep(time.Second)
	os.Exit(0)
}

func sendMessage() error {
	if stream == nil {
		return errors.New("Closed stream")
	}
	sentTime[messageID] = time.Now()
	startString := strconv.Itoa(messageID) + "&" + strconv.Itoa(querySize) + "&" + strconv.Itoa(resSize) + "&" + "0" + "&"
	messageID = (messageID + 1) % maxID
	msg := startString + strings.Repeat("0", querySize-len(startString))
	_, err := stream.Write([]byte(msg))
	return err
}

func clientSender() {
sendLoop:
	for {
		if stream == nil {
			break sendLoop
		}
		time.Sleep(intervalTime)
		if time.Since(startTime) >= runTime {
			stream.Close()
			break sendLoop
		} else {
			err := sendMessage()
			if err != nil {
				stream.Close()
				break sendLoop
			}
		}
	}
	printer()
}

func clientMain(multipath bool) error {
	cfgClient := &quic.Config{
		CreatePaths: multipath,
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	fmt.Println("Trying to connect...")
	// TODO: specify address
	session, err := quic.DialAddr(addr, tlsConfig, cfgClient)
	if err != nil {
		panic(err)
	}
	fmt.Println("Connected")
	startTime = time.Now()
	stream, err = session.OpenStreamSync()
	if err != nil {
		panic(err)
	}

	go clientSender()

	buf := make([]byte, resSize)
listenLoop:
	for {
		if stream == nil {
			break listenLoop
		}
		read, err := io.ReadFull(stream, buf)
		receivedTime := time.Now()
		if err != nil {
			return err
		}
		if read != resSize {
			return errors.New("Read does not match resSize")
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		msgID, _ := strconv.Atoi(splitMsg[0])
		sent, ok := sentTime[msgID]
		if !ok {
			continue
		}
		delays = append(delays, receivedTime.Sub(sent))
		delete(sentTime, msgID)
		counterLock.Lock()
		counter -= querySize
		counterLock.Unlock()
	}
	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
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
