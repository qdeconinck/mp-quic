// Go language Tor Pluggable Transport suite.  Works only as a managed
// client/server.
package main

import (
	"flag"
	"fmt"
	"io"
	golog "log"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"gitlab.com/yawning/obfs4.git/common/log"
)

const (
	simpleProxyVersion = "0.0.1"
	clientListenAddr   = "127.0.0.1:10500"

	quicIdleTimeout = 10 * time.Minute
	quicALPN        = "chimera-quic"
)

//var stateDir string
var termMon *termMonitor

// initial connection address (or only if MP is disabled)
var clientConnectAdr = "127.0.0.1:8888"

// initial server Bind address (or only if MP is disabled)
var serverBindAddr     = ":8888"

// func handling streams once accepted on the server
var serverStreamHandler func(io.ReadWriteCloser, string)

func getVersion() string {
	return fmt.Sprintf("chimera-proxy-%s", simpleProxyVersion)
}

func copyLoop(a io.ReadWriteCloser, b io.ReadWriteCloser) error {
	// Note: b is always the pt connection.  a is the SOCKS/ORPort connection.
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer b.Close()
		defer a.Close()
		_, err := io.Copy(b, a)
		errChan <- err
	}()
	go func() {
		defer wg.Done()
		defer a.Close()
		defer b.Close()
		_, err := io.Copy(a, b)
		errChan <- err
	}()

	// Wait for both upstream and downstream to close.  Since one side
	// terminating closes the other, the second error in the channel will be
	// something like EINVAL (though io.Copy() will swallow EOF), so only the
	// first error is returned.
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}

func main() {
	var err error
	// Initialize the termination state monitor as soon as possible
	termMon = newTermMonitor()

	// Initialize logging - we don't care about logging to file for now so
	// redirect to stdout.
	log.Init(true, "/dev/null", true)
	golog.SetOutput(os.Stdout)

	// Handle the command line arguments.
	_, execName := path.Split(os.Args[0])
	showVer := flag.Bool("version", false, "Print version and exit")
	logLevelStr := flag.String("logLevel", "ERROR", "Log level (ERROR/WARN/INFO/DEBUG)")

	// Set handler and handler args
	forwardHandlerTarget := flag.String("forward", "", "Use Forward Handler to specified target where server will pass incoming connections (defaults to non-forward echo)")

	// Client args
	flag.StringVar(&clientConnectAdr, "connect-addr", "127.0.0.1:8888", "client-side specified address of server.")

	// Multi-path Args
	mp := flag.Bool("m", false, "multipath")

	// Server Ards
	flag.StringVar(&serverBindAddr, "sb", ":8888", "server bind address.")


	flag.Parse()

	if *showVer {
		fmt.Printf("%s\n", getVersion())
		os.Exit(0)
	}
	if err = log.SetLogLevel(*logLevelStr); err != nil {
		golog.Fatalf("[ERROR]: %s - failed to set log level '%s': %s", execName, *logLevelStr, err)
	}
	ll, err := utils.ParseLogLevel(strings.ToLower(*logLevelStr))
	if err != nil {
		golog.Fatalf("failed to set log level %s\n", err)
	}
	utils.SetLogLevel(ll)

	if *mp {
		log.Debugf("enabling multipath")
	}

	if *forwardHandlerTarget != "" {
		if isClient() {
			log.Warnf("`-forward` is a server only option and has no effect for the client")
		}
		serverStreamHandler = getStaticForwardHandler(*forwardHandlerTarget)
	} else {
		serverStreamHandler = echoHandler
	}

	// Determine if this is a client or server, initialize the common state.
	var launched bool
	var ln io.Closer
	isClient := isClient()

	log.Noticef("%s - launching", getVersion())

	// Do the managed pluggable transport protocol configuration.
	if isClient {
		log.Infof("%s - initializing client transport listeners", execName)
		ch := getChimeraClientHandler(*mp)
		launched, ln, err = clientSetup(ch)
	} else {
		log.Infof("%s - initializing server transport listeners", execName)
		launched, ln, err = serverSetup(*mp)
	}
	if err != nil {
		log.Errorf("failed to launch - %s", err)
		os.Exit(-1)
	} else if !launched || ln == nil {
		// Initialization failed, the client or server setup routines should
		// have logged, so just exit here.
		os.Exit(-1)
	}

	log.Infof("%s - accepting connections", execName)
	defer func() {
		log.Noticef("%s - terminated", execName)
	}()

	// At this point, the pt config protocol is finished, and incoming
	// connections will be processed.  Wait till the parent dies
	// (immediate exit), a SIGTERM is received (immediate exit),
	// or a SIGINT is received.
	if sig := termMon.wait(false); sig == syscall.SIGTERM {
		return
	}

	// Ok, it was the first SIGINT, close all listeners, and wait till,
	// the parent dies, all the current connections are closed, or either
	// a SIGINT/SIGTERM is received, and exit.
	ln.Close()
	termMon.wait(true)
}

func isClient() bool {
	if strings.ToLower(os.Getenv("CHIMERA")) == "server" {
		return false
	}
	return true
}
