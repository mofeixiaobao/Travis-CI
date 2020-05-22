// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package gmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof" // net/http/pprof is for registering the pprof URLs with the web server, so http://localhost:8080/debug/pprof/ works.
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gatechain/gatemint/config"
	apiServer "github.com/gatechain/gatemint/daemon/gmd/api/server"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/node"
	"github.com/gatechain/gatemint/node/appinterface"
	"github.com/gatechain/gatemint/util/metrics"
	"github.com/gatechain/gatemint/util/tokens"
	"github.com/gatechain/go-deadlock"
	"github.com/gatechain/logging"
	"github.com/gatechain/logging/telemetryspec"
)

var server http.Server

type stopCallback func()

// Server represents an instance of the REST API HTTP server
type Server struct {
	RootPath             string
	Genesis              bookkeeping.Genesis
	StopCallBack         stopCallback
	pidFile              string
	netFile              string
	netListenFile        string
	log                  logging.Logger
	node                 *node.GatemintFullNode
	metricCollector      *metrics.MetricService
	metricServiceStarted bool

	stopping deadlock.Mutex
	stopped  bool
}

// Initialize creates a Node instance with applicable network services
func (s *Server) Initialize(cfg config.Local, application appinterface.Application) error {
	// set up node
	s.log = logging.Base()

	liveLog := filepath.Join(s.RootPath, "node.log")
	archive := filepath.Join(s.RootPath, cfg.LogArchiveName)
	fmt.Println("Logging to: ", liveLog)
	var maxLogAge time.Duration
	var err error
	if cfg.LogArchiveMaxAge != "" {
		maxLogAge, err = time.ParseDuration(cfg.LogArchiveMaxAge)
		if err != nil {
			s.log.Fatalf("invalid config LogArchiveMaxAge: %s", err)
			maxLogAge = 0
		}
	}
	logWriter := logging.MakeCyclicFileWriter(liveLog, archive, cfg.LogSizeLimit, maxLogAge)
	s.log.SetOutput(logWriter)
	//s.log.SetJSONFormatter()
	s.log.SetLevel(logging.Level(cfg.BaseLoggerDebugLevel))
	setupDeadlockLogger()

	// configure the deadlock detector library
	switch {
	case cfg.DeadlockDetection > 0:
		// Explicitly enabled deadlock detection
		deadlock.Opts.Disable = false

	case cfg.DeadlockDetection < 0:
		// Explicitly disabled deadlock detection
		deadlock.Opts.Disable = true

	case cfg.DeadlockDetection == 0:
		// Default setting - host app should configure this
		// If host doesn't, the default is Disable = false (so, enabled)
	}

	// if we have the telemetry enabled, we want to use it's sessionid as part of the
	// collected metrics decorations.
	fmt.Fprintln(logWriter, "++++++++++++++++++++++++++++++++++++++++")
	fmt.Fprintln(logWriter, "Logging Starting")
	if s.log.GetTelemetryEnabled() {
		fmt.Fprintf(logWriter, "Telemetry Enabled: %s\n", s.log.GetTelemetryHostName())
		fmt.Fprintf(logWriter, "Session: %s\n", s.log.GetTelemetrySession())
	} else {
		fmt.Fprintln(logWriter, "Telemetry Disabled")
	}
	fmt.Fprintln(logWriter, "++++++++++++++++++++++++++++++++++++++++")

	metricLabels := map[string]string{}
	if s.log.GetTelemetryEnabled() {
		metricLabels["telemetry_session"] = s.log.GetTelemetrySession()
	}
	s.metricCollector = metrics.MakeMetricService(
		&metrics.ServiceConfig{
			NodeExporterListenAddress: cfg.NodeExporterListenAddress,
			Labels:                    metricLabels,
			NodeExporterPath:          cfg.NodeExporterPath,
		})

	ex, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate node executable: %s", err)
	}
	phonebookDir := filepath.Dir(ex)

	s.node, err = node.MakeFull(s.log, s.RootPath, cfg, phonebookDir, s.Genesis, application)
	if os.IsNotExist(err) {
		return fmt.Errorf("node has not been installed: %s", err)
	}
	if err != nil {
		return fmt.Errorf("couldn't initialize the node: %s", err)
	}

	return nil
}

// helper handles startup of tcp listener
func makeListener(addr string) (net.Listener, error) {
	var listener net.Listener
	var err error
	if (addr == "127.0.0.1:0") || (addr == ":0") {
		// if port 0 is provided, prefer port 8080 first, then fall back to port 0
		preferredAddr := strings.Replace(addr, ":0", ":8080", -1)
		listener, err = net.Listen("tcp", preferredAddr)
		if err == nil {
			return listener, err
		}
	}
	// err was not nil or :0 was not provided, fall back to originally passed addr
	return net.Listen("tcp", addr)
}

// Start starts a Node instance and its network services
func (s *Server) Start() {
	s.log.Info("Trying to start an Gatemint node")
	fmt.Print("Initializing the Gatemint node... ")
	s.node.Start()
	s.log.Info("Successfully started an Gatemint node.")
	fmt.Println("Success!")

	cfg := s.node.Config()

	if cfg.EnableMetricReporting {
		if err := s.metricCollector.Start(context.Background()); err != nil {
			// log this error
			s.log.Infof("Unable to start metric collection service : %v", err)
		}
		s.metricServiceStarted = true
	}

	apiToken, err := tokens.GetAndValidateAPIToken(s.RootPath, tokens.GmdTokenFilename)
	if err != nil {
		fmt.Printf("APIToken error: %v\n", err)
		os.Exit(1)
	}

	netlog := logging.NewLogger()
	logWriter := logging.MakeCyclicFileWriter(filepath.Join(s.RootPath, "net.log"), filepath.Join(s.RootPath, "net.archive.log"), cfg.LogSizeLimit, 0)
	netlog.SetOutput(logWriter)
	netlog.SetLevel(logging.Level(cfg.BaseLoggerDebugLevel))

	// use the data dir as the static file dir (for our API server), there's
	// no need to separate the two yet. This lets us serve the swagger.json file.
	apiHandler := apiServer.NewRouter(netlog, s.node, apiToken)

	addr := cfg.EndpointAddress
	if addr == "" {
		addr = ":http"
	}

	listener, err := makeListener(addr)

	if err != nil {
		fmt.Printf("Could not start node: %v\n", err)
		os.Exit(1)
	}

	addr = listener.Addr().String()
	server = http.Server{
		Addr:         addr,
		Handler:      apiHandler,
		ReadTimeout:  time.Duration(cfg.RestReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(cfg.RestWriteTimeoutSeconds) * time.Second,
	}

	defer s.Stop()

	tcpListener := listener.(*net.TCPListener)
	errChan := make(chan error, 1)
	go func() {
		err = server.Serve(tcpListener)
		errChan <- err
	}()

	// Set up files for our PID and our listening address
	s.pidFile = filepath.Join(s.RootPath, "gatemint.pid")
	s.netFile = filepath.Join(s.RootPath, "gatemint.net")
	ioutil.WriteFile(s.pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
	ioutil.WriteFile(s.netFile, []byte(fmt.Sprintf("%s\n", addr)), 0644)

	listenAddr, listening := s.node.ListeningAddress()
	if listening {
		s.netListenFile = filepath.Join(s.RootPath, "gatemint-listen.net")
		ioutil.WriteFile(s.netListenFile, []byte(fmt.Sprintf("%s\n", listenAddr)), 0644)
	}

	// Handle signals cleanly
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)
	go func() {
		sig := <-c
		fmt.Printf("Exiting on %v\n", sig)
		s.Stop()
		os.Exit(0)
	}()

	fmt.Printf("Node running and accepting RPC requests over HTTP on port %v. Press Ctrl-C to exit\n", addr)
	err = <-errChan
	if err != nil {
		s.log.Warn(err)
	} else {
		s.log.Info("Node exited successfully")
	}
}

// Stop initiates a graceful shutdown of the node by shutting down the network server.
func (s *Server) Stop() {
	s.stopping.Lock()
	defer s.stopping.Unlock()

	if s.stopped {
		return
	}

	// Attempt to log a shutdown event before we exit...
	s.log.Event(telemetryspec.ApplicationState, telemetryspec.ShutdownEvent)
	s.StopCallBack()
	s.node.Stop()

	err := server.Shutdown(context.Background())
	if err != nil {
		s.log.Error(err)
	}

	if s.metricServiceStarted {
		if err := s.metricCollector.Shutdown(); err != nil {
			// log this error
			s.log.Infof("Unable to shutdown metric collection service : %v", err)
		}
		s.metricServiceStarted = false
	}

	s.log.CloseTelemetry()

	os.Remove(s.pidFile)
	os.Remove(s.netFile)
	os.Remove(s.netListenFile)

	s.stopped = true
}

// OverridePhonebook is used to replace the phonebook associated with
// the server's node.
func (s *Server) OverridePhonebook(dialOverride ...string) {
	s.node.ReplacePeerList(dialOverride...)
}

//TODO delete
func (s *Server) InitApplication(application appinterface.Application, rootDir string) error {
	s.node.InitApplication(application)
	err := s.node.Ledger().InitApplication(application, s.Genesis, rootDir)
	if err != nil {
		return err
	}
	err = s.node.TransactionPool().InitApplication(application)
	return err
}
