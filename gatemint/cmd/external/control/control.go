package control

import (
	"bytes"
	"errors"
	"fmt"
	//"github.com/gatechain/gatemint/cmd/kmd/codes"
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/daemon/gmd/api/client"
	"github.com/gatechain/gatemint/daemon/kmd/lib/kmdapi"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/gatemint/util"
	"github.com/gatechain/gatemint/util/tokens"
	"github.com/gatechain/logging"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// KMDController wraps directories and processes involved in running kmd
type KMDController struct {
	kmd        string // path to binary
	kmdDataDir string
	kmdPIDPath string
}

// KMDStartArgs are the possible arguments for starting kmd
type KMDStartArgs struct {
	TimeoutSecs uint64
}

// NodeController provides an object for controlling a specific gmd node instance
type NodeController struct {
	algod              string
	algoh              string
	algodDataDir       string
	algodPidFile       string
	algodNetFile       string
	algodNetListenFile string

	KMDController
}

// AlgodStartArgs are the possible arguments for starting algod
type AlgodStartArgs struct {
	PeerAddress       string
	ListenIP          string
	RedirectOutput    bool
	RunUnderHost      bool
	TelemetryOverride string
}

// LaggedStdIo is an indirect wrapper around os.Stdin/os.Stdout/os.Stderr that prevents
// direct dependency which could be an issue when a caller panics, leaving the child processes
// alive and blocks for EOF.
type LaggedStdIo struct {
	ioClass    int
	LinePrefix atomic.Value // of datatype string
}

// KMDClient is the client used to interact with the kmd API over its socket
type KMDClient struct {
	httpClient http.Client
	apiToken   string
	address    string
}

var errAlgodExitedEarly = fmt.Errorf("node exited before we could contact it")
var errKMDDataDirNotAbs = fmt.Errorf("kmd data dir must be absolute path")
var errKMDExitedEarly = fmt.Errorf("kmd exited before we could contact it")

const (
	// NetFilename is the name of the net file in the kmd data dir
	NetFilename = "kmd.net"
	// PIDFilename is the name of the PID file in the kmd data dir
	PIDFilename = "kmd.pid"
	// LockFilename is the name of the lock file in the kmd data dir
	LockFilename = "kmd.lock"
	// DefaultKMDPort is the port that kmd will first try to start on if none is specified
	DefaultKMDPort = 7833
	// DefaultKMDHost is the host that kmd will first try to start on if none is specified
	DefaultKMDHost = "127.0.0.1"

	// StdErrFilename is the name of the file in <datadir> where stderr will be captured if not redirected to host
	StdErrFilename = "algod-err.log"
	// StdOutFilename is the name of the file in <datadir> where stdout will be captured if not redirected to host
	StdOutFilename = "algod-out.log"

	// DefaultKMDDataDir is exported so tests can initialize it with config info
	DefaultKMDDataDir = "kmd-v0.5"
	// DefaultKMDDataDirPerms is exported so tests can initialize the default kmd data dir
	DefaultKMDDataDirPerms = 0700

	// kmdStdErrFilename is the name of the file in <kmddatadir> where stderr will be captured
	kmdStdErrFilename = "kmd-err.log"
	// kmdStdOutFilename is the name of the file in <kmddatadir> where stdout will be captured
	kmdStdOutFilename = "kmd-out.log"

	timeoutSecs = 120

	// KMDTokenHeader is the HTTP header used for the pre-shared auth token
	KMDTokenHeader = "X-KMD-API-Token"
)

// MakeNodeController creates a NodeController representing a
// specific data directory (and an associated binary directory)
func MakeNodeController(binDir, algodDataDir string) NodeController {
	nc := NodeController{
		algod:              filepath.Join(binDir, "gmd"),
		algoh:              filepath.Join(binDir, "gmh"),
		algodDataDir:       algodDataDir,
		algodPidFile:       filepath.Join(algodDataDir, "gatemint.pid"),
		algodNetFile:       filepath.Join(algodDataDir, "gatemint.net"),
		algodNetListenFile: filepath.Join(algodDataDir, "gatemint-listen.net"),
	}
	nc.SetKMDBinDir(binDir)
	return nc
}

func killPID(pid int) error {
	process, err := os.FindProcess(pid)
	if process == nil || err != nil {
		return err
	}

	err = syscall.Kill(pid, syscall.SIGTERM)
	if err != nil {
		return err
	}
	waitLong := time.After(time.Second * 30)
	for {
		// Send null signal - if process still exists, it'll return nil
		// So when we get an error, assume it's gone.
		if err = process.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		select {
		case <-waitLong:
			return syscall.Kill(pid, syscall.SIGKILL)
		case <-time.After(time.Millisecond * 100):
		}
	}
}

// NewLaggedStdIo creates a new instance of the LaggedStdIo.
// allowed stdio are limited to os.Stdin, os.Stdout and os.Stderr
func NewLaggedStdIo(stdio interface{}, linePrefix string) *LaggedStdIo {
	lio := &LaggedStdIo{}
	lio.LinePrefix.Store(linePrefix)
	switch stdio {
	case os.Stdin:
		lio.ioClass = 0
		return lio
	case os.Stdout:
		lio.ioClass = 1
		return lio
	case os.Stderr:
		lio.ioClass = 2
		return lio
	}
	return nil
}

func makeHTTPClient() http.Client {
	client := http.Client{
		Timeout: timeoutSecs * time.Second,
	}
	return client
}

// MakeKMDClient instantiates a KMDClient for the given sockFile and apiToken
func MakeKMDClient(address string, apiToken string) (KMDClient, error) {
	kcl := KMDClient{
		httpClient: makeHTTPClient(),
		apiToken:   apiToken,
		address:    address,
	}
	return kcl, nil
}

// getPathAndMethod infers the request path and method from the request type
func getPathAndMethod(req kmdapi.APIV1Request) (reqPath string, reqMethod string, err error) {
	switch req.(type) {
	default:
		err = fmt.Errorf("unknown request type")
	case kmdapi.VersionsRequest:
		reqPath = "versions"
		reqMethod = "GET"
	case kmdapi.APIV1GETWalletsRequest:
		reqPath = "v1/wallets"
		reqMethod = "GET"
	case kmdapi.APIV1POSTWalletRequest:
		reqPath = "v1/wallet"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletInitRequest:
		reqPath = "v1/wallet/init"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletReleaseRequest:
		reqPath = "v1/wallet/release"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletRenewRequest:
		reqPath = "v1/wallet/renew"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletRenameRequest:
		reqPath = "v1/wallet/rename"
		reqMethod = "POST"
	case kmdapi.APIV1POSTWalletInfoRequest:
		reqPath = "v1/wallet/info"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMasterKeyExportRequest:
		reqPath = "v1/master-key/export"
		reqMethod = "POST"
	case kmdapi.APIV1POSTKeyImportRequest:
		reqPath = "v1/key/import"
		reqMethod = "POST"
	case kmdapi.APIV1POSTKeyExportRequest:
		reqPath = "v1/key/export"
		reqMethod = "POST"
	case kmdapi.APIV1POSTKeyRequest:
		reqPath = "v1/key"
		reqMethod = "POST"
	case kmdapi.APIV1DELETEKeyRequest:
		reqPath = "v1/key"
		reqMethod = "DELETE"
	case kmdapi.APIV1POSTKeyListRequest:
		reqPath = "v1/key/list"
		reqMethod = "POST"
	case kmdapi.APIV1POSTProgramSignRequest:
		reqPath = "v1/program/sign"
		reqMethod = "POST"
	case kmdapi.APIV1POSTTransactionSignRequest:
		reqPath = "v1/transaction/sign"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigListRequest:
		reqPath = "v1/multisig/list"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigImportRequest:
		reqPath = "v1/multisig/import"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigExportRequest:
		reqPath = "v1/multisig/export"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigTransactionSignRequest:
		reqPath = "v1/multisig/sign"
		reqMethod = "POST"
	case kmdapi.APIV1POSTMultisigProgramSignRequest:
		reqPath = "v1/multisig/signprogram"
		reqMethod = "POST"
	case kmdapi.APIV1DELETEMultisigRequest:
		reqPath = "v1/multisig"
		reqMethod = "DELETE"
	}
	return
}

// StartAlgod spins up an algod process and waits for it to begin
func (nc *NodeController) StartAlgod(args AlgodStartArgs) (alreadyRunning bool, err error) {
	// If algod is already running, we can't start again
	alreadyRunning = nc.algodRunning()
	if alreadyRunning {
		return alreadyRunning, nil
	}

	algodCmd := nc.buildAlgodCommand(args)

	var errLogger, outLogger *LaggedStdIo
	if args.RedirectOutput {
		errLogger = NewLaggedStdIo(os.Stderr, "gmd")
		outLogger = NewLaggedStdIo(os.Stdout, "gmd")
		algodCmd.Stderr = errLogger
		algodCmd.Stdout = outLogger
	} else if !args.RunUnderHost {
		// If not redirecting output to the host, we want to capture stderr and stdout to files
		files := nc.setAlgodCmdLogFiles(algodCmd)
		// Descriptors will get dup'd after exec, so OK to close when we return
		for _, file := range files {
			defer file.Close()
		}
	}

	err = algodCmd.Start()
	if err != nil {
		return
	}

	if args.RedirectOutput {
		// update the logger output prefix with the process id.
		linePrefix := fmt.Sprintf("algod(%d)", algodCmd.Process.Pid)
		errLogger.SetLinePrefix(linePrefix)
		outLogger.SetLinePrefix(linePrefix)
	}

	// Wait on the algod process and check if exits
	c := make(chan bool)
	go func() {
		// this Wait call is important even beyond the scope of this function; it allows the system to
		// move the process from a "zombie" state into "done" state, and is required for the Signal(0) test.
		algodCmd.Wait()
		c <- true
	}()

	success := false
	for !success {
		select {
		case <-c:
			return false, errAlgodExitedEarly
		case <-time.After(time.Millisecond * 100):
			// If we can't talk to the API yet, spin
			algodClient, err := nc.AlgodClient()
			if err != nil {
				continue
			}

			// See if the server is up
			err = algodClient.HealthCheck()
			if err == nil {
				success = true
				continue
			}

			// Perhaps we're running an old version with no HealthCheck endpoint?
			_, err = algodClient.Status()
			if err == nil {
				success = true
			}
		}
	}
	return
}

// algodRunning returns a boolean indicating if algod is running
func (nc NodeController) algodRunning() (isRunning bool) {
	_, err := nc.GetAlgodPID()
	if err == nil {
		// no error means file already exists, and we just loaded its content.
		// check if we can communicate with it.
		algodClient, err := nc.AlgodClient()
		if err == nil {
			err = algodClient.HealthCheck()
			if err == nil {
				// yes, we can communicate with it.
				return true
			}
		}
	}
	return false
}

// buildAlgodCommand
func (nc NodeController) buildAlgodCommand(args AlgodStartArgs) *exec.Cmd {
	startArgs := make([]string, 0)
	startArgs = append(startArgs, "-d")
	startArgs = append(startArgs, nc.algodDataDir)
	if len(args.TelemetryOverride) > 0 {
		startArgs = append(startArgs, "-t")
		startArgs = append(startArgs, args.TelemetryOverride)
	}

	// Parse peerDial and listenIP cmdline flags
	peerDial := args.PeerAddress
	if len(peerDial) > 0 {
		startArgs = append(startArgs, "-p")
		startArgs = append(startArgs, peerDial)
	}
	listenIP := args.ListenIP
	if len(listenIP) > 0 {
		startArgs = append(startArgs, "-l")
		startArgs = append(startArgs, listenIP)
	}

	// Check if we should be using algoh
	var cmd string
	if args.RunUnderHost {
		cmd = nc.algoh
	} else {
		cmd = nc.algod
	}

	return exec.Command(cmd, startArgs...)
}

func (nc NodeController) setAlgodCmdLogFiles(cmd *exec.Cmd) (files []*os.File) {
	{ // Scoped to ensure err and out variables aren't mixed up
		errFileName := filepath.Join(nc.algodDataDir, StdErrFilename)
		errFile, err := os.OpenFile(errFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			cmd.Stderr = errFile
			files = append(files, errFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stderr: %v\n", err)
		}
	}
	{
		outFileName := filepath.Join(nc.algodDataDir, StdOutFilename)
		outFile, err := os.OpenFile(outFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			cmd.Stdout = outFile
			files = append(files, outFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stdout: %v\n", err)
		}
	}
	return
}

// AlgodClient attempts to build a client.RestClient for communication with
// the algod REST API, but fails if we can't find the net file
func (nc NodeController) AlgodClient() (algodClient client.RestClient, err error) {
	algodAPIToken, err := tokens.GetAndValidateAPIToken(nc.algodDataDir, tokens.GmdTokenFilename)
	if err != nil {
		return
	}

	// Fetch the server URL from the net file, if it exists
	algodURL, err := nc.ServerURL()
	if err != nil {
		return
	}

	// Build the client from the URL and API token
	algodClient = client.MakeRestClient(algodURL, algodAPIToken)
	return
}

// ServerURL returns the appropriate URL for the node under control
func (nc NodeController) ServerURL() (url.URL, error) {
	addr, err := nc.GetHostAddress()
	if err != nil {
		return url.URL{}, err
	}
	return url.URL{Scheme: "http", Host: addr}, nil
}

// GetAlgodPID returns the PID from the algod.pid file in the node's data directory, or an error
func (nc NodeController) GetAlgodPID() (pid int64, err error) {
	// Pull out the PID, ignoring newlines
	pidStr, err := util.GetFirstLineFromFile(nc.algodPidFile)
	if err != nil {
		return -1, err
	}
	// Parse as an integer
	pid, err = strconv.ParseInt(pidStr, 10, 32)
	return
}

// GetHostAddress retrieves the REST address for the node from its algod.net file.
func (nc NodeController) GetHostAddress() (string, error) {
	// For now, we want the old behavior to 'just work';
	// so if data directory is not specified, we assume the default address of 127.0.0.1:8080
	if len(nc.algodDataDir) == 0 {
		return "127.0.0.1:8080", nil
	}
	return util.GetFirstLineFromFile(nc.algodNetFile)
}

// GetListeningAddress retrieves the listening address from the algod-listen.net file for the node
func (nc NodeController) GetListeningAddress() (string, error) {
	return util.GetFirstLineFromFile(nc.algodNetListenFile)
}

// FullStop stops both algod and kmd, if they're running
func (nc NodeController) FullStop() error {
	_, _, err := nc.stopProcesses()
	return err
}

// stopProcesses attempts to read PID files for algod and kmd and kill the
// corresponding processes. If it can't read a PID file, it doesn't return an
// error, but if it reads a PID file and the process doesn't die, it does
func (nc NodeController) stopProcesses() (algodAlreadyStopped, kmdAlreadyStopped bool, err error) {
	algodAlreadyStopped, err = nc.StopAlgod()
	if err != nil {
		return
	}
	kmdAlreadyStopped, err = nc.StopKMD()
	return
}

// StopAlgod reads the net file and kills the algod process
func (nc *NodeController) StopAlgod() (alreadyStopped bool, err error) {
	// Find algod PID
	algodPID, err := nc.GetAlgodPID()
	if err == nil {
		// Kill algod by PID
		err = killPID(int(algodPID))
		if err != nil {
			return
		}
	} else {
		err = nil
		alreadyStopped = true
	}
	return
}

// Clone creates a new DataDir based on the controller's DataDir; if copyLedger is true, we'll clone the ledger.sqlite file
func (nc NodeController) Clone(targetDir string, copyLedger bool) (err error) {
	os.RemoveAll(targetDir)
	err = os.Mkdir(targetDir, 0700)
	if err != nil && !os.IsExist(err) {
		return
	}

	// Copy Core Files, silently failing to copy any that don't exist
	files := []string{config.GenesisJSONFile, config.ConfigFilename, config.PhonebookFilename}
	for _, file := range files {
		src := filepath.Join(nc.algodDataDir, file)
		if util.FileExists(src) {
			dest := filepath.Join(targetDir, file)
			_, err = util.CopyFile(src, dest)
			if err != nil {
				switch err.(type) {
				case *os.PathError:
					continue
				default:
					return
				}
			}
		}
	}

	// Copy Ledger Files if requested
	if copyLedger {
		var genesis bookkeeping.Genesis
		genesis, err = nc.readGenesisJSON(filepath.Join(nc.algodDataDir, config.GenesisJSONFile))
		if err != nil {
			return
		}

		genesisFolder := filepath.Join(nc.algodDataDir, genesis.ID())
		targetGenesisFolder := filepath.Join(targetDir, genesis.ID())
		err = os.Mkdir(targetGenesisFolder, 0770)
		if err != nil {
			return
		}

		files := []string{"ledger.sqlite"}
		for _, file := range files {
			src := filepath.Join(genesisFolder, file)
			dest := filepath.Join(targetGenesisFolder, file)
			_, err = util.CopyFile(src, dest)
			if err != nil {
				return
			}
		}
	}

	return
}

func (nc NodeController) readGenesisJSON(genesisFile string) (genesisLedger bookkeeping.Genesis, err error) {
	// Load genesis
	genesisText, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		return
	}

	err = protocol.DecodeJSON(genesisText, &genesisLedger)
	return
}

// StopKMD reads the net file and kills the kmd process
func (kc *KMDController) StopKMD() (alreadyStopped bool, err error) {
	// Find kmd PID
	kmdPID, err := kc.GetKMDPID()
	if err == nil {
		// Kill kmd by PID
		err = killPID(int(kmdPID))
		if err != nil {
			return
		}
	} else {
		err = nil
		alreadyStopped = true
	}
	return
}

// SetKMDBinDir updates the KMDController for a binDir that contains `kmd`
func (kc *KMDController) SetKMDBinDir(binDir string) {
	kc.kmd = filepath.Join(binDir, "kmd")
}

// SetKMDDataDir updates the KMDController for a kmd data directory.
func (kc *KMDController) SetKMDDataDir(kmdDataDir string) {
	kc.kmdDataDir = kmdDataDir
	kc.kmdPIDPath = filepath.Join(kmdDataDir, PIDFilename)
}

// StartKMD spins up a kmd process and waits for it to begin
func (kc *KMDController) StartKMD(args KMDStartArgs) (alreadyRunning bool, err error) {
	// Optimistically check if kmd is already running
	pid, err := kc.GetKMDPID()
	if err == nil {
		// Got a PID. Is there actually a process running there?
		// "If sig is 0, then no signal is sent, but existence and permission
		// checks are still performed"
		err = syscall.Kill(int(pid), syscall.Signal(0))
		if err == nil {
			// Yup, return alreadyRunning = true
			return true, nil
		}
		// Nope, clean up the files the zombie may have left behind
		kc.cleanUpZombieKMD()
	}

	if !filepath.IsAbs(kc.kmdDataDir) {
		logging.Base().Errorf("%s: kmd data dir is not an absolute path, which is unsafe", kc.kmdDataDir)
		return false, errKMDDataDirNotAbs
	}
	dataDirStat, err := os.Stat(kc.kmdDataDir)
	if err == nil {
		if !dataDirStat.IsDir() {
			logging.Base().Errorf("%s: kmd data dir exists but is not a directory", kc.kmdDataDir)
			return false, errors.New("bad kmd data dir")
		}
		if (dataDirStat.Mode() & 0077) != 0 {
			logging.Base().Errorf("%s: kmd data dir exists but is too permissive (%o)", kc.kmdDataDir, dataDirStat.Mode()&0777)
			return false, errors.New("kmd data dir not secure")
		}
	} else {
		err = os.MkdirAll(kc.kmdDataDir, DefaultKMDDataDirPerms)
		if err != nil {
			logging.Base().Errorf("%s: kmd data dir err: %s", kc.kmdDataDir, err)
			return false, err
		}
	}

	// Try to start the kmd process
	kmdCmd := kc.buildKMDCommand(args)

	// Capture stderr and stdout to files
	files := kc.setKmdCmdLogFiles(kmdCmd)
	// Descriptors will get dup'd after exec, so OK to close when we return
	for _, file := range files {
		defer file.Close()
	}

	err = kmdCmd.Start()
	if err != nil {
		return
	}

	// Call kmdCmd.Wait() to clean up the process when it exits and report
	// why it exited
	c := make(chan error)
	go func() {
		c <- kmdCmd.Wait()
	}()

	/*
		// Wait for kmd to start
		success := false
		for !success {
			select {
			case err = <-c:
				// Try to extract an exit code
				exitError, ok := err.(*exec.ExitError)
				if !ok {
					return false, errKMDExitedEarly
				}
				ws := exitError.Sys().(syscall.WaitStatus)
				exitCode := ws.ExitStatus()

				// Check if we exited because kmd is already running
				if exitCode == codes.ExitCodeKMDAlreadyRunning {
					return true, nil
				}

				// Fail on any other errors
				return false, errKMDExitedEarly
			case <-time.After(time.Millisecond * 100):
				// If we can't talk to the API yet, spin
				kmdClient, err := kc.KMDClient()
				if err != nil {
					continue
				}

				// See if the server is up by requesting the versions endpoint
				req := kmdapi.VersionsRequest{}
				resp := kmdapi.VersionsResponse{}
				err = kmdClient.DoV1Request(req, &resp)
				if err == nil {
					success = true
					continue
				}
			}
		}
	*/
	return
}

// GetKMDPID returns the PID from the kmd.pid file in the kmd data directory, or an error
func (kc KMDController) GetKMDPID() (pid int64, err error) {
	// Pull out the PID, ignoring newlines
	pidStr, err := util.GetFirstLineFromFile(kc.kmdPIDPath)
	if err != nil {
		return -1, err
	}
	// Parse as an integer
	pid, err = strconv.ParseInt(pidStr, 10, 32)
	return
}

// cleanUpZombieKMD removes files that a kmd node that's not actually running
// might have left behind
func (kc KMDController) cleanUpZombieKMD() {
	if kc.kmdPIDPath != "" {
		os.Remove(kc.kmdPIDPath)
	}
}

func (kc KMDController) buildKMDCommand(args KMDStartArgs) *exec.Cmd {
	var startArgs []string
	startArgs = append(startArgs, "-d")
	startArgs = append(startArgs, kc.kmdDataDir)
	startArgs = append(startArgs, "-t")
	startArgs = append(startArgs, fmt.Sprintf("%d", args.TimeoutSecs))
	return exec.Command(kc.kmd, startArgs...)
}

func (kc *KMDController) setKmdCmdLogFiles(cmd *exec.Cmd) (files []*os.File) {
	{ // Scoped to ensure err and out variables aren't mixed up
		errFileName := filepath.Join(kc.kmdDataDir, kmdStdErrFilename)
		errFile, err := os.OpenFile(errFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err == nil {
			cmd.Stderr = errFile
			files = append(files, errFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stderr: %v\n", err)
		}
	}
	{
		outFileName := filepath.Join(kc.kmdDataDir, kmdStdOutFilename)
		outFile, err := os.OpenFile(outFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err == nil {
			cmd.Stdout = outFile
			files = append(files, outFile)
		} else {
			fmt.Fprintf(os.Stderr, "error creating file for capturing stdout: %v\n", err)
		}
	}
	return
}

// KMDClient reads an APIToken and netFile from the kmd dataDir, and then
// builds a KMDClient for the running kmd process
func (kc KMDController) KMDClient() (kmdClient KMDClient, err error) {
	// Grab the KMD API token
	apiToken, err := tokens.GetAndValidateAPIToken(kc.kmdDataDir, tokens.KmdTokenFilename)
	if err != nil {
		return
	}

	// Grab the socket file location
	netFile := filepath.Join(kc.kmdDataDir, NetFilename)
	sockPath, err := util.GetFirstLineFromFile(netFile)
	if err != nil {
		return
	}

	// Build the client
	kmdClient, err = MakeKMDClient(sockPath, apiToken)
	return
}

// DoV1Request accepts a request from kmdapi/requests and
func (kcl KMDClient) DoV1Request(req kmdapi.APIV1Request, resp kmdapi.APIV1Response) error {

	var body []byte

	// Get the path and method for this request type
	reqPath, reqMethod, err := getPathAndMethod(req)
	if err != nil {
		return err
	}

	// Encode the request
	body = protocol.EncodeJSON(req)
	fullPath := fmt.Sprintf("http://%s/%s", kcl.address, reqPath)
	hreq, err := http.NewRequest(reqMethod, fullPath, bytes.NewReader(body))
	if err != nil {
		return err
	}

	// Add the auth token
	hreq.Header.Add(KMDTokenHeader, kcl.apiToken)

	// Send the request
	hresp, err := kcl.httpClient.Do(hreq)
	if err != nil {
		return err
	}

	// Decode the response object
	decoder := protocol.NewJSONDecoder(hresp.Body)
	err = decoder.Decode(resp)
	hresp.Body.Close()
	if err != nil {
		return err
	}

	// Check if this was an error response
	err = resp.GetError()
	if err != nil {
		return err
	}

	return nil
}

// CreateWallet wraps kmdapi.APIV1POSTWalletRequest
func (kcl KMDClient) CreateWallet(walletName []byte, walletDriverName string, walletPassword []byte, walletMDK crypto.MasterDerivationKey) (resp kmdapi.APIV1POSTWalletResponse, err error) {
	req := kmdapi.APIV1POSTWalletRequest{
		WalletName:          string(walletName),
		WalletDriverName:    walletDriverName,
		WalletPassword:      string(walletPassword),
		MasterDerivationKey: walletMDK,
	}
	err = kcl.DoV1Request(req, &resp)
	return
}

// Write implement the io.Writer interface and redirecting the written output
// to the correct pipe.
func (s *LaggedStdIo) Write(p []byte) (n int, err error) {
	if s.ioClass == 1 {
		return s.write(os.Stdout, p)
	}
	if s.ioClass == 2 {
		return s.write(os.Stderr, p)
	}
	return 0, nil
}

// Read implmenents the io.Reader interface and redirecting the read request to the
// correct stdin pipe.
func (s *LaggedStdIo) Read(p []byte) (n int, err error) {
	if s.ioClass == 0 {
		return os.Stdin.Read(p)
	}
	return 0, nil
}

// write responsible for (potentially) splitting the written output into multiple
// lines and adding a prefix for each line.
func (s *LaggedStdIo) write(writer io.Writer, p []byte) (n int, err error) {
	linePrefix := s.LinePrefix.Load().(string)
	// do we have a line prefix ?
	if linePrefix == "" {
		// if not, just write it out.
		return writer.Write(p)
	}
	// break the output buffer into multiple lines.
	lines := strings.Split(string(p), "\n")
	totalBytes := 0
	for _, outputLine := range lines {
		// avoid outputing empty lines.
		if len(outputLine) == 0 {
			continue
		}
		// prepare the line that we want to print
		s := linePrefix + " : " + outputLine + "\n"
		n, err = writer.Write([]byte(s))
		if err != nil {
			return totalBytes + n, err
		}
		totalBytes += n + 1
	}
	// if we success, output the original len(p), so that the caller won't know
	// we've diced and splited the original string.
	return len(p), nil
}

// SetLinePrefix sets the line prefix that would be used during the write opeearion.
func (s *LaggedStdIo) SetLinePrefix(linePrefix string) {
	s.LinePrefix.Store(linePrefix)
}
