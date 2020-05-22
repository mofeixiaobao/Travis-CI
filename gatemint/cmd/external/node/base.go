package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gatechain/gatemint/cmd/external/control"
	"github.com/gatechain/gatemint/config"
	v1 "github.com/gatechain/gatemint/daemon/gmd/api/spec/v1"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/gatemint/util"
	"github.com/gatechain/gatemint/util/tokens"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

var defaultCacheDir = "goal.cache"
var kmdDataDirFlag string

var peerDial string
var listenIP string
var runUnderHost bool
var telemetryOverride string
var dataDirs []string

var targetDir string
var noLedger bool

var maxPendingTransactions uint64

var waitSec uint32

var newNodeNetwork string
var newNodeDestination string
var newNodeArchival bool
var newNodeIndexer bool
var newNodeRelay string

const (
	errorNoDataDirectory             = "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment. Exiting."
	infoNodeStart                    = "Algorand node successfully started!"
	infoNodeAlreadyStarted           = "Algorand node was already started!"
	errorNodeFailedToStart           = "Algorand node failed to start: %s"
	infoDataDir                      = "[Data Directory: %s]"
	errLoadingConfig                 = "Error loading Config file from '%s': %v"
	infoTryingToStopNode             = "Trying to stop the node..."
	errorKill                        = "Cannot kill node: %s"
	infoNodeSuccessfullyStopped      = "The node was successfully stopped."
	errorNodeStatus                  = "Cannot contact Algorand node: %s."
	infoNodeStatus                   = "Last committed block: %d\nTime since last block: %s\nSync Time: %s\nLast consensus protocol: %s\nNext consensus protocol: %s\nRound for next consensus protocol: %d\nNext consensus protocol supported: %v\nHas Synced Since Startup: %t"
	errorNodeNotDetected             = "Algorand node does not appear to be running: %s"
	errorOneDataDirSupported         = "Only one data directory can be specified for this command."
	errorCloningNode                 = "Error cloning the node: %s"
	infoNodeCloned                   = "Node cloned successfully to: %s"
	errorNodeRunning                 = "Node must be stopped before writing APIToken"
	errorNodeFailGenToken            = "Cannot generate API token: %s"
	infoNodeWroteToken               = "Successfully wrote new API token: %s"
	infoNodePendingTxnsDescription   = "Pending Transactions (Truncated max=%d, Total in pool=%d): "
	infoNodeNoPendingTxnsDescription = "None"
	errorNodeCreation                = "Error during node creation: %v"
	errorNodeCreationIPFailure       = "Parsing passed IP %v failed: need a valid IPv4 or IPv6 address with a specified port number"
)

func Command() *cobra.Command {
	nodeCmd := &cobra.Command{
		Use:   "node",
		Short: "Manage a specified algorand node",
		Long:  `Collection of commands to support the creation and management of Algorand node instances, where each instance corresponds to a unique data directory.`,
		Run: func(cmd *cobra.Command, args []string) {
			//Fall back
			cmd.HelpFunc()(cmd, args)
		},
	}

	nodeCmd.PersistentFlags().StringArrayVarP(&dataDirs, "datadir", "d", []string{""}, "Data directory for the node")

	nodeCmd.AddCommand(startCmd())
	nodeCmd.AddCommand(stopCmd())
	nodeCmd.AddCommand(statusCmd())
	nodeCmd.AddCommand(lastRoundCmd())
	nodeCmd.AddCommand(restartCmd())
	nodeCmd.AddCommand(cloneCmd())
	nodeCmd.AddCommand(generateTokenCmd())
	nodeCmd.AddCommand(pendingTxnsCmd())
	nodeCmd.AddCommand(waitCmd())
	nodeCmd.AddCommand(createCmd())

	return nodeCmd
}

func startCmd() *cobra.Command {
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Init the specified algorand node",
		Long:  `Init the specified algorand node`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Start Node
			Start(peerDial, listenIP, telemetryOverride, runUnderHost)
		},
	}

	startCmd.Flags().StringVarP(&peerDial, "peer", "p", "", "Peer address to dial for initial connection")
	startCmd.Flags().StringVarP(&listenIP, "listen", "l", "", "Endpoint / REST address to listen on")
	startCmd.Flags().BoolVarP(&runUnderHost, "hosted", "H", false, "Run algod hosted by algoh")
	startCmd.Flags().StringVarP(&telemetryOverride, "telemetry", "t", "", `Enable telemetry if supported (Use "true", "false", "0" or "1")`)

	return startCmd
}

func stopCmd() *cobra.Command {
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "stop the specified Algorand node",
		Long:  `Stop the specified Algorand node`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Stop
			Stop()
		},
	}

	return stopCmd
}

func statusCmd() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Get the current node status",
		Long:  `Show the current status of the running Algorand node`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Status
			Status()
		},
	}

	return statusCmd
}

func lastRoundCmd() *cobra.Command {
	lastRoundCmd := &cobra.Command{
		Use:   "lastround",
		Short: "Print the last round number",
		Run: func(cmd *cobra.Command, _ []string) {
			//
			LastRound()
		},
	}

	return lastRoundCmd
}

func restartCmd() *cobra.Command {
	restartCmd := &cobra.Command{
		Use:   "restart",
		Short: "stop, and then start, the specified Algorand node",
		Long:  `Stop, and then start, the specified Algorand node`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Restart
			Restart(peerDial, listenIP, telemetryOverride, runUnderHost)
		},
	}

	restartCmd.Flags().StringVarP(&peerDial, "peer", "p", "", "Peer address to dial for initial connection")
	restartCmd.Flags().StringVarP(&listenIP, "listen", "l", "", "Endpoint / REST address to listen on")
	restartCmd.Flags().BoolVarP(&runUnderHost, "hosted", "H", false, "Run algod hosted by algoh")
	restartCmd.Flags().StringVarP(&telemetryOverride, "telemetry", "t", "", `Enable telemetry if supported (Use "true", "false", "0" or "1")`)

	return restartCmd
}

func cloneCmd() *cobra.Command {
	cloneCmd := &cobra.Command{
		Use:   "clone",
		Short: "Clone the specified node to create another node",
		Long:  `Clone the specified node to create another node. Optionally you can control whether the clone includes the current ledger, or if it starts with an uninitialized one. The default is to clone the ledger as well. Specify -n or --noledger to start with an uninitialized ledger.`,
		Run: func(cmd *cobra.Command, _ []string) {
			//
			Clone(targetDir, noLedger)
		},
	}

	cloneCmd.Flags().StringVarP(&targetDir, "targetdir", "t", "", "Target directory for the clone")
	cloneCmd.Flags().BoolVarP(&noLedger, "noledger", "n", false, "Don't include ledger when copying (No Ledger)")

	return cloneCmd
}

func generateTokenCmd() *cobra.Command {
	generateTokenCmd := &cobra.Command{
		Use:   "generatetoken",
		Short: "Generate and install a new API token",
		Long:  "Generate and install a new API token",
		Run: func(cmd *cobra.Command, _ []string) {
			//
			GenerateToken()
		},
	}

	return generateTokenCmd
}

func pendingTxnsCmd() *cobra.Command {
	pendingTxnsCmd := &cobra.Command{
		Use:   "pendingtxns",
		Short: "Get a snapshot of current pending transactions on this node",
		Long:  `Get a snapshot of current pending transactions on this node, cut off at MAX transactions (-m), default 0. If MAX=0, fetches as many transactions as possible.`,
		Run: func(cmd *cobra.Command, _ []string) {
			//
			PendingTxns(maxPendingTransactions)
		},
	}

	pendingTxnsCmd.Flags().Uint64VarP(&maxPendingTransactions, "maxPendingTxn", "m", 0, "Cap the number of txns to fetch")

	return pendingTxnsCmd
}

func waitCmd() *cobra.Command {
	waitCmd := &cobra.Command{
		Use:   "wait",
		Short: "Waits for the node to make progress",
		Long:  "Waits for the node to make progress, which includes catching up",
		Run: func(cmd *cobra.Command, _ []string) {
			//
			Wait(waitSec)
		},
	}

	waitCmd.Flags().Uint32VarP(&waitSec, "waittime", "w", 5, "Time (in seconds) to wait for node to make progress")

	return waitCmd
}

func createCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "create a node at the desired data directory for the desired network",
		Long:  "create a node at the desired data directory for the desired network",
		Run: func(cmd *cobra.Command, _ []string) {
			//
			Create(newNodeNetwork, newNodeDestination, newNodeRelay, listenIP, newNodeArchival, newNodeIndexer, runUnderHost)
		},
	}

	createCmd.Flags().StringVar(&newNodeNetwork, "network", "", "Network the new node should point to")
	createCmd.Flags().StringVar(&newNodeDestination, "destination", "", "Destination path for the new node")
	localDefaults := config.GetDefaultLocal()
	createCmd.Flags().BoolVarP(&newNodeArchival, "archival", "a", localDefaults.Archival, "Make the new node archival, storing all blocks")
	createCmd.Flags().BoolVarP(&runUnderHost, "hosted", "H", localDefaults.RunHosted, "Configure the new node to run hosted by algoh")
	createCmd.Flags().BoolVarP(&newNodeIndexer, "indexer", "i", localDefaults.IsIndexerActive, "Configure the new node to enable the indexer feature (implies --archival)")
	createCmd.Flags().StringVar(&newNodeRelay, "relay", localDefaults.NetAddress, "Configure as a relay with specified listening address (NetAddress)")
	createCmd.Flags().StringVar(&listenIP, "api", "", "REST API Endpoint")
	createCmd.MarkFlagRequired("destination")
	createCmd.MarkFlagRequired("network")

	return createCmd
}

func Start(peerDial, listenIP, telemetryOverride string, runUnderHost bool) {
	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}

	onDataDirs(func(dataDir string) {
		nc := control.MakeNodeController(binDir, dataDir)
		nodeArgs := control.AlgodStartArgs{
			PeerAddress:       peerDial,
			ListenIP:          listenIP,
			RedirectOutput:    false,
			RunUnderHost:      runUnderHost,
			TelemetryOverride: telemetryOverride,
		}

		if getRunHostedConfigFlag(dataDir) {
			nodeArgs.RunUnderHost = true
		}

		algodAlreadyRunning, err := nc.StartAlgod(nodeArgs)
		if algodAlreadyRunning {
			reportInfoln(infoNodeAlreadyStarted)
		}

		if err != nil {
			reportErrorf(errorNodeFailedToStart, err)
		} else {
			reportInfoln(infoNodeStart)
		}
	})
}

func Stop() {
	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}
	onDataDirs(func(dataDir string) {
		nc := control.MakeNodeController(binDir, dataDir)

		reportInfof(infoTryingToStopNode)

		err = nc.FullStop()
		if err != nil {
			reportErrorf(errorKill, err)
		}

		reportInfoln(infoNodeSuccessfullyStopped)
	})
}

func Status() {
	onDataDirs(getStatus)
}

func LastRound() {
	onDataDirs(func(dataDir string) {
		round, err := ensureAlgodClient(dataDir).CurrentRound()
		if err != nil {
			reportErrorf(errorNodeStatus, err)
		}

		reportInfof("%d\n", round)
	})
}

func Restart(peerDial, listenIP, telemetryOverride string, runUnderHost bool) {
	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}
	onDataDirs(func(dataDir string) {
		nc := control.MakeNodeController(binDir, dataDir)

		_, err = nc.GetAlgodPID()

		if err != nil {
			reportInfof(errorNodeNotDetected, err)
			fmt.Println("Attempting to start the Algorand node anyway...")
		} else {
			reportInfof(infoTryingToStopNode)
			err = nc.FullStop()
			if err != nil {
				reportInfof(errorKill, err)
				fmt.Println("Attempting to start the Algorand node anyway...")
			} else {
				reportInfoln(infoNodeSuccessfullyStopped)
			}
		}
		// brief sleep to allow the node to finish shutting down
		time.Sleep(time.Duration(time.Second))

		nodeArgs := control.AlgodStartArgs{
			PeerAddress:       peerDial,
			ListenIP:          listenIP,
			RedirectOutput:    false,
			RunUnderHost:      runUnderHost,
			TelemetryOverride: telemetryOverride,
		}

		if getRunHostedConfigFlag(dataDir) {
			nodeArgs.RunUnderHost = true
		}

		algodAlreadyRunning, err := nc.StartAlgod(nodeArgs)
		if algodAlreadyRunning {
			reportInfoln(infoNodeAlreadyStarted)
		}

		if err != nil {
			reportErrorf(errorNodeFailedToStart, err)
		} else {
			reportInfoln(infoNodeStart)
		}
	})
}

func Clone(targetDir string, noLedger bool) {
	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}
	nc := control.MakeNodeController(binDir, ensureSingleDataDir())
	err = nc.Clone(targetDir, !noLedger)
	if err != nil {
		reportErrorf(errorCloningNode, err)
	} else {
		reportInfof(infoNodeCloned, targetDir)
	}
}

func GenerateToken() {
	onDataDirs(func(dataDir string) {
		// Ensure the node is stopped -- HealthCheck should fail
		clientConfig := control.ClientConfig{
			AlgodDataDir: dataDir,
			//KMDDataDir:   resolveKmdDataDir(dataDir),
			CacheDir: ensureCacheDir(dataDir),
		}
		client, err := control.MakeClientFromConfig(clientConfig, control.AlgodClient)
		if err == nil {
			err = client.HealthCheck()
			if err == nil {
				reportErrorln(errorNodeRunning)
			}
		}

		// Generate & persist a new token
		apiToken, err := tokens.GenerateAPIToken(dataDir, tokens.GmdTokenFilename)
		if err != nil {
			reportErrorf(errorNodeFailGenToken, err)
		}

		// Report the new token back to the user
		reportInfof(infoNodeWroteToken, apiToken)
	})
}

func PendingTxns(maxPendingTransactions uint64) {
	onDataDirs(func(dataDir string) {
		client := ensureAlgodClient(dataDir)
		statusTxnPool, err := client.GetPendingTransactions(maxPendingTransactions)
		if err != nil {
			reportErrorf(errorNodeStatus, err)
		}

		pendingTxns := statusTxnPool.TruncatedTxns

		// do this inline for now, break it out when we need to reuse a Txn->String function
		reportInfof(infoNodePendingTxnsDescription, maxPendingTransactions, statusTxnPool.TotalTxns)
		if pendingTxns.Transactions == nil || len(pendingTxns.Transactions) == 0 {
			reportInfof(infoNodeNoPendingTxnsDescription)
		} else {
			for _, pendingTxn := range pendingTxns.Transactions {
				pendingTxnStr, err := json.MarshalIndent(pendingTxn, "", "    ")
				if err != nil {
					// json parsing of the txn failed, so let's just skip printing it
					fmt.Printf("Unparseable Transaction %s\n", pendingTxn.TxID)
					continue
				}
				fmt.Printf("%s\n", string(pendingTxnStr))
			}
		}
	})
}

func Wait(waitSec uint32) {
	client := ensureAlgodClient(ensureSingleDataDir())
	stat, err := client.Status()
	if err != nil {
		reportErrorf(errorNodeStatus, err)
	}

	startRound := stat.LastRound
	endTime := time.After(time.Second * time.Duration(waitSec))
	for {
		select {
		case <-endTime:
			reportErrorf("Timed out waiting for node to make progress")
		case <-time.After(500 * time.Millisecond):
			stat, err = client.Status()
			if err != nil {
				reportErrorf(errorNodeStatus, err)
			}
			if startRound != stat.LastRound {
				os.Exit(0)
			}
		}
	}
}

func Create(newNodeNetwork, newNodeDestination, newNodeRelay, listenIP string, newNodeArchival, newNodeIndexer, runUnderHost bool) {
	// validate network input
	validNetworks := map[string]bool{"mainnet": true, "testnet": true, "devnet": true, "betanet": true}
	if !validNetworks[newNodeNetwork] {
		reportErrorf(errorNodeCreation, "passed network name invalid")
	}

	// validate and store passed options
	localConfig := config.GetDefaultLocal()
	if newNodeRelay != "" {
		if isValidIP(newNodeRelay) {
			localConfig.NetAddress = newNodeRelay
		} else {
			reportErrorf(errorNodeCreationIPFailure, newNodeRelay)
		}
	}
	if listenIP != "" {
		if isValidIP(listenIP) {
			localConfig.EndpointAddress = listenIP
		} else {
			reportErrorf(errorNodeCreationIPFailure, listenIP)
		}
	}
	localConfig.Archival = newNodeArchival || newNodeRelay != "" || newNodeIndexer
	localConfig.IsIndexerActive = newNodeIndexer
	localConfig.RunHosted = runUnderHost

	// locate genesis block
	exePath, err := util.ExeDir()
	if err != nil {
		reportErrorln(errorNodeCreation, err)
	}
	firstChoicePath := filepath.Join(exePath, "genesisfiles", newNodeNetwork, "genesis.json")
	secondChoicePath := filepath.Join("var", "lib", "algorand", "genesis", newNodeNetwork, "genesis.json")
	thirdChoicePath := filepath.Join(exePath, "genesisfiles", "genesis", newNodeNetwork, "genesis.json")
	paths := []string{firstChoicePath, secondChoicePath, thirdChoicePath}
	correctPath := ""
	for _, pathCandidate := range paths {
		if util.FileExists(pathCandidate) {
			correctPath = pathCandidate
			break
		}
	}
	if correctPath == "" {
		reportErrorf("Could not find genesis.json file. Paths checked: %v", strings.Join(paths, ","))
	}

	// verify destination does not exist, and attempt to create destination folder
	if util.FileExists(newNodeDestination) {
		reportErrorf(errorNodeCreation, "destination folder already exists")
	}
	destPath := filepath.Join(newNodeDestination, "genesis.json")
	err = os.MkdirAll(newNodeDestination, 0766)
	if err != nil {
		reportErrorf(errorNodeCreation, "could not create destination folder")
	}

	// copy genesis block to destination
	_, err = util.CopyFile(correctPath, destPath)
	if err != nil {
		reportErrorf(errorNodeCreation, err)
	}

	// save config to destination
	err = localConfig.SaveToDisk(newNodeDestination)
	if err != nil {
		reportErrorf(errorNodeCreation, err)
	}
}

func onDataDirs(action func(dataDir string)) {
	dirs := getDataDirs()
	report := len(dirs) > 1

	for _, dir := range dirs {
		if report {
			reportInfof(infoDataDir, dir)
		}
		action(dir)
	}
}

func getDataDirs() (dirs []string) {
	if len(dataDirs) == 0 {
		reportErrorln(errorNoDataDirectory)
	}
	dirs = append(dirs, ensureFirstDataDir())
	dirs = append(dirs, dataDirs[1:]...)
	return
}

func ensureFirstDataDir() string {
	// Get the target data directory to work against,
	// then handle the scenario where no data directory is provided.
	dir := resolveDataDir()
	if dir == "" {
		reportErrorln(errorNoDataDirectory)
	}
	return dir
}

func resolveDataDir() string {
	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if len(dataDirs) > 0 {
		dir = dataDirs[0]
	}
	if dir == "" {
		dir = os.Getenv("ALGORAND_DATA")
	}
	return dir
}

func getRunHostedConfigFlag(dataDir string) bool {
	// See if this instance wants to run Hosted, even if '-H' wasn't specified on our cmdline
	cfg, err := config.LoadConfigFromDisk(dataDir)
	if err != nil && !os.IsNotExist(err) {
		reportErrorf(errLoadingConfig, dataDir, err)
	}
	return cfg.RunHosted
}

func ensureSingleDataDir() string {
	if len(dataDirs) > 1 {
		reportErrorln(errorOneDataDirSupported)
	}
	return ensureFirstDataDir()
}

func getStatus(dataDir string) {
	client := ensureAlgodClient(dataDir)
	stat, err := client.Status()
	if err != nil {
		reportErrorf(errorNodeStatus, err)
	}
	vers, err := client.AlgodVersions()
	if err != nil {
		reportErrorf(errorNodeStatus, err)
	}

	fmt.Println(makeStatusString(stat))
	if vers.GenesisID != "" {
		fmt.Printf("Genesis ID: %s\n", vers.GenesisID)
	}
	fmt.Printf("Genesis hash: %s\n", base64.StdEncoding.EncodeToString(vers.GenesisHash[:]))
}

func ensureAlgodClient(dataDir string) control.Client {
	return ensureGoalClient(dataDir, control.AlgodClient)
}

func ensureGoalClient(dataDir string, clientType control.ClientType) control.Client {
	clientConfig := control.ClientConfig{
		AlgodDataDir: dataDir,
		KMDDataDir:   resolveKmdDataDir(dataDir),
		CacheDir:     ensureCacheDir(dataDir),
	}
	client, err := control.MakeClientFromConfig(clientConfig, clientType)
	if err != nil {
		reportErrorf(errorNodeStatus, err)
	}
	return client
}

// -k || $ALGORAND_KMD || old location in algod data dir if it is a 'private' dev algo data dir || ~/.algorand/{genesis id}/kmd-{kmd version}
func resolveKmdDataDir(dataDir string) string {
	if kmdDataDirFlag != "" {
		out, _ := filepath.Abs(kmdDataDirFlag)
		return out
	}
	kmdDataDirEnv := os.Getenv("ALGORAND_KMD")
	if kmdDataDirEnv != "" {
		out, _ := filepath.Abs(kmdDataDirEnv)
		return out
	}
	if dataDir == "" {
		dataDir = resolveDataDir()
	}
	if control.AlgorandDataIsPrivate(dataDir) {
		algodKmdPath, _ := filepath.Abs(filepath.Join(dataDir, control.DefaultKMDDataDir))
		return algodKmdPath
	}
	cu, err := user.Current()
	if err != nil {
		reportErrorf("could not look up current user while looking for kmd dir: %s", err)
	}
	if cu.HomeDir == "" {
		reportErrorln("user has no home dir while looking for kmd dir")
	}
	genesis, err := readGenesis(dataDir)
	if err != nil {
		reportErrorf("could not read genesis.json: %s", err)
	}
	return filepath.Join(cu.HomeDir, ".algorand", genesis.ID(), control.DefaultKMDDataDir)
}

func makeStatusString(stat v1.NodeStatus) string {
	lastRoundTime := fmt.Sprintf("%.1fs", stat.TimeSinceLastRound)
	catchupTime := fmt.Sprintf("%.1fs", time.Duration(stat.CatchupTime).Seconds())
	return fmt.Sprintf(infoNodeStatus, stat.LastRound, lastRoundTime, catchupTime, stat.LastVersion, stat.NextVersion, stat.NextVersionRound, stat.NextVersionSupported, stat.HasSyncedSinceStartup)
}

func ensureCacheDir(dataDir string) string {
	var err error
	if control.AlgorandDataIsPrivate(dataDir) {
		cacheDir := filepath.Join(dataDir, defaultCacheDir)
		err = os.Mkdir(cacheDir, 0700)
		if err != nil && !os.IsExist(err) {
			reportErrorf("could not make cachedir: %s", err)
		}
		return cacheDir
	}
	// Put the cache in the user's home directory
	algorandDir, err := config.GetDefaultConfigFilePath()
	if err != nil {
		reportErrorf("config error %s", err)
	}
	dataDirEscaped := strings.ReplaceAll(dataDir, "/", "_")
	cacheDir := filepath.Join(algorandDir, dataDirEscaped)
	err = os.MkdirAll(cacheDir, 0700)
	if err != nil {
		reportErrorf("could not make cachedir: %s", err)
	}
	return cacheDir
}

func readGenesis(dataDir string) (genesis bookkeeping.Genesis, err error) {
	path := filepath.Join(dataDir, config.GenesisJSONFile)
	genesisText, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	err = protocol.DecodeJSON(genesisText, &genesis)
	return
}

func isValidIP(userInput string) bool {
	host, port, err := net.SplitHostPort(userInput)
	if err != nil {
		return false
	}
	if port == "" {
		return false
	}
	if host == "" {
		return false
	}
	return net.ParseIP(host) != nil
}

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	// log.Infof(format, args...)
}

func reportInfoln(args ...interface{}) {
	fmt.Println(args...)
	// log.Infoln(args...)
}

func reportErrorln(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	// log.Warnf(format, args...)
	os.Exit(1)
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	// log.Warnf(format, args...)
	os.Exit(1)
}
