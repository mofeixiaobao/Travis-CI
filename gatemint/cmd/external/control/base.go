package control

import (
	"encoding/json"
	"fmt"
	"github.com/gatechain/crypto"
	algodclient "github.com/gatechain/gatemint/daemon/gmd/api/client"
	"github.com/gatechain/gatemint/daemon/gmd/api/spec/common"
	v1 "github.com/gatechain/gatemint/daemon/gmd/api/spec/v1"
	"github.com/gatechain/gatemint/util"
	"os"
	"path/filepath"
)

// Client represents the entry point for all libgoal functions
type Client struct {
	nc           NodeController
	kmdStartArgs KMDStartArgs
	dataDir      string
	cacheDir     string
}


// ClientType represents the type of client you need
// It ensures the specified type(s) can be initialized
// when the libgoal client is created.
// Any client type not specified will be initialized on-demand.
type ClientType int


// ClientConfig is data to configure a Client
type ClientConfig struct {
	// AlgodDataDir is the data dir for `algod`
	AlgodDataDir string

	// KMDDataDir is the data dir for `kmd`, default ${HOME}/.algorand/kmd
	KMDDataDir string

	// CacheDir is a place to store some stuff
	CacheDir string

	// BinDir may be "" and it will be guesed
	BinDir string
}



const (
	// DynamicClient creates clients on-demand
	DynamicClient ClientType = iota
	// KmdClient ensures the kmd client can be initialized when created
	KmdClient
	// AlgodClient ensures the algod client can be initialized when created
	AlgodClient
	// FullClient ensures all clients can be initialized when created
	FullClient

	defaultKMDTimeoutSecs = 60
)

// SystemConfig is the json object in $ALGORAND_DATA/system.json
type SystemConfig struct {
	// SharedServer is true if this is a daemon on a multiuser system.
	// If not shared, kmd and other files are often stored under $ALGORAND_DATA when otherwise they might go under $HOME/.algorand/
	SharedServer bool `json:"shared_server,omitempty"`
}

// map data dir to loaded config
var systemConfigCache map[string]SystemConfig

var (
	// UnencryptedWalletName is the name of the default, unencrypted wallet
	UnencryptedWalletName = []byte("unencrypted-default-wallet")

	errorNoDataDirectory = fmt.Errorf("Data directory not specified.  Please make sure to pass dir path or an empty string " +
		" if $ALGORAND_DATA in your environment is set.")
)


func getDataDir(dataDir string) (string, error) {
	// Get the target data directory to work against,
	// then handle the scenario where no data directory is provided.

	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	dir := dataDir
	if dir == "" {
		dir = os.Getenv("ALGORAND_DATA")
	}
	if dir == "" {
		fmt.Println(errorNoDataDirectory.Error())
		return "", errorNoDataDirectory

	}
	return dir, nil
}


// MakeClientWithBinDir creates and inits a libgoal.Client, additionally
// allowing the user to specify a binary directory
func MakeClientWithBinDir(binDir, dataDir, cacheDir string, clientType ClientType) (c Client, err error) {
	config := ClientConfig{
		BinDir:       binDir,
		AlgodDataDir: dataDir,
		CacheDir:     cacheDir,
	}
	err = c.init(config, clientType)
	return
}


func getNodeController(binDir, dataDir string) (nc NodeController, err error) {
	dataDir, err = getDataDir(dataDir)
	if err != nil {
		return NodeController{}, nil
	}

	return MakeNodeController(binDir, dataDir), nil
}


// MakeClientFromConfig creates a libgoal.Client from a config struct with many options.
func MakeClientFromConfig(config ClientConfig, clientType ClientType) (c Client, err error) {
	if config.BinDir == "" {
		config.BinDir, err = util.ExeDir()
		if err != nil {
			return
		}
	}
	err = c.init(config, clientType)
	return
}


// AlgorandDataIsPrivate returns true if the algod data dir can be considered 'private' and we can store all related data there.
// Otherwise, some data will likely go under ${HOME}/.algorand/
func AlgorandDataIsPrivate(dataDir string) bool {
	if dataDir == "" {
		return true
	}
	sc, err := ReadSystemConfig(dataDir)
	if err != nil {
		return true
	}
	return !sc.SharedServer
}


// ReadSystemConfig read and parse $ALGORAND_DATA/system.json
func ReadSystemConfig(dataDir string) (sc SystemConfig, err error) {
	var ok bool
	sc, ok = systemConfigCache[dataDir]
	if ok {
		return
	}
	fin, err := os.Open(filepath.Join(dataDir, "system.json"))
	if _, isPathErr := err.(*os.PathError); isPathErr {
		// no file is fine, just return defaults
		err = nil
		return
	}
	if err != nil {
		return
	}
	dec := json.NewDecoder(fin)
	err = dec.Decode(&sc)
	if err == nil {
		systemConfigCache[dataDir] = sc
	}
	return
}

// Init takes data directory path or an empty string if $ALGORAND_DATA is defined and initializes Client
func (c *Client) init(config ClientConfig, clientType ClientType) error {
	// check and assign dataDir
	dataDir, err := getDataDir(config.AlgodDataDir)
	if err != nil {
		return err
	}
	c.dataDir = dataDir
	c.cacheDir = config.CacheDir

	// Get node controller
	nc, err := getNodeController(config.BinDir, config.AlgodDataDir)
	if err != nil {
		return err
	}
	if config.KMDDataDir != "" {
		nc.SetKMDDataDir(config.KMDDataDir)
	} else {
		algodKmdPath, _ := filepath.Abs(filepath.Join(dataDir, DefaultKMDDataDir))
		nc.SetKMDDataDir(algodKmdPath)
	}
	c.nc = nc

	// Initialize default kmd start args
	c.kmdStartArgs = KMDStartArgs{
		TimeoutSecs: defaultKMDTimeoutSecs,
	}

	if clientType == KmdClient || clientType == FullClient {
		_, err = c.ensureKmdClient()
		if err != nil {
			return err
		}
	}

	if clientType == AlgodClient || clientType == FullClient {
		_, err = c.ensureAlgodClient()
		if err != nil {
			return err
		}
	}
	return nil
}


func (c *Client) ensureKmdClient() (*KMDClient, error) {
	kmd, err := c.getKMDClient()
	if err != nil {
		return nil, err
	}
	return &kmd, nil
}


func (c *Client) ensureAlgodClient() (*algodclient.RestClient, error) {
	algod, err := c.getAlgodClient()
	if err != nil {
		return nil, err
	}
	return &algod, err
}


func (c *Client) getKMDClient() (KMDClient, error) {
	// Will return alreadyRunning = true if kmd already running
	_, err := c.nc.StartKMD(c.kmdStartArgs)
	if err != nil {
		return KMDClient{}, err
	}

	kmdClient, err := c.nc.KMDClient()
	if err != nil {
		return KMDClient{}, nil
	}
	return kmdClient, nil
}

func (c *Client) getAlgodClient() (algodclient.RestClient, error) {
	algodClient, err := c.nc.AlgodClient()
	if err != nil {
		return algodclient.RestClient{}, err
	}
	return algodClient, nil
}

// FullStop stops the clients including graceful shutdown to algod and kmd
func (c *Client) FullStop() error {
	return c.nc.FullStop()
}


// CreateWallet creates a kmd wallet with the specified parameters
func (c *Client) CreateWallet(name []byte, password []byte, mdk crypto.MasterDerivationKey) ([]byte, error) {
	// Pull the list of all wallets from kmd
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return nil, err
	}

	// Create the wallet
	resp, err := kmd.CreateWallet(name, "levelDB", password, mdk)
	if err != nil {
		return nil, err
	}

	return []byte(resp.Wallet.ID), nil
}

// HealthCheck returns an error if something is wrong
func (c *Client) HealthCheck() error {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		err = algod.HealthCheck()
	}
	return err
}


// GetPendingTransactions gets a snapshot of current pending transactions on the node.
// If maxTxns = 0, fetches as many transactions as possible.
func (c *Client) GetPendingTransactions(maxTxns uint64) (resp v1.PendingTransactions, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.GetPendingTransactions(maxTxns)
	}
	return
}


// Status returns the node status
func (c *Client) Status() (resp v1.NodeStatus, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.Status()
	}
	return
}


// AlgodVersions return the list of supported API versions in algod
func (c Client) AlgodVersions() (resp common.Version, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.Versions()
	}
	return
}


// CurrentRound returns the current known round
func (c Client) CurrentRound() (lastRound uint64, err error) {
	// Get current round
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err := algod.Status()
		if err == nil {
			lastRound = resp.LastRound
		}
	}
	return
}
