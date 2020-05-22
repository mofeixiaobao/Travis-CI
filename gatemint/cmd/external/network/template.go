package network

import (
	"encoding/json"
	"fmt"
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/cmd/external/control"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/gen"
	"github.com/gatechain/gatemint/util"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type walletTemplateData struct {
	Name              string
	ParticipationOnly bool
}

type nodeConfig struct {
	Name              string
	IsRelay           bool
	Wallets           []walletTemplateData
	DeadlockDetection int
}

// Template represents the template used for creating private named networks
type Template struct {
	Genesis gen.GenesisData
	Nodes   []nodeConfig
}

var defaultTemplate = Template{
	Genesis: gen.DefaultGenesis,
}

func loadTemplateFromReader(reader io.Reader, template *Template) error {
	dec := json.NewDecoder(reader)
	return dec.Decode(template)
}

func loadTemplate(templateFile string) (Template, error) {
	template := defaultTemplate
	f, err := os.Open(templateFile)
	if err != nil {
		return template, err
	}
	defer f.Close()

	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		// for arm machines, use smaller key dilution
		template.Genesis.PartKeyDilution = 100
	}

	err = loadTemplateFromReader(f, &template)
	return template, err
}

func (t Template) generateGenesisAndWallets(targetFolder, networkName, binDir string) error {
	genesisData := t.Genesis
	genesisData.NetworkName = networkName
	return gen.GenerateGenesisFiles(genesisData, targetFolder, true)
}

// Validate a specific network template to ensure it's rational, consistent, and complete
func (t Template) Validate() error {
	// Genesis wallet percentages must add up to 100
	// Genesis account names must be unique
	totalPct := uint(0)
	accounts := make(map[string]bool)
	for _, wallet := range t.Genesis.Wallets {
		totalPct += uint(wallet.Stake)
		upperAcct := strings.ToUpper(wallet.Name)
		if _, found := accounts[upperAcct]; found {
			return fmt.Errorf("invalid template: duplicate Genesis account %s", wallet.Name)
		}
		accounts[upperAcct] = true
	}
	if totalPct != 100 {
		return fmt.Errorf("invalid template: Genesis account allocations must total 100 (actual %v)", totalPct)
	}

	// No wallet can be assigned to more than one node
	// At least one relay is required
	wallets := make(map[string]bool)
	relayCount := 0
	for _, cfg := range t.Nodes {
		if cfg.IsRelay {
			relayCount++
		}
		for _, wallet := range cfg.Wallets {
			upperWallet := strings.ToUpper(wallet.Name)
			if _, found := wallets[upperWallet]; found {
				return fmt.Errorf("invalid template: Wallet '%s' assigned to multiple nodes", wallet.Name)
			}
			wallets[upperWallet] = true
		}
	}
	if relayCount == 0 {
		return fmt.Errorf("invalid template: at least one relay is required")
	}

	return nil
}

// Create data folders for all NodeConfigs, configuring relays appropriately and
// returning the full path to the 'prime' relay and node folders (the first one created) and the genesis data used in this network.
func (t Template) createNodeDirectories(targetFolder string, binDir string, importKeys bool) (relayDirs []string, nodeDirs map[string]string, genData gen.GenesisData, err error) {
	genesisFile := filepath.Join(targetFolder, genesisFileName)
	genData, err = gen.LoadGenesisData(genesisFile)
	if err != nil {
		return
	}

	nodeDirs = make(map[string]string)
	getGenesisVerCmd := filepath.Join(binDir, "gmd")
	importKeysCmd := filepath.Join(binDir, "gm")
	genesisVer, _, err := util.ExecAndCaptureOutput(getGenesisVerCmd, "-G", "-d", targetFolder)
	if err != nil {
		return
	}
	genesisVer = strings.TrimSpace(genesisVer)

	for _, cfg := range t.Nodes {
		nodeDir := filepath.Join(targetFolder, cfg.Name)
		err = os.Mkdir(nodeDir, os.ModePerm)
		if err != nil {
			return
		}

		_, err = util.CopyFile(genesisFile, filepath.Join(nodeDir, genesisFileName))
		if err != nil {
			return
		}

		if cfg.IsRelay {
			_, err = filepath.Abs(nodeDir)
			if err != nil {
				return
			}
			relayDirs = append(relayDirs, cfg.Name)
		} else {
			nodeDirs[cfg.Name] = cfg.Name
		}

		genesisDir := filepath.Join(nodeDir, genesisVer)
		err = os.Mkdir(genesisDir, os.ModePerm)
		if err != nil {
			return
		}

		var files []os.FileInfo
		files, err = ioutil.ReadDir(targetFolder)
		if err != nil {
			return
		}

		hasWallet := false
		for _, info := range files {
			name := info.Name()
			if config.IsRootKeyFilename(name) || config.IsPartKeyFilename(name) {
				for _, wallet := range cfg.Wallets {
					if (config.MatchesRootKeyFilename(wallet.Name, name) && !wallet.ParticipationOnly) || config.MatchesPartKeyFilename(wallet.Name, name) {
						// fmt.Println("cp", filepath.Join(targetFolder, name), "->", filepath.Join(genesisDir, name))
						_, err = util.CopyFile(filepath.Join(targetFolder, name), filepath.Join(genesisDir, name))
						if err != nil {
							return
						}
						hasWallet = true
					}
				}
			}
		}

		if importKeys && hasWallet {
			var client control.Client
			client, err = control.MakeClientWithBinDir(binDir, nodeDir, "", control.KmdClient)
			_, err = client.CreateWallet(control.UnencryptedWalletName, nil, crypto.MasterDerivationKey{})
			if err != nil {
				return
			}

			_, _, err = util.ExecAndCaptureOutput(importKeysCmd, "account", "importrootkey", "-w", string(control.UnencryptedWalletName), "-d", nodeDir)
			if err != nil {
				return
			}
		}

		// Create any necessary config.json file for this node
		nodeCfg := filepath.Join(nodeDir, config.ConfigFilename)
		err = cfg.createConfigFile(nodeCfg, len(t.Nodes)-1) // minus 1 to avoid counting self
		if err != nil {
			return
		}
	}
	return
}

// TODO: Build the JSON object using a real encoder
func (node nodeConfig) createConfigFile(configFile string, numNodes int) error {
	// Override default :8080 REST endpoint, and disable SRV lookup
	configString := `{ "GossipFanout": ` + fmt.Sprintf("%d", numNodes) +
		`, "EndpointAddress": "127.0.0.1:0", "DNSBootstrapID": ""`
	if node.IsRelay {
		// Have relays listen on any localhost port
		configString += `, "NetAddress": "127.0.0.1:0"`
	} else {
		// Non-relays should not open incoming connections
		configString += `, "IncomingConnectionsLimit": 0`
	}

	// 	This setting works in conjunction with the Archival setting.
	// 	If Archival is set to false this setting does nothing.
	// 	If it set to true, the node tracks all transactions stored on the node in an indexer and allows two additional REST calls for fast transaction searches. See Algorand Node Types for more information.
	configString += `, "IsIndexerActive": true`

	if node.DeadlockDetection != 0 {
		configString += fmt.Sprintf(`, "DeadlockDetection": %d`, node.DeadlockDetection)
	}

	configString += " }"
	return ioutil.WriteFile(configFile, []byte(configString), os.ModePerm)
}
