package network

import (
	"fmt"
	"github.com/gatechain/gatemint/util"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

const (
	infoNetworkAlreadyExists = "Network Root Directory '%s' already exists"
	errorCreateNetwork       = "Error creating private network: %s"
	infoNetworkCreated       = "Network %s created under %s"
	errorLoadingNetwork      = "Error loading deployed network: %s"
	errorStartingNetwork     = "Error starting deployed network: %s"
	infoNetworkStarted       = "Network Started under %s"
	infoNetworkStopped       = "Network Stopped under %s"
	infoNetworkDeleted       = "Network Deleted under %s"
	infoAutoFeeSet = "Automatically set fee to %d MicroAlgos"

	// Node
	infoNodeStart            = "Algorand node successfully started!"
	errorNodeFailedToStart   = "Algorand node failed to start: %s"
)


var networkRootDir string
var networkName string
var networkTemplateFile string
var startNode string
var noImportKeys bool
var noClean bool


func Command() *cobra.Command {
	networkCmd := &cobra.Command{
		Use:   "network",
		Short: "Create and manage private, multi-node, locally-hosted networks",
		Long: `Collection of commands to support the creation and management of 'private networks'. These are fully-formed Algorand networks with private, custom Genesis ledgers running the current build of Algorand software. Rather than creating a node instance based on the released genesis.json, these networks have their own and need to be manually connected.

The basic idea is that we create one or more data directories and wallets to form this network, specify which node owns which wallets, and can start/stop the network as a unit. Each node is just like any other node running on TestNet or DevNet.`,
		Run: func(cmd *cobra.Command, args []string) {
			//Fall back
			cmd.HelpFunc()(cmd, args)
		},
	}

	networkCmd.AddCommand(networkCreateCmd())
	networkCmd.PersistentFlags().StringVarP(&networkRootDir, "rootdir", "r", "", "Root directory for the private network directories")
	networkCmd.MarkPersistentFlagRequired("rootdir")

	networkCmd.AddCommand(networkStartCmd())
	networkCmd.AddCommand(networkRestartCmd())
	networkCmd.AddCommand(networkStopCmd())
	networkCmd.AddCommand(networkStatusCmd())
	networkCmd.AddCommand(networkDeleteCmd())

	return networkCmd
}


func networkCreateCmd() *cobra.Command {
	networkCreateCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a private named network from a template",
		Long:  `Creates a collection of folders under the specified root directory that make up the entire private network named 'private' (simplifying cleanup).`,
		Run: func(cmd *cobra.Command, _ []string) {
			print("network create command")

			Create(networkName, networkRootDir, networkTemplateFile, !noImportKeys, noClean)
		},
	}

	networkCreateCmd.Flags().StringVarP(&networkName, "network", "n", "", "Specify the name to use for the private network")
	networkCreateCmd.MarkFlagRequired("network")
	networkCreateCmd.Flags().StringVarP(&networkTemplateFile, "template", "t", "", "Specify the path to the template file for the network")
	networkCreateCmd.MarkFlagRequired("template")
	networkCreateCmd.Flags().BoolVarP(&noImportKeys, "noimportkeys", "K", false, "Do not import root keys when creating the network (by default will import)")
	networkCreateCmd.Flags().BoolVar(&noClean, "noclean", false, "Prevents auto-cleanup on error - for diagnosing problems")

	return networkCreateCmd
}

func networkStartCmd() *cobra.Command {
	var networkStartCmd = &cobra.Command{
		Use:   "start",
		Short: "Start a deployed private network",
		Long:  `Start a deployed private network`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Start network
			Start(networkRootDir, startNode)
		},
	}

	return networkStartCmd
}

func networkRestartCmd() *cobra.Command {
	networkRestartCmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart a deployed private network",
		Long:  `Restart a deployed private network`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Restart
			Restart(networkRootDir)
		},
	}

	return networkRestartCmd
}

func networkStopCmd() *cobra.Command {
	networkStopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop a deployed private network",
		Long:  `Stop a deployed private network`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Stop
			Stop(networkRootDir)
		},
	}

	return networkStopCmd
}

func networkStatusCmd() *cobra.Command {
	networkStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Prints status for all nodes in a deployed private network",
		Long:  `Prints status for all nodes in a deployed private network`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Status
			Status(networkRootDir)
		},
	}

	return networkStatusCmd
}

func networkDeleteCmd() *cobra.Command {
	networkDeleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Stops and Deletes a deployed private network",
		Long:  `Stops and Deletes a deployed private network. NOTE: This does not prompt first - so be careful before you do this!`,
		Run: func(cmd *cobra.Command, _ []string) {
			// Delete
			Delete(networkRootDir)
		},
	}

	return networkDeleteCmd
}


func Create(networkName, networkRootDir, networkTemplateFile string, noImportKeys, noClean bool) {
	networkRootDir, err := filepath.Abs(networkRootDir)
	if err != nil {
		panic(err)
	}
	networkTemplateFile, err = filepath.Abs(networkTemplateFile)
	if err != nil {
		panic(err)
	}
	// Make sure target directory doesn't already exist
	exists := util.FileExists(networkRootDir)
	if exists {
		reportError(infoNetworkAlreadyExists, networkRootDir)
	}

	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}

	network, err := CreateNetworkFromTemplate(networkName, networkRootDir, networkTemplateFile, binDir, !noImportKeys)
	if err != nil {
		if noClean {
			reportInfo(" ** failed ** - Preserving network rootdir '%s'", networkRootDir)
		} else {
			os.RemoveAll(networkRootDir) // Don't leave partial network directory if create failed
		}
		reportError(errorCreateNetwork, err)
	}

	reportInfo(infoNetworkCreated, network.Name(), networkRootDir)
}

func Start(networkRootDir, startNode string) {
	network, binDir := getNetworkAndBinDir(networkRootDir)
	if startNode == "" {
		err := network.Start(binDir, false)
		if err != nil {
			reportError(errorStartingNetwork, err)
		}
		reportInfo(infoNetworkStarted, networkRootDir)
	} else {
		err := network.StartNode(binDir, startNode, false)
		if err != nil {
			reportError(errorNodeFailedToStart, err)
		}
		reportInfo(infoNodeStart)
	}
}

func Restart(networkRootDir string) {
	network, binDir := getNetworkAndBinDir(networkRootDir)
	network.Stop(binDir)
	err := network.Start(binDir, false)
	if err != nil {
		reportError(errorStartingNetwork, err)
	}
	reportInfo(infoNetworkStarted, networkRootDir)
}

func Stop(networkRootDir string) {
	network, binDir := getNetworkAndBinDir(networkRootDir)
	network.Stop(binDir)
	reportInfo(infoNetworkStopped, networkRootDir)
}

func Status(networkRootDir string) {
	network, binDir := getNetworkAndBinDir(networkRootDir)

	statuses := network.NodesStatus(binDir)
	for dir, status := range statuses {
		if status.Error != nil {
			reportError("\n[%s]\n ** Error getting status: %v **\n", dir, status.Error)
		} else {
			//reportInfo("\n[%s]\n%s", dir, makeStatusString(status.Status))
		}
	}
	fmt.Println()
}

func Delete(networkRootDir string) {
	network, binDir := getNetworkAndBinDir(networkRootDir)

	err := network.Delete(binDir)
	if err != nil {
		reportError("Error stopping or deleting network: %v\n", err)
	}
	reportInfo(infoNetworkDeleted, networkRootDir)
}


func getNetworkAndBinDir(networkRootDir string) (Network, string) {
	networkRootDir, err := filepath.Abs(networkRootDir)
	if err != nil {
		panic(err)
	}
	network, err := LoadNetwork(networkRootDir)
	if err != nil {
		reportError(errorLoadingNetwork, err)
	}
	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}
	return network, binDir
}


func reportInfo(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	// log.Infof(format, args...)
}


func reportError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	// log.Warnf(format, args...)
	os.Exit(1)
}