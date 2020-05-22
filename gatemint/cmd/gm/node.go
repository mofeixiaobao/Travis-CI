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

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/daemon/gmd/api/spec/v1"
	"github.com/gatechain/gatemint/nodecontrol"
	"github.com/gatechain/gatemint/util"
)

var peerDial string
var listenIP string
var runUnderHost bool
var telemetryOverride string

func init() {
	nodeCmd.AddCommand(startCmd)
	nodeCmd.AddCommand(stopCmd)
	nodeCmd.AddCommand(statusCmd)

	startCmd.Flags().StringVarP(&peerDial, "peer", "p", "", "Peer address to dial for initial connection")
	startCmd.Flags().StringVarP(&listenIP, "listen", "l", "", "Endpoint / REST address to listen on")
	startCmd.Flags().BoolVarP(&runUnderHost, "hosted", "H", false, "Run gmd hosted by gmh")
	startCmd.Flags().StringVarP(&telemetryOverride, "telemetry", "t", "", `Enable telemetry if supported (Use "true", "false", "0" or "1")`)

}

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage a specified gatemint node",
	Long:  `Collection of commands to support the creation and management of Gatemint node instances, where each instance corresponds to a unique data directory.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		//Fall back
		cmd.HelpFunc()(cmd, args)
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Init the specified gatemint node",
	Long:  `Init the specified gatemint node`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}
		onDataDirs(func(dataDir string) {
			nc := nodecontrol.MakeNodeController(binDir, dataDir)
			nodeArgs := nodecontrol.AlgodStartArgs{
				PeerAddress:       peerDial,
				ListenIP:          listenIP,
				RedirectOutput:    false,
				RunUnderHost:      runUnderHost,
				TelemetryOverride: telemetryOverride,
			}

			if getRunHostedConfigFlag(dataDir) {
				nodeArgs.RunUnderHost = true
			}

			gmdAlreadyRunning, err := nc.StartAlgod(nodeArgs)
			if gmdAlreadyRunning {
				reportInfoln(infoNodeAlreadyStarted)
			}

			if err != nil {
				reportErrorf(errorNodeFailedToStart, err)
			} else {
				reportInfoln(infoNodeStart)
			}
		})
	},
}

func getRunHostedConfigFlag(dataDir string) bool {
	// See if this instance wants to run Hosted, even if '-H' wasn't specified on our cmdline
	cfg, err := config.LoadConfigFromDisk(dataDir)
	if err != nil && !os.IsNotExist(err) {
		reportErrorf(errLoadingConfig, dataDir, err)
	}
	return cfg.RunHosted
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop the specified gatemint node",
	Long:  `Stop the specified gatemint node`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}
		onDataDirs(func(dataDir string) {
			nc := nodecontrol.MakeNodeController(binDir, dataDir)

			log.Info(infoTryingToStopNode)

			err = nc.FullStop()
			if err != nil {
				reportErrorf(errorKill, err)
			}

			reportInfoln(infoNodeSuccessfullyStopped)
		})
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the current node status",
	Long:  `Show the current status of the running gatemint node`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		onDataDirs(getStatus)
	},
}

func getStatus(dataDir string) {
	client := ensureGmdClient(dataDir)
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

func makeStatusString(stat v1.NodeStatus) string {
	lastRoundTime := fmt.Sprintf("%.1fs", stat.TimeSinceLastRound)
	catchupTime := fmt.Sprintf("%.1fs", time.Duration(stat.CatchupTime).Seconds())
	return fmt.Sprintf(infoNodeStatus, stat.LastRound, lastRoundTime, catchupTime, stat.LastVersion, stat.NextVersion, stat.NextVersionRound, stat.NextVersionSupported, stat.HasSyncedSinceStartup)
}
