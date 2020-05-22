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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/libgoal"
	"github.com/gatechain/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var log = logging.Base()

var dataDirs []string

var defaultCacheDir = "gm.cache"

var versionCheck bool

func init() {
	rootCmd.Flags().BoolVarP(&versionCheck, "version", "v", false, "Display and write current build version and exit")

	// node.go
	rootCmd.AddCommand(nodeCmd)

	// network.go
	rootCmd.AddCommand(networkCmd)

	// Config
	defaultDataDirValue := []string{""}
	rootCmd.PersistentFlags().StringArrayVarP(&dataDirs, "datadir", "d", defaultDataDirValue, "Data directory for the node")
}

var rootCmd = &cobra.Command{
	Use:   "gm",
	Short: "CLI for interacting with Gatemint.",
	Long:  `GM is the CLI for interacting Gatemint software instance.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if versionCheck {
			fmt.Println(config.FormatVersionAndLicense())
			return
		}
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

// Write commands to exercise all subcommands with `-h`
// Can be used to check that there are no conflicts in arguments between inner and outer commands.
func runAllHelps(c *cobra.Command, out io.Writer) (err error) {
	if c.Runnable() {
		cmd := c.CommandPath() + " -h\n"
		_, err = out.Write([]byte(cmd))
		if err != nil {
			return
		}
	}
	for _, sub := range c.Commands() {
		err = runAllHelps(sub, out)
		if err != nil {
			return
		}
	}
	return
}

func main() {
	// Hidden command to generate docs in a given directory
	// gm generate-docs [path]
	if len(os.Args) == 3 && os.Args[1] == "generate-docs" {
		err := doc.GenMarkdownTree(rootCmd, os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	} else if len(os.Args) == 2 && os.Args[1] == "helptest" {
		// test that subcommands don't have arg conflicts:
		// gm helptest | bash -x -e
		runAllHelps(rootCmd, os.Stdout)
		os.Exit(0)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func resolveDataDir() string {
	// Figure out what data directory to tell gmd to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if len(dataDirs) > 0 {
		dir = dataDirs[0]
	}
	if dir == "" {
		dir = os.Getenv("GATEMINT_DATA")
	}
	return dir
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

func getDataDirs() (dirs []string) {
	if len(dataDirs) == 0 {
		reportErrorln(errorNoDataDirectory)
	}
	dirs = append(dirs, ensureFirstDataDir())
	dirs = append(dirs, dataDirs[1:]...)
	return
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

func ensureCacheDir(dataDir string) string {
	var err error
	if libgoal.AlgorandDataIsPrivate(dataDir) {
		cacheDir := filepath.Join(dataDir, defaultCacheDir)
		err = os.Mkdir(cacheDir, 0700)
		if err != nil && !os.IsExist(err) {
			reportErrorf("could not make cachedir: %s", err)
		}
		return cacheDir
	}
	// Put the cache in the user's home directory
	gatemintDir, err := config.GetDefaultConfigFilePath()
	if err != nil {
		reportErrorf("config error %s", err)
	}
	dataDirEscaped := strings.ReplaceAll(dataDir, "/", "_")
	cacheDir := filepath.Join(gatemintDir, dataDirEscaped)
	err = os.MkdirAll(cacheDir, 0700)
	if err != nil {
		reportErrorf("could not make cachedir: %s", err)
	}
	return cacheDir
}

func ensureGmdClient(dataDir string) libgoal.Client {
	return ensureGmClient(dataDir, libgoal.AlgodClient)
}

func ensureGmClient(dataDir string, clientType libgoal.ClientType) libgoal.Client {
	clientConfig := libgoal.ClientConfig{
		AlgodDataDir: dataDir,
		CacheDir:     ensureCacheDir(dataDir),
	}
	client, err := libgoal.MakeClientFromConfig(clientConfig, clientType)
	if err != nil {
		reportErrorf(errorNodeStatus, err)
	}
	return client
}

func reportInfoln(args ...interface{}) {
	fmt.Println(args...)
	// log.Infoln(args...)
}

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	// log.Infof(format, args...)
}

func reportErrorln(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	// log.Warnln(args...)
	os.Exit(1)
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	// log.Warnf(format, args...)
	os.Exit(1)
}
