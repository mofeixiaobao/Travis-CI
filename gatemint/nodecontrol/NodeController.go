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

package nodecontrol

import (
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// NodeController provides an object for controlling a specific algod node instance
type NodeController struct {
	algod              string
	algoh              string
	algodDataDir       string
	algodPidFile       string
	algodNetFile       string
	algodNetListenFile string

	KMDController
}

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

// AlgodStartArgs are the possible arguments for starting algod
type AlgodStartArgs struct {
	PeerAddress       string
	ListenIP          string
	RedirectOutput    bool
	RunUnderHost      bool
	TelemetryOverride string
}

// KMDStartArgs are the possible arguments for starting kmd
type KMDStartArgs struct {
	TimeoutSecs uint64
}

// NodeStartArgs represents the possible arguments for starting the node processes
type NodeStartArgs struct {
	AlgodStartArgs
	KMDStartArgs
}

// FullStart will start the kmd and algod, reporting of either process is already running
func (nc *NodeController) FullStart(args NodeStartArgs) (algodAlreadyRunning, kmdAlreadyRunning bool, err error) {
	// Start algod
	algodAlreadyRunning, err = nc.StartAlgod(args.AlgodStartArgs)
	if err != nil {
		return
	}

	// Start kmd
	kmdAlreadyRunning, err = nc.StartKMD(args.KMDStartArgs)
	if err != nil {
		return
	}

	return
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
