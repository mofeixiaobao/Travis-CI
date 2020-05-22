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

package libgoal

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/account"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/gatemint/util/db"
)

func participationKeysPath(dataDir string, address basics.Address, firstValid, lastValid basics.Round) (string, error) {
	// Build /<dataDir>/<genesisID>/<address>.<first_round>.<last_round>.partkey
	first := uint64(firstValid)
	last := uint64(lastValid)
	fileName := config.PartKeyFilename(address.String(), first, last)
	return filepath.Join(dataDir, fileName), nil
}

// GenParticipationKeys creates a .partkey database for a given address, fills
// it with keys, and installs it in the right place
func (c *Client) GenParticipationKeys(address string, firstValid, lastValid, keyDilution uint64) (part account.Participation, filePath string, err error) {
	return c.GenParticipationKeysTo(address, firstValid, lastValid, keyDilution, "")
}

// GenParticipationKeysTo creates a .partkey database for a given address, fills
// it with keys, and saves it in the specified output directory.
func (c *Client) GenParticipationKeysTo(address string, firstValid, lastValid, keyDilution uint64, outDir string) (part account.Participation, filePath string, err error) {
	// Parse the address
	parsedAddr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return
	}

	firstRound, lastRound := basics.Round(firstValid), basics.Round(lastValid)

	// Get the current protocol for ephemeral key parameters
	stat, err := c.Status()
	if err != nil {
		return
	}

	proto, ok := config.Consensus[protocol.ConsensusVersion(stat.LastVersion)]
	if !ok {
		err = fmt.Errorf("consensus protocol %s not supported", stat.LastVersion)
		return
	}

	// If output directory wasn't specified, store it in the current ledger directory.
	if outDir == "" {
		// Get the GenesisID for use in the participation key path
		var genID string
		genID, err = c.GenesisID()
		if err != nil {
			return
		}

		outDir = filepath.Join(c.DataDir(), genID)
	}
	// Connect to the database
	partKeyPath, err := participationKeysPath(outDir, parsedAddr, firstRound, lastRound)
	if err != nil {
		return
	}
	partdb, err := db.MakeErasableAccessor(partKeyPath)
	if err != nil {
		return
	}

	if keyDilution == 0 {
		keyDilution = proto.DefaultKeyDilution
	}

	// Fill the database with new participation keys
	newPart, err := account.FillDBWithParticipationKeys(partdb, parsedAddr, firstRound, lastRound, keyDilution)
	return newPart, partKeyPath, err
}

// ListParticipationKeys returns the available participation keys,
// as a map from database filename to Participation key object.
func (c *Client) ListParticipationKeys() (partKeyFiles map[string]account.Participation, err error) {
	genID, err := c.GenesisID()
	if err != nil {
		return
	}

	// Get a list of files in the participation keys directory
	keyDir := filepath.Join(c.DataDir(), genID)
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return
	}

	partKeyFiles = make(map[string]account.Participation)
	for _, file := range files {
		// If it can't be a participation key database, skip it
		if !config.IsPartKeyFilename(file.Name()) {
			continue
		}

		filename := file.Name()

		// Fetch a handle to this database
		handle, err := db.MakeErasableAccessor(filepath.Join(keyDir, filename))
		if err != nil {
			// Couldn't open it, skip it
			continue
		}

		// Fetch an account.Participation from the database
		part, err := account.RestoreParticipation(handle)
		handle.Close()
		if err != nil {
			// Couldn't read it, skip it
			continue
		}

		partKeyFiles[filename] = part
	}

	return
}
