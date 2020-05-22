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

package bookkeeping

import (
	"encoding/json"
	"github.com/gatechain/crypto"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/protocol"
)

// A Genesis object defines an Algorand "universe" -- a set of nodes that can
// talk to each other, agree on the ledger contents, etc.  This is defined
// by the initial account states (GenesisAllocation), the initial
// consensus protocol (GenesisProto), and the schema of the ledger.
type Genesis struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// The SchemaID allows nodes to store data specific to a particular
	// universe (in case of upgrades at development or testing time),
	// and as an optimization to quickly check if two nodes are in
	// the same universe.
	ChainID string `codec:"chain_id"`

	// Network identifies the unique algorand network for which the ledger
	// is valid.
	// Note the Network name should not include a '-', as we generate the
	// GenesisID from "<Network>-<SchemaID>"; the '-' makes it easy
	// to distinguish between the network and schema.
	Network protocol.NetworkID `codec:"network"`

	// Proto is the consensus protocol in use at the genesis block.
	Proto protocol.ConsensusVersion `codec:"proto"`

	// Allocation determines the initial accounts and their state.
	Allocation []GenesisAllocation `codec:"alloc"`

	// RewardsPool is the address of the rewards pool.
	RewardsPool string `codec:"rwd"`

	// FeeSink is the address of the fee sink.
	FeeSink string `codec:"fees"`

	// Timestamp for the genesis block
	Timestamp int64 `codec:"timestamp"`

	// Arbitrary genesis comment string - will be excluded from file if empty
	Comment string `codec:"comment"`

	ProxyAppContent json.RawMessage `codec:"app_state,omitempty"`
}


// Genesis.json SchemaID
var SchemaID = "v1"

var DefaultSinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var DefaultPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// LoadGenesisFromFile attempts to load a Genesis structure from a (presumably) genesis.json file.
func LoadGenesisFromFile(genesisFile string) (genesis Genesis, err error) {
	// Load genesis.json
	genesisText, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		return
	}

	err = protocol.DecodeJSON(genesisText, &genesis)
	return
}

// LoadGenesisFromFile attempts to load a Genesis structure from a (presumably) genesis.json file.
func LoadGenesisDataFromFile(genesisFile string) (genesis *Genesis, err error) {
	// Load genesis.json
	genesisText, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		return
	}

	err = protocol.DecodeJSON(genesisText, &genesis)
	return
}

func WriteGenesisDataToFile(genesisData *Genesis, outDir string) error {
	// Backwards compatibility with older genesis files: if the consensus
	// protocol version is not specified, default to V1.
	proto := genesisData.Proto
	if proto == protocol.ConsensusVersion("") {
		proto = protocol.ConsensusCurrentVersion
	}

	genesisData.Proto = proto

	// Check if the directory exists
	dir := filepath.Dir(outDir)
	if err := os.MkdirAll(dir, 0766); err != nil {
		return err
	}

	jsonData := protocol.EncodeJSON(genesisData)
	err := ioutil.WriteFile(outDir, append(jsonData, '\n'), 0666)
	return err
}

// ID is the effective Genesis identifier - the combination
// of the network and the ledger schema version
func (genesis Genesis) ID() string {
	return genesis.ChainID
	//return string(genesis.Network) + "-" + genesis.SchemaID
}

// A GenesisAllocation object represents an allocation of algos to
// an address in the genesis block.  Address is the checksummed
// short address.  Comment is a note about what this address is
// representing, and is purely informational.  State is the initial
// account state.
type GenesisAllocation struct {
	Address string             `codec:"addr"`
	Comment string             `codec:"comment"`
	State   basics.AccountData `codec:"state"`
}

// ToBeHashed impements the crypto.Hashable interface.
func (genesis Genesis) ToBeHashed() (crypto.HashID, []byte) {
	return protocol.Genesis, protocol.Encode(genesis)
}
