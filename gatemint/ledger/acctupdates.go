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

package ledger

import (
	"fmt"
	"time"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/logging"
)

// A modifiedAccount represents an account that has been modified since
// the persistent state stored in the account DB (i.e., in the range of
// rounds covered by the accountUpdates tracker).
type modifiedAccount struct {
	// data stores the most recent AccountData for this modified
	// account.
	data basics.AccountData

	// ndelta keeps track of how many times this account appears in
	// accountUpdates.deltas.  This is used to evict modifiedAccount
	// entries when all changes to an account have been reflected in
	// the account DB, and no outstanding modifications remain.
	ndeltas int
}

type modifiedAsset struct {
	// Created if true, deleted if false
	created bool

	// Creator is the creator of the asset
	creator basics.Address

	// Keeps track of how many times this asset appears in
	// accountUpdates.assetDeltas
	ndeltas int
}

type accountUpdates struct {
	// Connection to the database.
	dbs dbPair

	accountstore *AccountStore

	// dbRound is always exactly accountsRound(),
	// cached to avoid SQL queries.
	dbRound basics.Round

	// deltas stores updates for every round after dbRound.
	deltas []map[basics.Address]accountDelta

	// accounts stores the most recent account state for every
	// address that appears in deltas.
	accounts map[basics.Address]modifiedAccount

	// assetDeltas stores asset updates for every round after dbRound.
	assetDeltas []map[basics.AssetIndex]modifiedAsset

	// assets stores the most recent asset state for every asset
	// that appears in assetDeltas
	assets map[basics.AssetIndex]modifiedAsset

	// totals stores the totals for dbRound and every round after it;
	// i.e., totals is one longer than deltas.
	roundTotals []AccountTotals

	// initAccounts specifies initial account values for database.
	initAccounts map[basics.Address]basics.AccountData

	// initProto specifies the initial consensus parameters.
	initProto config.ConsensusParams

	// log copied from ledger
	log logging.Logger

	// lastFlushTime is the time we last flushed updates to
	// the accounts DB (bumping dbRound).
	lastFlushTime time.Time
}

func (au *accountUpdates) loadFromDisk(l ledgerForTracker) error {
	au.dbs = l.trackerDB()
	au.log = l.trackerLog()

	if au.initAccounts == nil {
		return fmt.Errorf("accountUpdates.loadFromDisk: initAccounts not set")
	}

	latest := l.Latest()

	//if au.accountstore.Round() < 1 {
	//	err := au.accountstore.Init(au.initAccounts)
	//	if err != nil {
	//		return err
	//	}
	//}
	totals, err := au.accountstore.LoadAccountTotals()
	if err != nil {
		return err
	}
	au.roundTotals = []AccountTotals{totals}
	au.dbRound = au.accountstore.Round()
	au.deltas = nil
	au.assetDeltas = nil
	au.accounts = make(map[basics.Address]modifiedAccount)
	loaded := au.dbRound
	for loaded < latest {
		err = fmt.Errorf("cannot load account store")
		return err
		//next := loaded + 1
		//
		//blk, aux, err := l.blockAux(next)
		//if err != nil {
		//	return err
		//}
		//
		//delta, err := l.trackerEvalVerified(blk, aux)
		//if err != nil {
		//	return err
		//}
		//
		//au.newBlock(blk, delta)
		//loaded = next
	}

	if err != nil {
		return err
	}

	return nil
}

func (au *accountUpdates) close() {
}

func (au *accountUpdates) lookup(addr []byte) (data basics.AccountData, err error) {
	return au.accountstore.lookup(addr)
}

func (au *accountUpdates) committedUpTo(rnd basics.Round) basics.Round {
	err := au.accountstore.NewRound(rnd, au.accounts, au.roundTotals[0])
	au.dbRound = rnd
	if err != nil {
		au.log.Panicf("committedUpTo: block %d err %s", rnd, err.Error())
	}
	au.accounts = make(map[basics.Address]modifiedAccount)
	return au.dbRound
}

func (au *accountUpdates) newBlock(blk bookkeeping.Block, delta StateDelta) {
	rnd := blk.Round()

	//if rnd <= au.latest() {
	//	// Duplicate, ignore.
	//	return
	//}

	if rnd != au.latest()+1 {
		au.log.Panicf("accountUpdates: newBlock %d too far in the future, dbRound %d", rnd, au.dbRound)
	}
	newTotals := &au.roundTotals[0]
	var ot basics.OverflowTracker
	for addr, data := range delta.accts {
		macct := au.accounts[addr]
		macct.data = data.new
		au.accounts[addr] = macct

		newTotals.delAccount(data.old, &ot)
		newTotals.addAccount(data.new, &ot)
	}
	//au.deltas = append(au.deltas, delta.accts)
}

func (au *accountUpdates) latest() basics.Round {
	return au.dbRound
}

func (au *accountUpdates) totals(rnd basics.Round) (totals AccountTotals, err error) {
	totals, err = au.accountstore.LoadAccountTotals()
	return
}

func (au *accountUpdates) updateTotals(account basics.AccountData) {
	newTotals := &au.roundTotals[0]
	var ot basics.OverflowTracker
	newTotals.delAccount(account, &ot)
}

func (au *accountUpdates) iterator() string {
	iter := au.accountstore.db.Iterator(nil, nil)
	var result = ""
	var totalPower = uint64(0)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var account basics.AccountData
		account, err := au.lookup(iter.Key())
		if err == nil {
			if len(iter.Key()) >= 32 {
				address := basics.ConverAddress(iter.Key())
				str := address.String()
				result += fmt.Sprintf("Account : %s, %d ", str, account.Power)
				totalPower += account.Power.Raw
			}

		}
	}
	result += fmt.Sprintf("countPower : %d", totalPower)
	return result

}
