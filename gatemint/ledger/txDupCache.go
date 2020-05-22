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
	"github.com/gatechain/gatemint/data/transactions"
	"sync"

	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
)

type txDupCache struct {
	rwmu       *sync.RWMutex
	txids      map[basics.Round]map[transactions.Txid]bool
	startRound basics.Round
	endRound   basics.Round
}

func txDupCacheInit() *txDupCache {
	tdc := &txDupCache{}
	tdc.rwmu = new(sync.RWMutex)
	tdc.txids = make(map[basics.Round]map[transactions.Txid]bool)
	tdc.startRound = 0
	tdc.endRound = 0
	return tdc
}

func (tdc *txDupCache) close() {
	tdc.rwmu.Lock()
	defer tdc.rwmu.Unlock()
	tdc.txids = make(map[basics.Round]map[transactions.Txid]bool)
}

// isNeedRefresh
func (tdc *txDupCache) isNeedRefreshCache(indexRound basics.Round, ledgerRound basics.Round) (bool, bool, basics.Round) {
	tdc.rwmu.RLock()
	defer tdc.rwmu.RUnlock()

	isNeedDelete := false
	isNeedInsert := false
	insertStartRound := basics.Round(0)

	if indexRound > tdc.startRound-1 {
		isNeedDelete = true
	}

	if ledgerRound > tdc.endRound {
		isNeedInsert = true
		insertStartRound = tdc.endRound + basics.Round(1)
	}

	return isNeedDelete, isNeedInsert, insertStartRound
}

func (tdc *txDupCache) addBlock(round basics.Round, blk bookkeeping.Block) error {
	tdc.rwmu.Lock()
	defer tdc.rwmu.Unlock()

	if tdc.endRound != 0 && round != tdc.endRound+1 {
		return fmt.Errorf("txDupCache add blk round error, need round %v, recived round is %v", tdc.endRound+1, round)
	}
	txMap := make(map[transactions.Txid]bool)
	for _, tx := range blk.PayProxySet {
		txMap[tx.Tx.ComputeID()] = true
	}
	tdc.txids[round] = txMap
	tdc.endRound = round
	if tdc.startRound == 0 {
		tdc.startRound = round
	}
	return nil
}

func (tdc *txDupCache) deleteBlock(indexRound basics.Round) error {
	tdc.rwmu.Lock()
	defer tdc.rwmu.Unlock()

	if indexRound < tdc.startRound-1 {
		return fmt.Errorf("txDupCache delete cache round is error ,need round %v, recived is %v", tdc.startRound, indexRound)
	}

	for i := tdc.startRound; i <= indexRound; i++ {
		delete(tdc.txids, i)
	}
	return nil
}

func (tdc *txDupCache) isTxCached(queryTx transactions.Tx) (bool, basics.Round) {
	tdc.rwmu.RLock()
	defer tdc.rwmu.RUnlock()

	queryTxId := queryTx.ComputeID()
	for round, blockTx := range tdc.txids {
		_, ok := blockTx[queryTxId]
		if ok {
			return true, round
		}
	}
	return false, 0
}
