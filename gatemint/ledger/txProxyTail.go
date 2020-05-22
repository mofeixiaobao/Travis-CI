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
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/logging"
)

type roundTxProto struct {
	protoVersion protocol.ConsensusVersion
}

type txProxyTail struct {
	recent map[basics.Round]roundTxProto

	lastValid map[basics.Round]map[transactions.Txid]struct{} // map tx.LastValid -> tx confirmed set

	// duplicate detection queries with LastValid not before
	// lowWaterMark are not guaranteed to succeed
	lowWaterMark basics.Round // the last round known to be committed to disk
}

func (t *txProxyTail) loadFromDisk(l ledgerForTracker) error {
	return nil
}

func (t *txProxyTail) loadFromDiskAfterIndexer(l ledgerForTracker) error {
	latest := l.Latest()
	hdr, err := l.BlockHdr(latest)
	if err != nil {
		return fmt.Errorf("txTail: could not get latest block header: %v", err)
	}
	proto := config.Consensus[hdr.CurrentProtocol]

	// If the latest round is R, then any transactions from blocks strictly older than
	// R + 1 - proto.MaxTxnLife
	// could not be valid in the next round (R+1), and so are irrelevant.
	// Thus we load the txids from blocks R+1-maxTxnLife to R, inclusive
	old := (latest + 1).SubSaturate(basics.Round(proto.MaxTxnLife))

	t.lowWaterMark = latest
	t.lastValid = make(map[basics.Round]map[transactions.Txid]struct{})
	t.recent = make(map[basics.Round]roundTxProto)

	for ; old <= latest; old++ {
		blk, err := l.Block(old)
		if err != nil {
			return err
		}
		t.recent[old] = roundTxProto{
			protoVersion: hdr.CurrentProtocol,
		}
		for _, txad := range blk.PayProxySet {

			txIndexInfo, err := l.GetTxValidInfo(txad.Tx)
			if err != nil {
				logging.Base().Warnf("get tx validInfo error : %v", err)
				return fmt.Errorf("get tx validInfo error : %v", err)
			}
			// TODO
			// here need to update first valid and last valid round
			lastValidHeight := txIndexInfo.LastValidRound
			txId := txad.Tx.ComputeID()
			t.putLV(lastValidHeight, txId)
		}
	}
	return nil
}

func (t *txProxyTail) close() {
}

func (t *txProxyTail) newBlock(blk bookkeeping.Block, delta StateDelta) {
	rnd := blk.Round()

	t.recent[rnd] = roundTxProto{
		protoVersion: blk.CurrentProtocol,
	}
	for txid, lv := range delta.Txids {
		t.putLV(lv, txid)
	}
}

func (t *txProxyTail) committedUpTo(rnd basics.Round) basics.Round {

	maxlife := basics.Round(config.Consensus[t.recent[rnd].protoVersion].MaxTxnLife)
	for r := range t.recent {
		if r+maxlife < rnd {
			delete(t.recent, r)
		}
	}
	for ; t.lowWaterMark < rnd; t.lowWaterMark++ {
		delete(t.lastValid, t.lowWaterMark)
	}

	return (rnd + 1).SubSaturate(maxlife)
}

// Deprecated
func (t *txProxyTail) isDup(proto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	if lastValid < t.lowWaterMark {
		return true, fmt.Errorf("txTail: tried to check for dup in missing round %d", lastValid)
	}
	_, confirmed := t.lastValid[lastValid][txid]
	return confirmed, nil
}

func (t *txProxyTail) checkDup(lastValid basics.Round, txid transactions.Txid) (bool, error) {
	if lastValid < t.lowWaterMark {
		return true, fmt.Errorf("txTail: tried to check for dup in missing round %d", lastValid)
	}
	_, confirmed := t.lastValid[lastValid][txid]
	return confirmed, nil
}

func (t *txProxyTail) getRoundTxIds(rnd basics.Round) (txMap map[transactions.Txid]bool) {
	rndtxs := t.lastValid[rnd]
	txMap = make(map[transactions.Txid]bool, len(rndtxs))
	for txId, _ := range rndtxs {
		txMap[txId] = true
	}
	return
}

func (t *txProxyTail) putLV(lastValid basics.Round, id transactions.Txid) {
	if _, ok := t.lastValid[lastValid]; !ok {
		t.lastValid[lastValid] = make(map[transactions.Txid]struct{})
	}
	t.lastValid[lastValid][id] = struct{}{}
}
