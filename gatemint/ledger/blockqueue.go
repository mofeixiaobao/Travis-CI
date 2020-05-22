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
	"github.com/gatechain/gatemint/protocol"
	"sync"

	"github.com/gatechain/go-deadlock"

	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/logging"
)

type blockEntry struct {
	block bookkeeping.Block
	cert  agreement.Certificate
	aux   evalAux
}

type blockQueue struct {
	l *Ledger

	lastCommitted basics.Round
	q             []blockEntry

	lastRoundForRead basics.Round
	rwmu             *sync.RWMutex

	mu      deadlock.Mutex
	cond    *sync.Cond
	running bool
}

func bqInit(l *Ledger) (*blockQueue, error) {
	bq := &blockQueue{}
	bq.rwmu = new(sync.RWMutex)
	bq.cond = sync.NewCond(&bq.mu)
	bq.l = l
	bq.running = true

	bq.lastCommitted = bq.l.blockStore.Round()
	bq.updateLastRoundForRead(bq.lastCommitted)
	//err := bq.l.blockDBs.rdb.Atomic(func(tx *sql.Tx) error {
	//	var err0 error
	//	bq.lastCommitted, err0 = blockLatest(tx)
	//	return err0
	//})
	//if err != nil {
	//	return nil, err
	//}

	go bq.syncer()
	return bq, nil
}

func (bq *blockQueue) close() {
	bq.mu.Lock()
	defer bq.mu.Unlock()
	if bq.running {
		bq.running = false
		bq.cond.Broadcast()
	}
}

func (bq *blockQueue) syncer() {
	bq.mu.Lock()
	for {
		for bq.running && len(bq.q) == 0 {
			bq.cond.Wait()
		}

		if !bq.running {
			bq.mu.Unlock()
			return
		}

		workQ := bq.q
		bq.mu.Unlock()

		for _, e := range workQ {
			bq.l.blockStore.BlockPut(e.block, e.cert, e.aux)
		}

		//err := bq.l.blockDBs.wdb.Atomic(func(tx *sql.Tx) error {
		//	for _, e := range workQ {
		//		err0 := blockPut(tx, e.block, e.cert, e.aux)
		//		if err0 != nil {
		//			return err0
		//		}
		//	}
		//	return nil
		//})

		bq.mu.Lock()

		//if err != nil {
		//	bq.l.log.Warnf("blockQueue.syncer: could not flush: %v", err)
		//}
		//else {
		bq.lastCommitted += basics.Round(len(workQ))
		bq.q = bq.q[len(workQ):]
		bq.updateLastRoundForRead(bq.lastCommitted + basics.Round(len(bq.q)))

		// Sanity-check: if we wrote any blocks, then the last
		// one must be from round bq.lastCommitted.
		if len(workQ) > 0 {
			lastWritten := workQ[len(workQ)-1].block.Round()
			if lastWritten != bq.lastCommitted {
				bq.l.log.Panicf("blockQueue.syncer: lastCommitted %v lastWritten %v workQ %v",
					bq.lastCommitted, lastWritten, workQ)
			}
		}

		committed := bq.lastCommitted
		bq.cond.Broadcast()
		bq.mu.Unlock()

		bq.l.notifyCommit(committed)
		//TODO THE FOLLOW
		//err = bq.l.blockDBs.wdb.Atomic(func(tx *sql.Tx) error {
		//	return blockForgetBefore(tx, minToSave)
		//})
		//if err != nil {
		//	bq.l.log.Warnf("blockQueue.syncer: blockForgetBefore(%d): %v", minToSave, err)
		//}

		bq.mu.Lock()
	}
}

func (bq *blockQueue) waitCommit(r basics.Round) {
	bq.mu.Lock()
	defer bq.mu.Unlock()

	for bq.lastCommitted < r {
		bq.cond.Wait()
	}
}

func (bq *blockQueue) latest() basics.Round {
	bq.mu.Lock()
	defer bq.mu.Unlock()
	return bq.lastCommitted + basics.Round(len(bq.q))
}

func (bq *blockQueue) latestCommitted() basics.Round {
	bq.mu.Lock()
	defer bq.mu.Unlock()
	return bq.lastCommitted
}

func (bq *blockQueue) putBlock(blk bookkeeping.Block, cert agreement.Certificate, aux evalAux) error {
	bq.mu.Lock()
	defer bq.mu.Unlock()

	nextRound := bq.lastCommitted + basics.Round(len(bq.q)) + 1

	// As an optimization to reduce warnings in logs, return a special
	// error when we're trying to store an old block.
	if blk.Round() < nextRound {
		bq.mu.Unlock()
		// lock is unnecessary here for sanity check
		myblk, mycert, err := bq.getBlockCert(blk.Round())
		if err == nil && myblk.Hash() != blk.Hash() {
			logging.Base().Errorf("bqPutBlock: tried to write fork: our (block,cert) is (%#v, %#v); other (block,cert) is (%#v, %#v)", myblk, mycert, blk, cert)
		}
		bq.mu.Lock()

		return BlockInLedgerError{blk.Round(), nextRound}
	}

	if blk.Round() != nextRound {
		return fmt.Errorf("bqPutBlock: got block %d, but expected %d", blk.Round(), nextRound)
	}

	bq.q = append(bq.q, blockEntry{
		block: blk,
		cert:  cert,
		aux:   aux,
	})

	bq.updateLastRoundForRead(bq.lastCommitted + basics.Round(len(bq.q)))
	bq.cond.Broadcast()
	return nil
}

func (bq *blockQueue) checkEntry(r basics.Round) (e *blockEntry, lastCommitted basics.Round, latest basics.Round, err error) {
	bq.mu.Lock()
	defer bq.mu.Unlock()

	// To help the caller form a more informative ErrNoEntry
	lastCommitted = bq.lastCommitted
	latest = bq.lastCommitted + basics.Round(len(bq.q))

	if r > bq.lastCommitted+basics.Round(len(bq.q)) {
		return nil, lastCommitted, latest, ErrNoEntry{
			Round:     r,
			Latest:    latest,
			Committed: lastCommitted,
		}
	}

	if r <= bq.lastCommitted {
		return nil, lastCommitted, latest, nil
	}

	return &bq.q[r-bq.lastCommitted-1], lastCommitted, latest, nil
}

func updateErrNoEntry(err error, lastCommitted basics.Round, latest basics.Round) error {
	if err != nil {
		switch errt := err.(type) {
		case ErrNoEntry:
			errt.Committed = lastCommitted
			errt.Latest = latest
			return errt
		}
	}

	return err
}

func (bq *blockQueue) getBlock(r basics.Round) (blk bookkeeping.Block, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		return e.block, nil
	}

	if err != nil {
		return
	}
	blk, err = bq.l.blockStore.LoadBlock(r)
	if err != nil {
		return
	}
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}

func (bq *blockQueue) getBlockHdr(r basics.Round) (hdr bookkeeping.BlockHeader, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		return e.block.BlockHeader, nil
	}

	if err != nil {
		return
	}
	block, err := bq.l.blockStore.LoadBlock(r)
	if err != nil {
		return
	}
	hdr = block.BlockHeader
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}

func (bq *blockQueue) getEncodedBlockCert(r basics.Round) (blkBytes []byte, certBytes []byte, err error) {
	blk, cert, err := bq.getBlockCert(r)
	blkBytes = protocol.Encode(blk)
	certBytes = protocol.Encode(cert)
	return
}

func (bq *blockQueue) getBlockCert(r basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		return e.block, e.cert, nil
	}

	if err != nil {
		return
	}

	blk, err = bq.l.blockStore.LoadBlock(r)
	if err != nil {
		return
	}

	certBytes := bq.l.blockStore.LoadBlockCertEncode(r)
	err = cdc.UnmarshalJSON(certBytes, &cert)
	if err != nil {
		return
	}
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}

func (bq *blockQueue) getBlockAux(r basics.Round) (blk bookkeeping.Block, aux evalAux, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		return e.block, e.aux, nil
	}

	if err != nil {
		return
	}
	blk, err = bq.l.blockStore.LoadBlock(r)
	if err != nil {
		return
	}
	auxBytes := bq.l.blockStore.LoadAuxEncode(r)
	err = cdc.UnmarshalJSON(auxBytes, &aux)
	if err != nil {
		return
	}
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}

func (bq *blockQueue) updateLastRoundForRead(round basics.Round) {
	bq.rwmu.Lock()
	defer bq.rwmu.Unlock()

	bq.lastRoundForRead = round
}

func (bq *blockQueue) readLastRoundForRead() basics.Round {
	bq.rwmu.RLock()
	defer bq.rwmu.RUnlock()

	return bq.lastRoundForRead
}
