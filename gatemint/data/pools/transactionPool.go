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

package pools

import (
	"fmt"
	"github.com/gatechain/gatemint/node/appinterface"
	"sort"
	"sync"
	"time"

	"github.com/gatechain/go-deadlock"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/gatemint/ledger"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/gatemint/util/condvar"
	"github.com/gatechain/logging"
	"github.com/gatechain/logging/telemetryspec"
)

// TransactionPool is a struct maintaining a sanitized pool of transactions that are available for inclusion in
// a Block.  We sanitize it by preventing duplicates and limiting the number of transactions retained for each account
type TransactionPool struct {
	mu                     deadlock.Mutex
	cond                   sync.Cond
	expiredTxCount         map[basics.Round]int
	pendingBlockEvaluator  *ledger.BlockEvaluator
	numPendingWholeBlocks  basics.Round
	feeThresholdMultiplier uint64
	ledger                 *ledger.Ledger
	statusCache            *statusCache
	logStats               bool
	expFeeFactor           uint64
	txPoolMaxSize          int

	// pendingMu protects pendingTxGroups and pendingTxids
	pendingMu       deadlock.RWMutex
	pendingTxGroups [][]transactions.SignedTxn
	pendingTxids    map[transactions.Txid]transactions.SignedTxn

	// Calls to remember() add transactions to rememberedTxGroups and
	// rememberedTxids.  Calling rememberCommit() adds them to the
	// pendingTxGroups and pendingTxids.  This allows us to batch the
	// changes in OnNewBlock() without preventing a concurrent call
	// to Pending() or Verified().
	rememberedTxGroups [][]transactions.SignedTxn
	rememberedTxids    map[transactions.Txid]transactions.SignedTxn

	// pendingMu protects pendingTxGroups and pendingTxids
	pendingProxyMu        deadlock.RWMutex
	pendingProxyTxGroups  []transactions.TxWithValidInfo
	pendingProxyValidInfo map[transactions.Txid]transactions.TxWithValidInfo
	pendingProxyMaxHeap   txMaxHeap

	sortedType int

	rememberedProxyMaxHeap   txMaxHeap
	rememberedProxyTxGroups  []transactions.TxWithValidInfo
	rememberedProxyValidInfo map[transactions.Txid]transactions.TxWithValidInfo

	// result of logic.Eval()
	lsigCache *lsigEvalCache
	lcmu      deadlock.RWMutex

	notifiedTxsAvailable bool
	txsAvailable         chan struct{} // fires once for each height, when the txpool is not empty

	application appinterface.Application

	protoVertion protocol.ConsensusVersion

	minimumTxFee uint64
}

// Sort txs by fee
type MapStore []Item
type Item struct {
	Fee   uint64
	Data transactions.TxWithValidInfo
}

// MakeTransactionPool is the constructor, it uses Ledger to ensure that no account has pending transactions that together overspend.
//
// The pool also contains status information for the last transactionPoolStatusSize
// transactions that were removed from the pool without being committed.
func MakeTransactionPool(ledger *ledger.Ledger, cfg config.Local) *TransactionPool {
	if cfg.TxPoolExponentialIncreaseFactor < 1 {
		cfg.TxPoolExponentialIncreaseFactor = 1
	}
	pool := TransactionPool{
		pendingTxids:    make(map[transactions.Txid]transactions.SignedTxn),
		rememberedTxids: make(map[transactions.Txid]transactions.SignedTxn),
		expiredTxCount:  make(map[basics.Round]int),
		ledger:          ledger,
		statusCache:     makeStatusCache(cfg.TxPoolSize),
		logStats:        cfg.EnableAssembleStats,
		expFeeFactor:    cfg.TxPoolExponentialIncreaseFactor,
		lsigCache:       makeLsigEvalCache(cfg.TxPoolSize),
		txPoolMaxSize:   cfg.TxPoolSize,

		pendingProxyValidInfo:    make(map[transactions.Txid]transactions.TxWithValidInfo),
		rememberedProxyValidInfo: make(map[transactions.Txid]transactions.TxWithValidInfo),

		application: ledger.GetApplication(),
		sortedType:  cfg.TxSortedType,
		protoVertion: "",
		minimumTxFee: cfg.MinimumTxFee,
	}
	pool.cond.L = &pool.mu
	pool.recomputeBlockEvaluator(make(map[transactions.Txid]basics.Round))
	pool.EnableTxsAvailable()
	return &pool
}

// TODO I moved this number to be a constant in the module, we should consider putting it in the local config
const expiredHistory = 10

const expiredTxDefaultRound = 100

// timeoutOnNewBlock determines how long Test() and Remember() wait for
// OnNewBlock() to process a new block that appears to be in the ledger.
const timeoutOnNewBlock = time.Second

func (pool *TransactionPool) InitApplication(application appinterface.Application) error {
	pool.application = application
	return nil
}

func (pool *TransactionPool) GetApplication() appinterface.Application {
	return pool.application
}

// NumExpired returns the number of transactions that expired at the end of a round (only meaningful if cleanup has
// been called for that round)
func (pool *TransactionPool) NumExpired(round basics.Round) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.expiredTxCount[round]
}

// PendingTxIDs return the IDs of all pending transactions
func (pool *TransactionPool) PendingTxIDs() []transactions.Txid {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()

	ids := make([]transactions.Txid, len(pool.pendingTxids))
	i := 0
	for txid := range pool.pendingTxids {
		ids[i] = txid
		i++
	}
	return ids
}

// Pending returns a list of transaction groups that should be proposed
// in the next block, in order.
func (pool *TransactionPool) Pending() [][]transactions.SignedTxn {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()
	// note that this operation is safe for the sole reason that arrays in go are immutable.
	// if the underlaying array need to be expanded, the actual underlaying array would need
	// to be reallocated.
	return pool.pendingTxGroups

}

func (pool *TransactionPool) ProxyPendingTxIDs() []transactions.Txid {
	pool.pendingProxyMu.RLock()
	defer pool.pendingProxyMu.RUnlock()

	ids := make([]transactions.Txid, len(pool.pendingProxyValidInfo))
	i := 0
	for txid := range pool.pendingProxyValidInfo {
		ids[i] = txid
		i++
	}
	return ids
}

func (pool *TransactionPool) ProxyPending() []transactions.TxWithValidInfo {
	pool.pendingProxyMu.RLock()
	defer pool.pendingProxyMu.RUnlock()
	// note that this operation is safe for the sole reason that arrays in go are immutable.
	// if the underlaying array need to be expanded, the actual underlaying array would need
	// to be reallocated.
	// sortedType == 1 means sorted by fee
	if pool.sortedType == 1 {
		return pool.pendingProxyMaxHeap
	}
	return pool.pendingProxyTxGroups
}

// EnableTxsAvailable initializes the TxsAvailable channel,
// ensuring it will trigger once every height when transactions are available.
// NOTE: not thread safe - should only be called once, on startup
func (pool *TransactionPool) EnableTxsAvailable() {
	pool.txsAvailable = make(chan struct{}, 1)
}

// TxsAvailable returns a channel which fires once for every height,
// and only when transactions are available in the TransactionPool.
// NOTE: the returned channel may be nil if EnableTxsAvailable was not called.
func (pool *TransactionPool) TxsAvailabled() <-chan struct{} {
	return pool.txsAvailable
}

func (pool *TransactionPool) notifyTxsAvailable() {
	if !pool.notifiedTxsAvailable && len(pool.pendingProxyValidInfo) > 0 {
		// channel cap is 1, so this will send once
		pool.notifiedTxsAvailable = true
		select {
		case pool.txsAvailable <- struct{}{}:
		default:
		}
	}
}

// rememberCommit() saves the changes added by remember to
// pendingTxGroups and pendingTxids.  The caller is assumed to
// be holding pool.mu.  flush indicates whether previous
// pendingTxGroups and pendingTxids should be flushed out and
// replaced altogether by rememberedTxGroups and rememberedTxids.
func (pool *TransactionPool) rememberCommit(flush bool) {
	pool.pendingMu.Lock()
	defer pool.pendingMu.Unlock()

	if flush {
		pool.pendingTxGroups = pool.rememberedTxGroups
		pool.pendingTxids = pool.rememberedTxids
	} else {
		pool.pendingTxGroups = append(pool.pendingTxGroups, pool.rememberedTxGroups...)
		for txid, txn := range pool.rememberedTxids {
			pool.pendingTxids[txid] = txn
		}
	}

	pool.rememberedTxGroups = nil
	pool.rememberedTxids = make(map[transactions.Txid]transactions.SignedTxn)
}

// rememberCommit() saves the changes added by remember to
// pendingTxGroups and pendingTxids.  The caller is assumed to
// be holding pool.mu.  flush indicates whether previous
// pendingTxGroups and pendingTxids should be flushed out and
// replaced altogether by rememberedTxGroups and rememberedTxids.
func (pool *TransactionPool) rememberProxyCommit(flush bool) {
	pool.pendingProxyMu.Lock()
	defer pool.pendingProxyMu.Unlock()

	var pendingProxyTxGroups []transactions.TxWithValidInfo

	if flush {
		if pool.sortedType == 1 {
			pool.pendingProxyMaxHeap = pool.rememberedProxyMaxHeap
		} else {
			pendingProxyTxGroups = pool.rememberedProxyTxGroups
		}
		pool.pendingProxyValidInfo = pool.rememberedProxyValidInfo
	} else {
		if pool.sortedType == 1 {
			for _, txInfo := range pool.rememberedProxyMaxHeap {
				pool.pendingProxyMaxHeap.Push(txInfo)
			}
		} else {
			pendingProxyTxGroups = append(pool.pendingProxyTxGroups, pool.rememberedProxyTxGroups...)
		}

		for txId, txValidInfo := range pool.rememberedProxyValidInfo {
			pool.pendingProxyValidInfo[txId] = txValidInfo
		}
	}

	// Preferential packaging for high-cost txs
	minTxFee := pool.minimumTxFee
	totalTxFee := uint64(0)
	for _, v := range pendingProxyTxGroups {
		totalTxFee += v.Fee
	}

	// Reverse sort
	sort.Slice(pendingProxyTxGroups, func(i, j int) bool {
		return pendingProxyTxGroups[i].Fee > pendingProxyTxGroups[j].Fee
	})

	// Restore the state
	pool.pendingProxyTxGroups = nil

	// Meet the minimum transaction fee limit
	if totalTxFee >= minTxFee {
		//for _,v := range pendingProxyTxGroups {
		//	fmt.Println("txID:", v.TxInfo.ComputeID())
		//}
		pool.pendingProxyTxGroups = pendingProxyTxGroups
		// Clear the cache
		pool.rememberedProxyTxGroups = nil
	}

	pool.notifyTxsAvailable()
	//pool.rememberedProxyTxGroups = nil
	pool.rememberedProxyMaxHeap = initMaxHeap()
	pool.rememberedProxyValidInfo = make(map[transactions.Txid]transactions.TxWithValidInfo)
}

// PendingCount returns the number of transactions currently pending in the pool.
func (pool *TransactionPool) PendingCount() int {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()

	var count int
	for _, txgroup := range pool.pendingTxGroups {
		count += len(txgroup)
	}
	return count
}

// checkPendingQueueSize test to see if there is more room in the pending
// group transaction list. As long as we haven't surpassed the size limit, we
// should be good to go.
func (pool *TransactionPool) checkPendingQueueSize() error {
	pendingSize := len(pool.ProxyPending())
	if pendingSize >= pool.txPoolMaxSize {
		return fmt.Errorf("TransactionPool.Test: transaction pool have reached capacity")
	}
	return nil
}

func (pool *TransactionPool) checkSufficientFee(txgroup []transactions.SignedTxn) error {
	// The baseline threshold fee per byte is 1, the smallest fee we can
	// represent.  This amounts to a fee of 100 for a 100-byte txn, which
	// is well below MinTxnFee (1000).  This means that, when the pool
	// is not under load, the total MinFee dominates for small txns,
	// but once the pool comes under load, the fee-per-byte will quickly
	// come to dominate.
	feePerByte := uint64(1)

	// The threshold is multiplied by the feeThresholdMultiplier that
	// tracks the load on the transaction pool over time.  If the pool
	// is mostly idle, feeThresholdMultiplier will be 0, and all txns
	// are accepted (assuming the BlockEvaluator approves them, which
	// requires a flat MinTxnFee).
	feePerByte = feePerByte * pool.feeThresholdMultiplier

	// The feePerByte should be bumped to 1 to make the exponentially
	// threshold growing valid.
	if feePerByte == 0 && pool.numPendingWholeBlocks > 1 {
		feePerByte = uint64(1)
	}

	// The threshold grows exponentially if there are multiple blocks
	// pending in the pool.
	// golang has no convenient integer exponentiation, so we just
	// do this in a loop
	for i := 0; i < int(pool.numPendingWholeBlocks)-1; i++ {
		feePerByte *= pool.expFeeFactor
	}

	for _, t := range txgroup {
		feeThreshold := feePerByte * uint64(t.GetEncodedLength())
		if t.Txn.Fee.Raw < feeThreshold {
			return fmt.Errorf("fee %d below threshold %d (%d per byte * %d bytes)",
				t.Txn.Fee, feeThreshold, feePerByte, t.GetEncodedLength())
		}
	}

	return nil
}

// Test performs basic duplicate detection and well-formedness checks
// on a transaction group without storing the group.
func (pool *TransactionPool) Test(txgroup []transactions.SignedTxn) error {
	if err := pool.checkPendingQueueSize(); err != nil {
		return err
	}

	for i := range txgroup {
		txgroup[i].InitCaches()
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.pendingBlockEvaluator.TestTransactionGroup(txgroup)
}

// Test performs basic duplicate detection and well-formedness checks
// on a transaction group without storing the group.
func (pool *TransactionPool) TestProxyTx(txgroup []transactions.Tx) error {
	if err := pool.checkPendingQueueSize(); err != nil {
		return err
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.pendingBlockEvaluator.TestProxyTransactionGroup(txgroup)
}

type poolIngestParams struct {
	checkFee   bool // if set, perform fee checks
	preferSync bool // if set, wait until ledger is caught up
}

// remember attempts to add a transaction group to the pool.
func (pool *TransactionPool) remember(txgroup []transactions.SignedTxn) error {
	params := poolIngestParams{
		checkFee:   true,
		preferSync: true,
	}
	return pool.ingest(txgroup, params)
}

// add tries to add the transaction group to the pool, bypassing the fee
// priority checks.
func (pool *TransactionPool) add(txgroup []transactions.SignedTxn) error {
	params := poolIngestParams{
		checkFee:   false,
		preferSync: false,
	}
	return pool.ingest(txgroup, params)
}

// add tries to add the transaction group to the pool, bypassing the fee
// priority checks.
func (pool *TransactionPool) addProxy(tx transactions.Tx, responseCheckTxInfo appinterface.ResponseTxValidInfo) error {
	params := poolIngestParams{
		checkFee:   false,
		preferSync: false,
	}
	return pool.ingestSingle(tx, responseCheckTxInfo, params)

}

// ingest checks whether a transaction group could be remembered in the pool,
// and stores this transaction if valid.
//
// ingest assumes that pool.mu is locked.  It might release the lock
// while it waits for OnNewBlock() to be called.
func (pool *TransactionPool) ingest(txgroup []transactions.SignedTxn, params poolIngestParams) error {
	if pool.pendingBlockEvaluator == nil {
		return fmt.Errorf("TransactionPool.ingest: no pending block evaluator")
	}

	if params.preferSync {
		// Make sure that the latest block has been processed by OnNewBlock().
		// If not, we might be in a race, so wait a little bit for OnNewBlock()
		// to catch up to the ledger.
		latest := pool.ledger.Latest()
		waitExpires := time.Now().Add(timeoutOnNewBlock)
		for pool.pendingBlockEvaluator.Round() <= latest && time.Now().Before(waitExpires) {
			condvar.TimedWait(&pool.cond, timeoutOnNewBlock)
			if pool.pendingBlockEvaluator == nil {
				return fmt.Errorf("TransactionPool.ingest: no pending block evaluator")
			}
		}
	}

	// Check that the handling fee for each transaction is sufficient.
	if params.checkFee {
		err := pool.checkSufficientFee(txgroup)
		if err != nil {
			return err
		}
	}

	err := pool.addToPendingBlockEvaluator(txgroup)
	if err != nil {
		return err
	}

	pool.rememberedTxGroups = append(pool.rememberedTxGroups, txgroup)
	for _, t := range txgroup {
		pool.rememberedTxids[t.ID()] = t
	}

	return nil
}

func (pool *TransactionPool) ingestSingle(tx transactions.Tx, responseCheckTxInfo appinterface.ResponseTxValidInfo, params poolIngestParams) error {
	if pool.pendingBlockEvaluator == nil {
		return fmt.Errorf("TransactionPool.ingest: no pending block evaluator")
	}

	if params.preferSync {
		// Make sure that the latest block has been processed by OnNewBlock().
		// If not, we might be in a race, so wait a little bit for OnNewBlock()
		// to catch up to the ledger.
		latest := pool.ledger.Latest()
		waitExpires := time.Now().Add(timeoutOnNewBlock)
		for pool.pendingBlockEvaluator.Round() <= latest && time.Now().Before(waitExpires) {
			condvar.TimedWait(&pool.cond, timeoutOnNewBlock)
			if pool.pendingBlockEvaluator == nil {
				return fmt.Errorf("TransactionPool.ingest: no pending block evaluator")
			}
		}
	}

	// if TransactionPool contains the tx ,should not put this tx to txPool
	txHash := tx.ComputeID()

	if _, ok := pool.rememberedProxyValidInfo[txHash]; ok {
		return fmt.Errorf("txPool rememberedGroups contains the tx before, tx id is : %v", txHash)
	}

	if params.checkFee {
		//if _, ok := pool.pendingProxyTxids[txHash]; ok {
		if _, ok := pool.pendingProxyValidInfo[txHash]; ok {
			return fmt.Errorf("txPool pengdingGroups contains the tx before, tx id is : %v", txHash)
		}
	}

	err := pool.addSingleToPendingBlockEvaluator(tx, responseCheckTxInfo)
	if err != nil {
		return err
	}

	txWithValidInfo := transactions.TxWithValidInfo{
		TxInfo:          tx,
		FirstValidRound: basics.Round(responseCheckTxInfo.FirstValidRound),
		LastValidRound:  basics.Round(responseCheckTxInfo.LastValidRound),
		Fee:             responseCheckTxInfo.Fee,
	}

	if pool.sortedType == 1 {
		pool.rememberedProxyMaxHeap.Push(txWithValidInfo)
	} else {
		pool.rememberedProxyTxGroups = append(pool.rememberedProxyTxGroups, txWithValidInfo)
	}

	pool.rememberedProxyValidInfo[txHash] = txWithValidInfo
	//pool.TxsAvailabled()
	return nil
}

// RememberOne stores the provided transaction
// Precondition: Only RememberOne() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) RememberOne(t transactions.SignedTxn) error {
	return pool.Remember([]transactions.SignedTxn{t})
}

// Remember stores the provided transaction group
// Precondition: Only Remember() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) Remember(txgroup []transactions.SignedTxn) error {
	if err := pool.checkPendingQueueSize(); err != nil {
		return err
	}

	for i := range txgroup {
		txgroup[i].InitCaches()
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	err := pool.remember(txgroup)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %v", err)
	}

	pool.rememberCommit(false)
	return nil
}

// todo need to add to p2p module
func (pool *TransactionPool) RememberSingle(tx transactions.Tx) error {

	if err := pool.checkPendingQueueSize(); err != nil {
		return err
	}
	responseCheckTx := pool.application.CheckTx(appinterface.RequestCheckTx{Tx: tx})
	if responseCheckTx.IsErr() {
		return fmt.Errorf(" proxy checkTx err: %v", responseCheckTx.Response.GetMsg())
	}
	responseGetTxValidInfo := responseCheckTx.ResponseTxValidInfo
	txWithValidInfo := transactions.TxWithValidInfo{
		TxInfo:          tx,
		FirstValidRound: basics.Round(responseGetTxValidInfo.FirstValidRound),
		LastValidRound:  basics.Round(responseGetTxValidInfo.LastValidRound),
		Fee:             responseGetTxValidInfo.Fee,
	}
	err := txWithValidInfo.Alive(pool.pendingBlockEvaluator.Round())
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember error: %v", err)
	}
	proto := config.Consensus[pool.getConsensusVersion()]
	err = txWithValidInfo.WellFormed(proto.MaxTxnLife)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember error: %v", err)
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	err = pool.rememberSingle(tx, responseGetTxValidInfo)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember error: %v", err)
	}

	pool.rememberProxyCommit(false)
	return nil
}

// remember attempts to add a transaction group to the pool.
func (pool *TransactionPool) rememberSingle(tx transactions.Tx, responseCheckTxInfo appinterface.ResponseTxValidInfo) error {
	params := poolIngestParams{
		checkFee:   true,
		preferSync: true,
	}
	return pool.ingestSingle(tx, responseCheckTxInfo, params)
}

// Lookup returns the error associated with a transaction that used
// to be in the pool.  If no status information is available (e.g., because
// it was too long ago, or the transaction committed successfully), then
// found is false.  If the transaction is still in the pool, txErr is empty.
func (pool *TransactionPool) Lookup(txid transactions.Txid) (tx transactions.SignedTxn, txErr string, found bool) {
	if pool == nil {
		return transactions.SignedTxn{}, "", false
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()

	tx, inPool := pool.pendingTxids[txid]
	if inPool {
		return tx, "", true
	}

	return pool.statusCache.check(txid)
}

// Lookup returns the error associated with a transaction that used
// to be in the pool.  If no status information is available (e.g., because
// it was too long ago, or the transaction committed successfully), then
// found is false.  If the transaction is still in the pool, txErr is empty.
func (pool *TransactionPool) LookupProxyTx(txid transactions.Txid) (tx transactions.Tx, txErr string, found bool) {
	if pool == nil {
		return transactions.Tx{}, "", false
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.pendingProxyMu.RLock()
	defer pool.pendingProxyMu.RUnlock()

	//tx, inPool := pool.pendingProxyTxids[txid]
	txValidinfo, inPool := pool.pendingProxyValidInfo[txid]
	if inPool {
		tx = txValidinfo.TxInfo
		return tx, "", true
	}
	return transactions.Tx{}, "proxy tx not in pool", false
}

// Verified returns whether a given SignedTxn is already in the
// pool, and, since only verified transactions should be added
// to the pool, whether that transaction is verified (i.e., Verify
// returned success).  This is used as an optimization to avoid
// re-checking signatures on transactions that we have already
// verified.
func (pool *TransactionPool) Verified(txn transactions.SignedTxn) bool {
	if pool == nil {
		return false
	}
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()
	pendingSigTxn, ok := pool.pendingTxids[txn.ID()]
	if !ok {
		return false
	}

	return pendingSigTxn.Sig == txn.Sig && pendingSigTxn.Msig.Equal(txn.Msig) && pendingSigTxn.Lsig.Equal(&txn.Lsig)
}

// EvalOk for LogicSig Eval of a txn by txid, returns the SignedTxn, error string, and found.
func (pool *TransactionPool) EvalOk(cvers protocol.ConsensusVersion, txid transactions.Txid) (found bool, err error) {
	pool.lcmu.RLock()
	defer pool.lcmu.RUnlock()
	return pool.lsigCache.get(cvers, txid)
}

// EvalRemember sets an error string from LogicSig Eval for some SignedTxn
func (pool *TransactionPool) EvalRemember(cvers protocol.ConsensusVersion, txid transactions.Txid, err error) {
	pool.lcmu.Lock()
	defer pool.lcmu.Unlock()
	pool.lsigCache.put(cvers, txid, err)
}

// OnNewBlock excises transactions from the pool that are included in the specified Block or if they've expired
func (pool *TransactionPool) OnNewBlock(block bookkeeping.Block, delta ledger.StateDelta) {
	var stats telemetryspec.ProcessBlockMetrics
	var knownCommitted uint
	var unknownCommitted uint

	commitedTxids := delta.Txids

	if pool.logStats {
		pool.pendingMu.RLock()
		for txid := range commitedTxids {
			//if _, ok := pool.pendingProxyTxids[txid]; ok {
			if _, ok := pool.pendingProxyValidInfo[txid]; ok {
				knownCommitted++
			} else {
				unknownCommitted++
			}
		}
		pool.pendingMu.RUnlock()
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	defer pool.cond.Broadcast()

	if pool.pendingBlockEvaluator == nil || block.Round() >= pool.pendingBlockEvaluator.Round() {
		// Adjust the pool fee threshold.  The rules are:
		// - If there was less than one full block in the pool, reduce
		//   the multiplier by 2x.  It will eventually go to 0, so that
		//   only the flat MinTxnFee matters if the pool is idle.
		// - If there were less than two full blocks in the pool, keep
		//   the multiplier as-is.
		// - If there were two or more full blocks in the pool, grow
		//   the multiplier by 2x (or increment by 1, if 0).
		switch pool.numPendingWholeBlocks {
		case 0:
			pool.feeThresholdMultiplier = pool.feeThresholdMultiplier / pool.expFeeFactor

		case 1:
			// Keep the fee multiplier the same.

		default:
			if pool.feeThresholdMultiplier == 0 {
				pool.feeThresholdMultiplier = 1
			} else {
				pool.feeThresholdMultiplier = pool.feeThresholdMultiplier * pool.expFeeFactor
			}
		}
		// Recompute the pool by starting from the new latest block.
		// This has the side-effect of discarding transactions that
		// have been committed (or that are otherwise no longer valid).
		stats = pool.recomputeBlockEvaluator(commitedTxids)
	}

	stats.KnownCommittedCount = knownCommitted
	stats.UnknownCommittedCount = unknownCommitted

	proto := config.Consensus[block.CurrentProtocol]

	// update consensusVersion cache
	pool.updateConsensusVersion(block.CurrentProtocol)

	pool.expiredTxCount[block.Round()] = int(stats.ExpiredCount)
	delete(pool.expiredTxCount, block.Round()-expiredHistory*basics.Round(proto.MaxTxnLife))

	if pool.logStats {
		var details struct {
			Round uint64
		}
		details.Round = uint64(block.Round())
		logging.Base().Metrics(telemetryspec.Transaction, stats, details)
	}
}

// alwaysVerifiedPool implements ledger.VerifiedTxnCache and returns every
// transaction as verified.
type alwaysVerifiedPool struct {
	pool *TransactionPool
}

func (*alwaysVerifiedPool) Verified(txn transactions.SignedTxn) bool {
	return true
}
func (pool *alwaysVerifiedPool) EvalOk(cvers protocol.ConsensusVersion, txid transactions.Txid) (txfound bool, err error) {
	return pool.pool.EvalOk(cvers, txid)
}
func (pool *alwaysVerifiedPool) EvalRemember(cvers protocol.ConsensusVersion, txid transactions.Txid, txErr error) {
	pool.pool.EvalRemember(cvers, txid, txErr)
}

func (pool *TransactionPool) addToPendingBlockEvaluatorOnce(txgroup []transactions.SignedTxn) error {
	r := pool.pendingBlockEvaluator.Round() + pool.numPendingWholeBlocks
	for _, tx := range txgroup {
		if tx.Txn.LastValid < r {
			return transactions.TxnDeadError{
				Round:      r,
				FirstValid: tx.Txn.FirstValid,
				LastValid:  tx.Txn.LastValid,
			}
		}
	}

	txgroupad := make([]transactions.SignedTxnWithAD, len(txgroup))
	for i, tx := range txgroup {
		txgroupad[i].SignedTxn = tx
	}
	return pool.pendingBlockEvaluator.TransactionGroup(txgroupad)
}

func (pool *TransactionPool) addSingleToPendingBlockEvaluatorOnce(tx transactions.Tx, responseCheckTxInfo appinterface.ResponseTxValidInfo) error {
	// round verify don't need

	return pool.pendingBlockEvaluator.TransactionSingle(tx, responseCheckTxInfo, pool.ledger.GetApplication())
}

func (pool *TransactionPool) addToPendingBlockEvaluator(txgroup []transactions.SignedTxn) error {
	err := pool.addToPendingBlockEvaluatorOnce(txgroup)
	if err == ledger.ErrNoSpace {
		pool.numPendingWholeBlocks++
		pool.pendingBlockEvaluator.ResetTxnBytes()
		err = pool.addToPendingBlockEvaluatorOnce(txgroup)
	}
	return err
}

func (pool *TransactionPool) addSingleToPendingBlockEvaluator(tx transactions.Tx, responseCheckTxInfo appinterface.ResponseTxValidInfo) error {
	err := pool.addSingleToPendingBlockEvaluatorOnce(tx, responseCheckTxInfo)
	if err == ledger.ErrNoSpace {
		pool.numPendingWholeBlocks++
		pool.pendingBlockEvaluator.ResetTxnBytes()
		err = pool.addSingleToPendingBlockEvaluatorOnce(tx, responseCheckTxInfo)
	}
	return err
}

// recomputeBlockEvaluator constructs a new BlockEvaluator and feeds all
// in-pool transactions to it (removing any transactions that are rejected
// by the BlockEvaluator).ResponseSaveToDisk
func (pool *TransactionPool) recomputeBlockEvaluator(committedTxIds map[transactions.Txid]basics.Round) (stats telemetryspec.ProcessBlockMetrics) {
	//pool.pendingBlockEvaluator = nil

	latest := pool.ledger.Latest()
	prev, err := pool.ledger.BlockHdr(latest)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: cannot get prev header for %d: %v",
			latest, err)
		return
	}
	pool.notifiedTxsAvailable = false

	var consensusData bookkeeping.ConsensusData
	committee := consensusData.Committee
	//committeePropose := consensusData.CommitteePropose
	equivocations := consensusData.Equivocations

	//if latest > 1 {
	//	lastBlockCertificate := pool.ledger.ReadPreCertificate()
	//	if lastBlockCertificate.Round != (latest) {
	//		logging.Base().Warnf("ledger preCertificate round is not right, round is %v, need round is %v ", lastBlockCertificate.Round, latest)
	//		lastBlockCertificate, err = pool.ledger.CertificateSelect(latest)
	//		if err != nil {
	//			logging.Base().Errorf("could not make proposals at round %d: could not get last certificate from ledger: %v",
	//				latest, err)
	//			return
	//		}
	//	}
	//
	//	// todo
	//	// add equivocations
	//	//certEquivocations := lastBlockCertificate.EquivocationVotes
	//	//for _, certEquivocation := range certEquivocations {
	//	//	newCertEquivocation, err := convertEquivocationVoteType(certEquivocation)
	//	//	if err == nil {
	//	//		equivocations.CertEquivocations = append(equivocations.CertEquivocations, newCertEquivocation)
	//	//	} else {
	//	//		logging.Base().Warnf("newCertEquivocation type convert error", err)
	//	//	}
	//	//}
	//
	//	//for _, proposeAddress := range lastBlockCertificate.ProposerList {
	//	//	proposerPower := uint64(1)
	//	//	committee = append(committee, bookkeeping.CommitteeSingle{CommitteeAddress: proposeAddress, CommitteePower: proposerPower, CommitteeType: 0})
	//	//}
	//} else if latest == 1 {
	//	lastBlockCertificate := pool.ledger.ReadPreCertificate()
	//	if lastBlockCertificate.Round != (latest) {
	//		logging.Base().Warnf("ledger preCertificate round is not right, round is %v, need round is %v ", lastBlockCertificate.Round, latest)
	//		lastBlockCertificate, err = pool.ledger.CertificateSelect(latest)
	//		if err != nil {
	//			logging.Base().Errorf("could not make proposals at round %d: could not get last certificate from ledger: %v",
	//				latest, err)
	//			return
	//		}
	//	}
	//	//proposerPower := i.getBalancePower(round-1, lastBlockCertificate.Proposal.OriginalProposer)
	//	//proposerPower := uint64(1)
	//	//committee = append(committee, bookkeeping.CommitteeSingle{CommitteeAddress: lastBlockCertificate.Proposal.OriginalProposer, CommitteePower: proposerPower, CommitteeType: 0})
	//}

	// todo need to add proposer
	var proposer basics.Address

	appState, err := pool.ledger.AppState(latest)
	next := bookkeeping.MakeBlock(prev, committee, equivocations, proposer, appState)

	pool.numPendingWholeBlocks = 0
	pool.pendingBlockEvaluator, err = pool.ledger.StartEvaluator(next.BlockHeader, &alwaysVerifiedPool{pool}, nil)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: cannot start evaluator: %v", err)
		return
	}

	pool.pendingProxyMu.RLock()
	var txProxys []transactions.TxWithValidInfo
	if pool.sortedType == 1 {
		txProxys = pool.pendingProxyMaxHeap
	} else {
		txProxys = pool.pendingProxyTxGroups
	}

	pool.pendingProxyMu.RUnlock()

	for _, txProxy := range txProxys {

		txId := txProxy.TxInfo.ComputeID()
		if _, alreadyCommitted := committedTxIds[txId]; alreadyCommitted {
			continue
		}
		// if txProxy is round illegal, means txProxy is expired, abandon it
		if _, ok := pool.pendingProxyValidInfo[txId]; ok {

			//TODO need to add later, delete temporary
			lastValidRound := pool.pendingProxyValidInfo[txId].LastValidRound
			if lastValidRound <= latest {
				logging.Base().Infof("tx is expired, so abandon it , txId is :%v, lastValidRound is : %v, ,round is : %v", txId, lastValidRound, latest)
				continue
			}
		}
		responseCheckTxInfo := appinterface.ResponseTxValidInfo{FirstValidRound: uint64(txProxy.FirstValidRound), LastValidRound: uint64(txProxy.LastValidRound), Fee: txProxy.Fee}
		err = pool.addProxy(txProxy.TxInfo, responseCheckTxInfo)
		//todo
		// if add to pool faild, need to add handler
		if err != nil {
			logging.Base().Errorf("could not save tx to transactionPool, txId is %s, round is %s", txId, latest+1)
		}
	}

	pool.rememberProxyCommit(true)
	return
}

func (pool *TransactionPool) getBalancePower(round basics.Round, address basics.Address) uint64 {
	var balancePower uint64
	balancePower = 1
	record, err := pool.ledger.Lookup(round, address)
	if err != nil {
		logging.Base().Errorf("Failed to obtain balance record for address %v in round %v: %v", address, round)
	} else {
		balancePower = record.Power.Raw
	}
	return balancePower
}

//func convertEquivocationVoteType(eq agreement.EquivocationVoteAuthenticator) (bookkeeping.EquivocationAuthenticator, error) {
//	var newEq bookkeeping.EquivocationAuthenticator
//	newEq.Sender = eq.Sender
//	newEq.Cred = eq.Cred
//	newEq.Sigs = eq.Sigs
//
//	// only if length of eq.Proposals is 2 , EquivocationVote is effective
//	if len(eq.Proposals) == 2 {
//		newEq.Proposals[0].OriginalProposer = eq.Proposals[0].OriginalProposer
//		newEq.Proposals[0].BlockDigest = eq.Proposals[0].BlockDigest
//		newEq.Proposals[0].EncodingDigest = eq.Proposals[0].EncodingDigest
//		newEq.Proposals[0].OriginalPeriod = uint64(eq.Proposals[0].OriginalPeriod)
//
//		newEq.Proposals[1].OriginalProposer = eq.Proposals[1].OriginalProposer
//		newEq.Proposals[1].BlockDigest = eq.Proposals[1].BlockDigest
//		newEq.Proposals[1].EncodingDigest = eq.Proposals[1].EncodingDigest
//		newEq.Proposals[1].OriginalPeriod = uint64(eq.Proposals[1].OriginalPeriod)
//	} else {
//		return bookkeeping.EquivocationAuthenticator{}, fmt.Errorf("EquivocationVoteAuthenticator is not valid")
//	}
//
//	return newEq, nil
//}

func (pool *TransactionPool) getConsensusVersion() protocol.ConsensusVersion {
	if pool.protoVertion == "" {
		pool.updateConsensusVersion("")
	}
	return pool.protoVertion
}

func (pool *TransactionPool) updateConsensusVersion(pro protocol.ConsensusVersion) {
	if pro == "" {
		pool.protoVertion = protocol.ConsensusCurrentVersion
	} else {
		pool.protoVertion = pro
	}
}

//func (pool *TransactionPool) waitForTxs(pcv protocol.ConsensusVersion) bool {
//	cfg := config.Consensus[pcv]
//	return !cfg.CreateEmptyBlocks || cfg.CreateEmptyBlocksInterval > 0
//}
