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
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/node/appinterface"
	"reflect"
	"sort"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/data/committee"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/gatemint/data/transactions/logic"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/gatemint/util/execpool"
	"github.com/gatechain/gatemint/util/metrics"
	"github.com/gatechain/logging"
)

// ErrNoSpace indicates insufficient space for transaction in block
var ErrNoSpace = errors.New("block does not have space for transaction")

var logicGoodTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_ok", Description: "Total transaction scripts executed and accepted"})
var logicRejTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_rej", Description: "Total transaction scripts executed and rejected"})
var logicErrTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_err", Description: "Total transaction scripts executed and errored"})

// evalAux is left after removing explicit reward claims,
// in case we need this infrastructure in the future.
type evalAux struct {
}

// VerifiedTxnCache captures the interface for a cache of previously
// verified transactions.  This is expected to match the transaction
// pool object.
type VerifiedTxnCache interface {
	Verified(txn transactions.SignedTxn) bool
	EvalOk(cvers protocol.ConsensusVersion, txid transactions.Txid) (found bool, txErr error)
	EvalRemember(cvers protocol.ConsensusVersion, txid transactions.Txid, err error)
}

type roundCowBase struct {
	l ledgerForEvaluator

	// The round number of the previous block, for looking up prior state.
	rnd basics.Round

	// TxnCounter from previous block header.
	txnCount uint64

	// The current protocol consensus params.
	proto config.ConsensusParams
}

func (x *roundCowBase) lookup(addr basics.Address) (basics.AccountData, error) {
	return x.l.LookupWithoutRewards(x.rnd, addr)
}

func (x *roundCowBase) isDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	return x.l.isDup(x.proto, x.rnd+1, firstValid, lastValid, txid, txl)
}

func (x *roundCowBase) txnCounter() uint64 {
	return x.txnCount
}

// wrappers for roundCowState to satisfy the (current) transactions.Balances interface
func (cs *roundCowState) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	acctdata, err := cs.lookup(addr)
	if err != nil {
		return basics.BalanceRecord{}, err
	}
	if withPendingRewards {
		acctdata = acctdata.WithUpdatedRewards(cs.proto, cs.rewardsLevel())
	}
	return basics.BalanceRecord{Addr: addr, AccountData: acctdata}, nil
}

func (cs *roundCowState) Put(record basics.BalanceRecord) error {
	olddata, err := cs.lookup(record.Addr)
	if err != nil {
		return err
	}
	cs.put(record.Addr, olddata, record.AccountData)
	return nil
}

func (cs *roundCowState) Move(from basics.Address, to basics.Address, amt basics.Power, fromRewards *basics.Power, toRewards *basics.Power) error {
	rewardlvl := cs.rewardsLevel()

	fromBal, err := cs.lookup(from)
	if err != nil {
		return err
	}
	fromBalNew := fromBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if fromRewards != nil {
		var ot basics.OverflowTracker
		newFromRewards := ot.AddA(*fromRewards, ot.SubA(fromBalNew.Power, fromBal.Power))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of fromRewards for account %v: %d + (%d - %d)", from, *fromRewards, fromBalNew.Power, fromBal.Power)
		}
		*fromRewards = newFromRewards
	}

	var overflowed bool
	fromBalNew.Power, overflowed = basics.OSubA(fromBalNew.Power, amt)
	if overflowed {
		return fmt.Errorf("overspend (account %v, data %+v, tried to spend %v)", from, fromBal, amt)
	}
	cs.put(from, fromBal, fromBalNew)

	toBal, err := cs.lookup(to)
	if err != nil {
		return err
	}
	toBalNew := toBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if toRewards != nil {
		var ot basics.OverflowTracker
		newToRewards := ot.AddA(*toRewards, ot.SubA(toBalNew.Power, toBal.Power))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of toRewards for account %v: %d + (%d - %d)", to, *toRewards, toBalNew.Power, toBal.Power)
		}
		*toRewards = newToRewards
	}

	toBalNew.Power, overflowed = basics.OAddA(toBalNew.Power, amt)
	if overflowed {
		return fmt.Errorf("balance overflow (account %v, data %+v, was going to receive %v)", to, toBal, amt)
	}
	cs.put(to, toBal, toBalNew)

	return nil
}

func (cs *roundCowState) ConsensusParams() config.ConsensusParams {
	return cs.proto
}

// BlockEvaluator represents an in-progress evaluation of a block
// against the ledger.
type BlockEvaluator struct {
	state    *roundCowState
	aux      *evalAux
	validate bool
	generate bool
	txcache  VerifiedTxnCache

	prevHeader  bookkeeping.BlockHeader // cached
	proto       config.ConsensusParams
	genesisHash crypto.Digest

	block        bookkeeping.Block
	blockTxBytes int

	verificationPool execpool.BacklogPool

	l ledgerForEvaluator
}

type ledgerForEvaluator interface {
	GenesisHash() crypto.Digest
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	Lookup(basics.Round, basics.Address) (basics.AccountData, error)
	Totals(basics.Round) (AccountTotals, error)
	isDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, txlease) (bool, error)
	GetRoundTxIds(rnd basics.Round) (txMap map[transactions.Txid]bool)
	LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, error)

	Block(rnd basics.Round) (blk bookkeeping.Block, err error)

	//IsNeedRefreshCache(indexRound basics.Round, ledgerRound basics.Round) (bool, bool, basics.Round)
	//AddBlockToDupCache(round basics.Round, blk bookkeeping.Block) error
	//DeleteBlock(indexRound basics.Round) error
	//IsTxDupCached(queryTx transactions.Tx) (bool, basics.Round)

	CheckDup(lastValid basics.Round, txid transactions.Txid) (bool, error)
	GetTxValidInfo(tx transactions.Tx) (transactions.TxWithValidInfo, error)
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate.
func (l *Ledger) StartEvaluator(hdr bookkeeping.BlockHeader, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	return startEvaluator(l, hdr, nil, true, true, txcache, executionPool)
}

func startEvaluator(l ledgerForEvaluator, hdr bookkeeping.BlockHeader, aux *evalAux, validate bool, generate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	proto, ok := config.Consensus[hdr.CurrentProtocol]
	if !ok {
		return nil, ProtocolError(hdr.CurrentProtocol)
	}

	if aux == nil {
		aux = &evalAux{}
	}

	base := &roundCowBase{
		l: l,
		// round that lookups come from is previous block.  We validate
		// the block at this round below, so underflow will be caught.
		// If we are not validating, we must have previously checked
		// an agreement.Certificate attesting that hdr is valid.
		rnd:   hdr.Round - 1,
		proto: proto,
	}

	eval := &BlockEvaluator{
		aux:              aux,
		validate:         validate,
		generate:         generate,
		txcache:          txcache,
		block:            bookkeeping.Block{BlockHeader: hdr},
		proto:            proto,
		genesisHash:      l.GenesisHash(),
		verificationPool: executionPool,
		l:                l,
	}

	if hdr.Round > 0 {
		var err error
		eval.prevHeader, err = l.BlockHdr(base.rnd)
		if err != nil {
			return nil, fmt.Errorf("can't evaluate block %v without previous header: %v", hdr.Round, err)
		}

		base.txnCount = eval.prevHeader.TxnCounter
	}

	//reward nonsupport by gatemint

	if generate {
		if eval.proto.SupportGenesisHash {
			eval.block.BlockHeader.GenesisHash = eval.genesisHash
		}
		//reward nonsupport by gatemint
		//eval.block.BlockHeader.RewardsState = eval.prevHeader.NextRewardsState(hdr.Round, proto, incentivePoolData.Power, prevTotals.RewardUnits())
	}
	//// set the eval state with the current header
	eval.state = makeRoundCowState(base, eval.block.BlockHeader)
	//
	if validate {
		err := eval.block.BlockHeader.PreCheck(eval.prevHeader)
		if err != nil {
			return nil, err
		}
		//
		//	//reward nonsupport by gatemint
	}
	//// ensure that we have at least MinBalance after withdrawing rewards
	//ot.SubA(poolNew.Power, basics.Power{Raw: proto.MinBalance})
	//if ot.Overflowed {
	//	// TODO this should never happen; should we panic here?
	//	return nil, fmt.Errorf("overflowed subtracting rewards for block %v", hdr.Round)
	//}

	return eval, nil
}

// hotfix for testnet stall 08/26/2019; move some algos from testnet bank to rewards pool to give it enough time until protocol upgrade occur.
// hotfix for testnet stall 11/07/2019; do the same thing
func (eval *BlockEvaluator) workaroundOverspentRewards(rewardPoolBalance basics.BalanceRecord, headerRound basics.Round) (poolOld basics.BalanceRecord, err error) {
	// verify that we patch the correct round.
	if headerRound != 1499995 && headerRound != 2926564 {
		return rewardPoolBalance, nil
	}
	// verify that we're patching the correct genesis ( i.e. testnet )
	testnetGenesisHash, _ := crypto.DigestFromString("JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA")
	if eval.genesisHash != testnetGenesisHash {
		return rewardPoolBalance, nil
	}

	// get the testnet bank ( dispenser ) account address.
	bankAddr, _ := basics.UnmarshalChecksumAddress("GD64YIY3TWGDMCNPP553DZPPR6LDUSFQOIJVFDPPXWEG3FVOJCCDBBHU5A")
	amount := basics.Power{Raw: 20000000000}
	err = eval.state.Move(bankAddr, eval.prevHeader.RewardsPool, amount, nil, nil)
	if err != nil {
		err = fmt.Errorf("unable to move funds from testnet bank to incentive pool: %v", err)
		return
	}
	poolOld, err = eval.state.Get(eval.prevHeader.RewardsPool, true)

	return
}

// Round returns the round number of the block being evaluated by the BlockEvaluator.
func (eval *BlockEvaluator) Round() basics.Round {
	return eval.block.Round()
}

// ResetTxnBytes resets the number of bytes tracked by the BlockEvaluator to
// zero.  This is a specialized operation used by the transaction pool to
// simulate the effect of putting pending transactions in multiple blocks.
func (eval *BlockEvaluator) ResetTxnBytes() {
	eval.blockTxBytes = 0
}

// TestTransactionGroup performs basic duplicate detection and well-formedness checks
// on a transaction group, but does not actually add the transactions to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) TestTransactionGroup(txgroup []transactions.SignedTxn) error {
	// Nothing to do if there are no transactions.
	if len(txgroup) == 0 {
		return nil
	}

	if len(txgroup) > eval.proto.MaxTxGroupSize {
		return fmt.Errorf("group size %d exceeds maximum %d", len(txgroup), eval.proto.MaxTxGroupSize)
	}

	cow := eval.state.child()

	var group transactions.TxGroup
	for gi, txn := range txgroup {
		err := eval.testTransaction(txn, cow)
		if err != nil {
			return err
		}

		// Make sure all transactions in group have the same group value
		if txn.Txn.Group != txgroup[0].Txn.Group {
			return fmt.Errorf("transactionGroup: inconsistent group values: %v != %v",
				txn.Txn.Group, txgroup[0].Txn.Group)
		}

		if !txn.Txn.Group.IsZero() {
			txWithoutGroup := txn.Txn
			txWithoutGroup.Group = crypto.Digest{}
			txWithoutGroup.ResetCaches()

			group.TxGroupHashes = append(group.TxGroupHashes, crypto.HashObj(txWithoutGroup))
		} else if len(txgroup) > 1 {
			return fmt.Errorf("transactionGroup: [%d] had zero Group but was submitted in a group of %d", gi, len(txgroup))
		}
	}

	// If we had a non-zero Group value, check that all group members are present.
	if group.TxGroupHashes != nil {
		if txgroup[0].Txn.Group != crypto.HashObj(group) {
			return fmt.Errorf("transactionGroup: incomplete group: %v != %v (%v)",
				txgroup[0].Txn.Group, crypto.HashObj(group), group)
		}
	}

	return nil
}

// testTransaction performs basic duplicate detection and well-formedness checks
// on a single transaction, but does not actually add the transaction to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) testTransaction(txn transactions.SignedTxn, cow *roundCowState) error {
	// Verify that groups are supported.
	if !txn.Txn.Group.IsZero() && !eval.proto.SupportTxGroups {
		return fmt.Errorf("transaction groups not supported")
	}

	// Transaction valid (not expired)?
	err := txn.Txn.Alive(eval.block)
	if err != nil {
		return err
	}

	// Well-formed on its own?
	spec := transactions.SpecialAddresses{
		FeeSink:     eval.block.BlockHeader.FeeSink,
		RewardsPool: eval.block.BlockHeader.RewardsPool,
	}
	err = txn.Txn.WellFormed(spec, eval.proto)
	if err != nil {
		return fmt.Errorf("transaction %v: malformed: %v", txn.ID(), err)
	}

	// Transaction already in the ledger?
	txid := txn.ID()
	dup, err := cow.isDup(txn.Txn.First(), txn.Txn.Last(), txid, txlease{sender: txn.Txn.Sender, lease: txn.Txn.Lease})
	if err != nil {
		return err
	}
	if dup {
		return TransactionInLedgerError{txn.ID()}
	}

	return nil
}

// TestTransactionGroup performs basic duplicate detection and well-formedness checks
// on a transaction group, but does not actually add the transactions to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) TestProxyTransactionGroup(txgroup []transactions.Tx) error {
	// Nothing to do if there are no transactions.
	if len(txgroup) == 0 {
		return nil
	}

	if len(txgroup) > eval.proto.MaxTxGroupSize {
		return fmt.Errorf("group size %d exceeds maximum %d", len(txgroup), eval.proto.MaxTxGroupSize)
	}
	cow := eval.state.child()
	for _, txn := range txgroup {
		err := eval.testProxyTransaction(txn, cow)
		if err != nil {
			return err
		}
	}
	return nil
}

// testProxyTransaction performs basic duplicate detection and well-formedness checks
// on a single transaction, but does not actually add the transaction to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) testProxyTransaction(txn transactions.Tx, cow *roundCowState) error {

	// Transaction already in the ledger?
	// TODO this check not check transactionPool

	txWithValidInfo, err := eval.l.GetTxValidInfo(txn)
	if err != nil {
		return err
	}

	err = txWithValidInfo.Alive(eval.block.Round())
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember error: %v", err)
	}
	//proto := config.Consensus[eval.proto]
	err = txWithValidInfo.WellFormed(eval.proto.MaxTxnLife)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember error: %v", err)
	}

	isTxDup, err := eval.checkTxDup(txWithValidInfo.LastValidRound, txWithValidInfo.LastValidRound, txn)
	if err != nil {
		return err
	}
	if isTxDup {
		return fmt.Errorf("tx id dup in ledger, tx id : %v", txn.ComputeID())
	}
	return nil
}

// Transaction tentatively adds a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) Transaction(txn transactions.SignedTxn, ad transactions.ApplyData) error {
	//not support

	//return eval.transactionGroup([]transactions.SignedTxnWithAD{
	//	transactions.SignedTxnWithAD{
	//		SignedTxn: txn,
	//		ApplyData: ad,
	//	},
	//}, true)
	return nil
}

// TransactionGroup tentatively adds a new transaction group as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) TransactionGroup(txads []transactions.SignedTxnWithAD) error {
	//not support
	return nil
}

// TransactionGroup tentatively adds a new transaction group as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) TransactionSingle(tx transactions.Tx, responseCheckTxInfo appinterface.ResponseTxValidInfo, proxyApp appinterface.Application) error {
	return eval.transactionSingle(tx, true, responseCheckTxInfo, proxyApp)
}

// transactionGroup tentatively executes a group of transactions as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.  If remember is true,
// the transaction group is added to the block evaluator state; otherwise, the block evaluator
// is not modified and does not remember this transaction group.
func (eval *BlockEvaluator) transactionSingle(tx transactions.Tx, remember bool, responseCheckTxInfo appinterface.ResponseTxValidInfo, proxyApp appinterface.Application) error {
	// Nothing to do if there are no transactions.
	//var txibs []transactions.SignedTxnInBlock
	var groupTxBytes int

	var txsib transactions.SignedSingleTxnInBlock

	cow := eval.state.child()

	{
		if eval.validate {

			// Transaction already in the ledger?
			// judge tx is in indexer
			isTxDup, err := eval.checkTxDup(basics.Round(responseCheckTxInfo.LastValidRound), basics.Round(responseCheckTxInfo.LastValidRound), tx)
			if err != nil {
				return fmt.Errorf("check tx dup error, txId is : %v, err is : %v", tx.ComputeID(), err)
			}
			if isTxDup {
				return fmt.Errorf("tx is dup in ledger ,tx id : %v", tx.ComputeID())
			}
			// is block has enough space
			txsib = transactions.SignedSingleTxnInBlock{Tx: tx, HasGenesisID: true, HasGenesisHash: true}
			groupTxBytes += len(protocol.Encode(txsib))
			if eval.blockTxBytes+groupTxBytes > eval.proto.MaxTxnBytesPerBlock {
				return ErrNoSpace
			}
		}
		//add checkTx , and show some reason to check tx
		{
			// check isAlive tx, round and genesis judge
			// Transaction already in the ledger?
			// looks reasonable on its own
			// Properly signed
			// Verify that tx groups
			// needCheckLsig ?
			// cow balances isValidate
			// Move Power from one account to another, doing all necessary overflow checking (convenience method) and change account delta
			// existing block applying data check
			// Check if the transaction fits in the block
			// besides
			// Check if any affected accounts dipped below MinBalance (unless they are
			// completely zero, which means the account will be deleted.)

			// todo Remember this txn (below need to consider later)
			// cow.addTx(txn.Txn)

			//fmt.Println("*******inter checkTx :", tx.ComputeID())
			//responseCheckTx := proxyApp.CheckTx(appinterface.RequestCheckTx{Tx: tx})
			//if responseCheckTx.IsErr() {
			//	return errors.New(fmt.Sprintf(" proxy checkTx err: ", responseCheckTx.Response.GetMsg()))
			//}
			cow.mods.Txids[tx.ComputeID()] = basics.Round(responseCheckTxInfo.LastValidRound)
		}
	}

	if remember {
		//eval.block.Payset = append(eval.block.Payset, txsib)
		eval.block.PayProxySet = append(eval.block.PayProxySet, txsib)
		eval.blockTxBytes += groupTxBytes
		cow.commitToParent()

		// add temp
		// set all tx id will invalid after 1000 round

		//eval.state.mods.Txids[tx.ComputeID()] = eval.block.Round() + 1000

		// todo txlease is need?
		//eval.state.mods.txleases[tx.ComputeID()] = eval.block.Round() + 1000

		// add temp
	}

	return nil
}

// checkTxDup return error if dup is true
func (eval *BlockEvaluator) checkTxDup(firstValidHeight basics.Round, lastValidHeight basics.Round, tx transactions.Tx) (bool, error) {
	return eval.l.CheckDup(lastValidHeight, tx.ComputeID())
}

func (eval *BlockEvaluator) checkLogicSig(txn transactions.SignedTxn, txgroup []transactions.SignedTxnWithAD, groupIndex int) (err error) {
	if txn.Txn.FirstValid == 0 {
		return errors.New("LogicSig does not work with FirstValid==0")
	}
	// TODO: move this into some lazy evaluator for the few scripts that actually use `txn FirstValidTime` ?
	hdr, err := eval.l.BlockHdr(basics.Round(txn.Txn.FirstValid - 1))
	if err != nil {
		return fmt.Errorf("could not fetch BlockHdr for FirstValid-1=%d (current=%d): %s", txn.Txn.FirstValid-1, eval.block.BlockHeader.Round, err)
	}
	ep := logic.EvalParams{
		Txn:        &txn,
		Proto:      &eval.proto,
		TxnGroup:   txgroup,
		GroupIndex: groupIndex,
	}
	if hdr.TimeStamp < 0 {
		return fmt.Errorf("cannot evaluate LogicSig before 1970 at TimeStamp %d", hdr.TimeStamp)
	}
	ep.FirstValidTimeStamp = uint64(hdr.TimeStamp)
	pass, err := logic.Eval(txn.Lsig.Logic, ep)
	if err != nil {
		logicErrTotal.Inc(nil)
		return fmt.Errorf("transaction %v: rejected by logic err=%s", txn.ID(), err)
	}
	if !pass {
		logicRejTotal.Inc(nil)
		return fmt.Errorf("transaction %v: rejected by logic", txn.ID())
	}
	logicGoodTotal.Inc(nil)
	return nil
}

// Call "endOfBlock" after all the block's rewards and transactions are processed. Applies any deferred balance updates.
func (eval *BlockEvaluator) endOfBlock() error {
	if eval.generate {
		eval.block.TxnRoot = eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
		if eval.proto.TxnCounter {
			eval.block.TxnCounter = eval.state.txnCounter()
		} else {
			eval.block.TxnCounter = 0
		}
	}

	return nil
}

// Call "endOfProxyBlock" after all the block's rewards and transactions are processed. Applies any deferred balance updates.
func (eval *BlockEvaluator) endOfProxyBlock() error {
	if eval.generate {
		eval.block.TxnRoot = eval.block.PayProxySet.Commit(eval.proto.PaysetCommitFlat)
		if eval.proto.TxnCounter {
			eval.block.TxnCounter = eval.state.txnCounter()
		} else {
			eval.block.TxnCounter = 0
		}
	}

	return nil
}

// FinalValidation does the validation that must happen after the block is built and all state updates are computed
func (eval *BlockEvaluator) finalValidation() error {
	if eval.validate {
		// check commitments
		txnRoot := eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
		if txnRoot != eval.block.TxnRoot {
			return fmt.Errorf("txn root wrong: %v != %v", txnRoot, eval.block.TxnRoot)
		}

		var expectedTxnCount uint64
		if eval.proto.TxnCounter {
			expectedTxnCount = eval.state.txnCounter()
		}
		if eval.block.TxnCounter != expectedTxnCount {
			return fmt.Errorf("txn count wrong: %d != %d", eval.block.TxnCounter, expectedTxnCount)
		}
	}

	return nil
}

// FinalProxyValidation does the validation that must happen after the block is built and all state updates are computed
func (eval *BlockEvaluator) finalProxyValidation() error {
	if eval.validate {
		// check commitments
		txnRoot := eval.block.PayProxySet.Commit(eval.proto.PaysetCommitFlat)
		if txnRoot != eval.block.TxnRoot {
			return fmt.Errorf("proxy txn root wrong: %v != %v", txnRoot, eval.block.TxnRoot)
		}

		var expectedTxnCount uint64
		if eval.proto.TxnCounter {
			expectedTxnCount = eval.state.txnCounter()
		}
		if eval.block.TxnCounter != expectedTxnCount {
			return fmt.Errorf("txn count wrong: %d != %d", eval.block.TxnCounter, expectedTxnCount)
		}
	}

	return nil
}

// GenerateBlock produces a complete block from the BlockEvaluator.  This is
// used during proposal to get an actual block that will be proposed, after
// feeding in tentative transactions into this block evaluator.
func (eval *BlockEvaluator) GenerateProxyBlock() (*ValidatedBlock, error) {
	if !eval.generate {
		logging.Base().Panicf("GenerateBlock() called but generate is false")
	}

	err := eval.endOfProxyBlock()
	if err != nil {
		return nil, err
	}

	err = eval.finalProxyValidation()
	if err != nil {
		return nil, err
	}

	vb := ValidatedBlock{
		blk:   eval.block,
		delta: eval.state.mods,
		aux:   *eval.aux,
	}
	return &vb, nil
}

// GenerateBlock produces a complete block from the BlockEvaluator.  This is
// used during proposal to get an actual block that will be proposed, after
// feeding in tentative transactions into this block evaluator.
func (eval *BlockEvaluator) GenerateBlock() (*ValidatedBlock, error) {
	if !eval.generate {
		logging.Base().Panicf("GenerateBlock() called but generate is false")
	}

	err := eval.endOfBlock()
	if err != nil {
		return nil, err
	}

	err = eval.finalValidation()
	if err != nil {
		return nil, err
	}

	vb := ValidatedBlock{
		blk:   eval.block,
		delta: eval.state.mods,
		aux:   *eval.aux,
	}
	return &vb, nil
}

// update from eval std tx to eval proxy tx
func (l *Ledger) eval(ctx context.Context, blk bookkeeping.Block, aux *evalAux, validate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (StateDelta, evalAux, error) {

	eval, err := startEvaluator(l, blk.BlockHeader, aux, validate, false, txcache, executionPool)
	if err != nil {
		return StateDelta{}, evalAux{}, err
	}

	// TODO: batch tx sig verification: ingest blk.Payset and output a list of ValidatedTx

	proxyPaySet := blk.PayProxySet
	for _, proxyTx := range proxyPaySet {
		select {
		case <-ctx.Done():
			return StateDelta{}, evalAux{}, ctx.Err()
		default:
		}

		responseTxValidInfo := l.proxyApps.application.GetTxValidInfo(appinterface.RequestGetTxValidInfo{Tx: proxyTx.Tx})
		if responseTxValidInfo.IsErr() {
			return StateDelta{}, evalAux{}, fmt.Errorf("get txValidInfo err, txId is %v, error info : %v", proxyTx.Tx.ComputeID(), responseTxValidInfo.Response.Log)
		}

		err = eval.TransactionSingle(proxyTx.Tx, responseTxValidInfo.ResponseTxValidInfo, l.proxyApps.application)
		if err != nil {
			return StateDelta{}, evalAux{}, err
		}
	}

	err = eval.endOfProxyBlock()
	if err != nil {
		return StateDelta{}, evalAux{}, err
	}

	// If validating, do final block checks that depend on our new state
	if validate {
		err = eval.finalProxyValidation()
		if err != nil {
			return StateDelta{}, evalAux{}, err
		}
	}

	return eval.state.mods, *eval.aux, nil
}

// Validate uses the ledger to validate block blk as a candidate next block.
// It returns an error if blk is not the expected next block, or if blk is
// not a valid block (e.g., it has duplicate transactions, overspends some
// account, etc).
func (l *Ledger) Validate(ctx context.Context, blk bookkeeping.Block, txcache VerifiedTxnCache, executionPool execpool.BacklogPool, period uint64) (*ValidatedBlock, error) {
	delta, aux, err := l.eval(ctx, blk, nil, true, txcache, executionPool)
	if err != nil {
		return nil, err
	}

	// add reward verify
	isBlkHeaderLegal, err := l.verifyBlockHeader(blk, period)
	if err != nil {
		return nil, err
	} else if !isBlkHeaderLegal {
		return nil, fmt.Errorf("blk header not legal, round is %d", blk.Round())
	}
	req := buildExecuteRequest(blk)
	l.log.Warnf("BeginExecuteblock %d", blk.Round())
	Current++
	res := l.GetApplication().Executeblock(req)
	if res.ResponseStatus.IsErr() {
		l.log.Warnf("Warning in file: eval.go line 804. cannot commit @round err is %d %s", uint64(blk.Round()), res.ResponseStatus.GetMsg())
		return nil, fmt.Errorf(res.ResponseStatus.GetMsg())
	}
	l.log.Warnf("EndExecuteblock %d", blk.Round())
	//delta = buildDelta(res, delta)
	vb := ValidatedBlock{
		blk:   blk,
		delta: delta,
		aux:   aux,
	}
	return &vb, nil
}

// ValidatedBlock represents the result of a block validation.  It can
// be used to efficiently add the block to the ledger, without repeating
// the work of applying the block's changes to the ledger state.
type ValidatedBlock struct {
	blk   bookkeeping.Block
	delta StateDelta
	aux   evalAux
}

// Block returns the underlying Block for a ValidatedBlock.
func (vb ValidatedBlock) Block() bookkeeping.Block {
	return vb.blk
}

// WithSeed returns a copy of the ValidatedBlock with a modified seed.
func (vb ValidatedBlock) WithSeed(s committee.Seed) ValidatedBlock {
	newblock := vb.blk
	newblock.BlockHeader.Seed = s

	return ValidatedBlock{
		blk:   newblock,
		delta: vb.delta,
		aux:   vb.aux,
	}
}

func (l *Ledger) verifyBlockHeader(blk bookkeeping.Block, period uint64) (bool, error) {

	appStateOk, err := l.verifyAppState(blk)
	if err != nil {
		return appStateOk, fmt.Errorf("appState verify faild, %v", err)
	}
	if !appStateOk {
		return appStateOk, fmt.Errorf("appState verify is not correct")
	}

	// add period is not nil
	if period > 0 {
		//if len(blk.Committee.CertList) == 0 && len(blk.Committee.SoftList) == 0 {
		// just need to verify blk proposer
		if false {
			logging.Base().Infof("consensus committee verify empty committee ok, blk round is %v, blk period is %v", blk.Round(), period)
			fmt.Println("consensus committee verify empty committee ok, blk round is:, blk period is:", blk.Round(), ",,,", period)
			return true, nil
		}
	}

	committeeOk, err := l.verifyCommittee(blk, period)
	if err != nil {
		return committeeOk, fmt.Errorf("committee verify faild, %v", err)
	}
	if !committeeOk {
		return committeeOk, fmt.Errorf("committee verify is not correct")
	}

	return true, nil
	//return false, nil
}

func (l *Ledger) verifyAppState(blk bookkeeping.Block) (bool, error) {

	// todo verify appState
	return true, nil
}

// verifyCommittee varify block committee
func (l *Ledger) verifyCommittee(blk bookkeeping.Block, period uint64) (bool, error) {
	proto, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]
	if !ok {
		return false, ProtocolError(blk.BlockHeader.CurrentProtocol)
	}
	round := blk.Round()
	lastBlockCertificate, err := l.CertificateSelect(round - 1)
	if err != nil {
		return false, fmt.Errorf("validate block reward error: %d ,%v", uint64(round), err)
	}
	if round > 2 {
		proposeState := false
		if period < proto.CommitteeBottomPeriod {
			proposeState, err = verifyProposeList(blk, lastBlockCertificate)
			logging.Base().Infof("verify blk proposeList normal, round/period info is (%v/%v)", blk.Round(), period)
			if err != nil {
				logging.Base().Errorf("verify blk proposeList error, %v", err)
				return false, fmt.Errorf("verify blk proposeList error, round is %d", uint64(round))
			}
		} else {
			proposeState, err = reVerifyProposeList(blk, lastBlockCertificate)
			logging.Base().Infof("verify blk proposeList bottom, round/period info is (%v/%v)", blk.Round(), period)
			if err != nil {
				logging.Base().Errorf("verify blk proposeList error, %v", err)
				return false, fmt.Errorf("verify blk proposeList error, round is %d", uint64(round))
			}
		}
		if !proposeState {
			logging.Base().Errorf("verify blk proposeList not match")
			return false, fmt.Errorf("verify blk proposeList not match, round is %d", uint64(round))
		}
	}
	return true, nil
}

func verifyProposeList(blk bookkeeping.Block, cert agreement.Certificate) (bool, error) {
	if cert.ProposerList == nil || len(cert.ProposerList) == 0 {
		return false, fmt.Errorf("certificate proposerList length is 0")
	}

	var blkProposeAddressList []basics.Address
	for _, blkProposeInfo := range blk.Committee {
		blkProposeAddressList = append(blkProposeAddressList, blkProposeInfo.CommitteeAddress)
	}
	sort.Sort(basics.AddressSlice(blkProposeAddressList))
	certProposeList := cert.ProposerList
	sort.Sort(basics.AddressSlice(certProposeList))
	isCommitteeMatch := reflect.DeepEqual(blkProposeAddressList, certProposeList)
	if !isCommitteeMatch {
		logging.Base().Warnf("verify blk proposeList not match, blkPropose is : %v, certPropose is : %v", blkProposeAddressList, certProposeList)
	}
	return isCommitteeMatch, nil
}

func reVerifyProposeList(blk bookkeeping.Block, cert agreement.Certificate) (bool, error) {

	if len(blk.Committee) != 1 {
		logging.Base().Warnf("reVerify blk proposeList not match, blk committee len is not 1, blk committee is : %v ", blk.Committee)
	}
	isCommitteeMatch := bytes.Compare(blk.Committee[0].CommitteeAddress[:], cert.Proposal.OriginalProposer[:]) == 0
	if !isCommitteeMatch {
		logging.Base().Warnf("verify blk proposeList not match, blkPropose is : %v, certPropose is : %v", blk.Committee[0].CommitteeAddress[:], cert.Proposal.OriginalProposer[:])
	}
	return isCommitteeMatch, nil
}
