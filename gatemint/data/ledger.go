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

package data

import (
	"fmt"
	"github.com/gatechain/gatemint/node/appinterface"
	"github.com/gatechain/gatemint/node/indexer"
	"time"

	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/data/committee"
	"github.com/gatechain/gatemint/data/pools"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/gatemint/ledger"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/logging"
	"github.com/gatechain/logging/telemetryspec"
)

// The Ledger object in this (data) package provides a wrapper around the
// Ledger from the ledger package.  The reason for this is compatibility
// with the existing callers of the previous ledger API, without increasing
// the complexity of the ledger.Ledger code.  This Ledger object also
// implements various wrappers that return subsets of data exposed by
// ledger.Ledger, or return it in different forms, or return it for the
// latest round (as opposed to arbitrary rounds).
type Ledger struct {
	*ledger.Ledger

	log logging.Logger
}

func makeGenesisBlock(proto protocol.ConsensusVersion, genesisBal GenesisBalances, genesisID string, genesisHash crypto.Digest) (bookkeeping.Block, error) {
	params, ok := config.Consensus[proto]
	if !ok {
		return bookkeeping.Block{}, fmt.Errorf("unsupported protocol %s", proto)
	}

	poolAddr := basics.Address(genesisBal.rewardsPool)
	incentivePoolBalanceAtGenesis := genesisBal.balances[poolAddr].Power

	genesisRewardsState := bookkeeping.RewardsState{
		FeeSink:                   genesisBal.feeSink,
		RewardsPool:               genesisBal.rewardsPool,
		RewardsLevel:              0,
		RewardsRate:               incentivePoolBalanceAtGenesis.Raw / uint64(params.RewardsRateRefreshInterval),
		RewardsResidue:            0,
		RewardsRecalculationRound: basics.Round(params.RewardsRateRefreshInterval),
	}

	genesisProtoState := bookkeeping.UpgradeState{
		CurrentProtocol: proto,
	}

	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round:        0,
			Branch:       bookkeeping.BlockHash{},
			Seed:         committee.Seed(genesisHash),
			TxnRoot:      transactions.Payset{}.Commit(params.PaysetCommitFlat),
			TimeStamp:    genesisBal.timestamp,
			GenesisID:    genesisID,
			RewardsState: genesisRewardsState,
			UpgradeState: genesisProtoState,
			UpgradeVote:  bookkeeping.UpgradeVote{},
		},
	}

	if params.SupportGenesisHash {
		blk.BlockHeader.GenesisHash = genesisHash
	}

	return blk, nil
}

// LoadLedger creates a Ledger object to represent the ledger with the
// specified database file prefix, initializing it if necessary.
func LoadLedger(
	log logging.Logger, dbFilenamePrefix string, memory bool,
	genesisProto protocol.ConsensusVersion, genesisBal GenesisBalances, genesisID string, genesisHash crypto.Digest,
	blockListeners []ledger.BlockListener, isArchival bool, application appinterface.Application, rootDir string, genesis bookkeeping.Genesis,
) (*Ledger, error) {
	if genesisBal.balances == nil {
		genesisBal.balances = make(map[basics.Address]basics.AccountData)
	}
	genBlock, err := makeGenesisBlock(genesisProto, genesisBal, genesisID, genesisHash)
	if err != nil {
		return nil, err
	}

	params := config.Consensus[genesisProto]
	if params.ForceNonParticipatingFeeSink {
		sinkAddr := genesisBal.feeSink
		sinkData := genesisBal.balances[sinkAddr]
		sinkData.Status = basics.NotParticipating
		genesisBal.balances[sinkAddr] = sinkData
	}

	l := &Ledger{
		log: log,
	}
	genesisInitState := ledger.InitState{
		Block:       genBlock,
		Accounts:    genesisBal.balances,
		GenesisHash: genesisHash,
	}
	l.log.Debugf("Initializing Ledger(%s)", dbFilenamePrefix)

	ll, err := ledger.OpenLedger(log, dbFilenamePrefix, memory, genesisInitState, isArchival, application, rootDir, genesis)
	if err != nil {
		return nil, err
	}

	l.Ledger = ll
	l.RegisterBlockListeners(blockListeners)
	return l, nil
}

func (l *Ledger) LoadLedgerAfterIndex() error {
	return l.UpdateLedgerAfterIndex()
}

// AddressTxns returns the list of transactions to/from a given address in specific round
func (l *Ledger) AddressTxns(id basics.Address, r basics.Round) ([]transactions.SignedTxnWithAD, error) {
	blk, err := l.Block(r)
	if err != nil {
		return nil, err
	}
	spec := transactions.SpecialAddresses{
		FeeSink:     blk.FeeSink,
		RewardsPool: blk.RewardsPool,
	}
	proto := config.Consensus[blk.CurrentProtocol]

	var res []transactions.SignedTxnWithAD
	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil, err
	}
	for _, tx := range payset {
		if tx.Txn.MatchAddress(id, spec, proto) {
			res = append(res, tx)
		}
	}
	return res, nil
}

// LookupTxid returns the transaction with a given ID in a specific round
func (l *Ledger) LookupTxid(txid transactions.Txid, r basics.Round) (stxn transactions.SignedTxnWithAD, found bool, err error) {
	var blk bookkeeping.Block
	blk, err = l.Block(r)
	if err != nil {
		return transactions.SignedTxnWithAD{}, false, err
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return transactions.SignedTxnWithAD{}, false, err
	}
	for _, tx := range payset {
		if tx.ID() == txid {
			return tx, true, nil
		}
	}
	return transactions.SignedTxnWithAD{}, false, nil
}

// LastRound returns the local latest round of the network i.e. the *last* written block
func (l *Ledger) LastRound() basics.Round {
	return l.Latest()
}

// NextRound returns the *next* block to write i.e. latest() + 1
// Implements agreement.Ledger.NextRound
func (l *Ledger) NextRound() basics.Round {
	return l.LastRound() + 1
}

// BalanceRecord implements Ledger.BalanceRecord. It applies pending rewards to returned amounts.
func (l *Ledger) BalanceRecord(r basics.Round, addr basics.Address) (basics.BalanceRecord, error) {
	data, err := l.Lookup(r, addr)
	if err != nil {
		return basics.BalanceRecord{}, err
	}

	return basics.BalanceRecord{
		Addr:        addr,
		AccountData: data,
	}, nil
}

// Circulation implements agreement.Ledger.Circulation.
func (l *Ledger) Circulation(r basics.Round, addr basics.Address) (basics.Power, basics.BalanceRecord, error) {

	totals, acct, err := l.RecordAndTotals(r, addr)

	if err != nil {
		return basics.Power{}, basics.BalanceRecord{}, err
	}

	return totals.Money, basics.BalanceRecord{
		Addr:        addr,
		AccountData: acct,
	}, nil
}

// Seed gives the VRF seed that was agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.Seed
func (l *Ledger) Seed(r basics.Round) (committee.Seed, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return committee.Seed{}, err
	}
	return blockhdr.Seed, nil
}

// LookupDigest gives the block hash that was agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.LookupDigest
func (l *Ledger) LookupDigest(r basics.Round) (crypto.Digest, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return crypto.Digest{}, err
	}
	return crypto.Digest(blockhdr.Hash()), nil
}

// ConsensusParams gives the consensus parameters agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.ConsensusParams
func (l *Ledger) ConsensusParams(r basics.Round) (config.ConsensusParams, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return config.ConsensusParams{}, err
	}
	return config.Consensus[blockhdr.UpgradeState.CurrentProtocol], nil
}

// ConsensusVersion gives the consensus version agreed on in a given round,
// returning an error if we don't have that round or we have an
// I/O error.
// Implements agreement.Ledger.ConsensusVersion
func (l *Ledger) ConsensusVersion(r basics.Round) (protocol.ConsensusVersion, error) {
	blockhdr, err := l.BlockHdr(r)
	if err != nil {
		return "", err
	}
	return blockhdr.UpgradeState.CurrentProtocol, nil
}

// EnsureValidatedBlock ensures that the block, and associated certificate c, are
// written to the ledger, or that some other block for the same round is
// written to the ledger.
func (l *Ledger) EnsureValidatedBlock(vb *ledger.ValidatedBlock, c agreement.Certificate) {
	round := vb.Block().Round()

	for l.LastRound() < round {
		err := l.AddValidatedBlock(*vb, c)
		if err == nil {
			break
		}

		logfn := logging.Base().Errorf

		switch err.(type) {
		case ledger.BlockInLedgerError:
			logfn = logging.Base().Debugf
		}

		logfn("could not write block %d to the ledger: %v", round, err)
	}
}

// EnsureBlock ensures that the block, and associated certificate c, are
// written to the ledger, or that some other block for the same round is
// written to the ledger.
func (l *Ledger) EnsureBlock(block *bookkeeping.Block, c agreement.Certificate) {
	round := block.Round()
	protocolErrorLogged := false

	for l.LastRound() < round {
		err := l.AddBlock(*block, c)
		if err == nil {
			break
		}

		switch err.(type) {
		case ledger.ProtocolError:
			if !protocolErrorLogged {
				logging.Base().Errorf("unrecoverable protocol error detected at block %d: %v", round, err)
				protocolErrorLogged = true
			}
		case ledger.BlockInLedgerError:
			logging.Base().Debugf("could not write block %d to the ledger: %v", round, err)
			return // this error implies that l.LastRound() >= round
		default:
			logging.Base().Errorf("could not write block %d to the ledger: %v", round, err)
		}

		// If there was an error add a short delay before the next attempt.
		time.Sleep(100 * time.Millisecond)
	}
}

// AssemblePayset adds transactions to a BlockEvaluator.
func (l *Ledger) AssemblePayset(pool *pools.TransactionPool, eval *ledger.BlockEvaluator, deadline time.Time) (stats telemetryspec.AssembleBlockStats) {
	proxyPending := pool.ProxyPending()
	stats.StartCount = len(proxyPending)
	stats.StopReason = telemetryspec.AssembleBlockEmpty
	totalFees := uint64(0)

	// retrieve a list of all the previously known txid in the current round. We want to retrieve it here so we could avoid
	// exercising the ledger read lock.
	//prevRoundTxIds := l.GetRoundTxIds(l.Latest())

	for len(proxyPending) > 0 {

		proxyTxSingle := proxyPending[0]
		proxyPending = proxyPending[1:]

		// todo TODO need to add proxy tx id to tx tail

		// if we already had this tx in the previous round, and haven't removed it yet from the txpool, that's fine.
		// just skip that one.
		//if prevRoundTxIds[txgroup[0].ID()] {
		//	stats.EarlyCommittedCount++
		//	continue
		//}

		if time.Now().After(deadline) {
			stats.StopReason = telemetryspec.AssembleBlockTimeout
			break
		}

		responseCheckTxInfo := appinterface.ResponseTxValidInfo{
			FirstValidRound: uint64(proxyTxSingle.FirstValidRound),
			LastValidRound:  uint64(proxyTxSingle.LastValidRound),
			Fee:             proxyTxSingle.Fee,
		}

		err := eval.TransactionSingle(proxyTxSingle.TxInfo, responseCheckTxInfo, l.GetApplication())
		if err == ledger.ErrNoSpace {
			stats.StopReason = telemetryspec.AssembleBlockFull
			break
		}
		if err != nil {
			// GOAL2-255: Don't warn for common case of txn already being in ledger
			switch err.(type) {
			case ledger.TransactionInLedgerError:
				stats.CommittedCount++
			case transactions.MinFeeError:
				stats.InvalidCount++
				logging.Base().Infof("Cannot add pending transaction to block: %v", err)
			default:
				stats.InvalidCount++
				logging.Base().Warnf("Cannot add pending transaction to block: %v", err)
			}
		} else {
			stats.IncludedCount++
			encodedLen := proxyTxSingle.TxInfo.ComputeEncodingLen()
			if encodedLen < stats.MinLength {
				stats.MinLength = encodedLen
			} else if encodedLen > stats.MaxLength {
				stats.MaxLength = encodedLen
			}
		}

	}

	if stats.IncludedCount != 0 {
		stats.AverageFee = totalFees / uint64(stats.IncludedCount)
	}
	return
}

func (l *Ledger) InitApplication(application appinterface.Application, genesis bookkeeping.Genesis, rootDir string) error {
	err := l.Ledger.InitApplication(application, genesis, rootDir)
	return err
}

func (l *Ledger) GetApplication() appinterface.Application {
	return l.Ledger.GetApplication()
}

func (l *Ledger) SetIndexer(indexer *indexer.Indexer) {
	l.Ledger.SetIndexer(indexer)
}
