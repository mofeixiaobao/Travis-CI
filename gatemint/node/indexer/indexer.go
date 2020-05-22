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

package indexer

import (
	"context"
	"fmt"
	"github.com/gatechain/gatemint/node/appinterface"
	"github.com/tendermint/tendermint/libs/pubsub/query"
	"time"

	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
)

// Ledger interface to make testing easier
type Ledger interface {
	Block(rnd basics.Round) (blk bookkeeping.Block, err error)
	Wait(r basics.Round) chan struct{}
}

const (
	// see README
	defaultPerPage = 30
	maxPerPage     = 1000

	// SubscribeTimeout is the maximum time we wait to subscribe for an event.
	// must be less than the server's write timeout (see rpcserver.DefaultConfig)
	SubscribeTimeout = 5 * time.Second
)

// Indexer keeps track of transactions and their senders
// to enable quick retrieval.
type Indexer struct {
	IDB        *DB
	indexStore *IndexStore
	l          Ledger
	ctx        context.Context
	cancelCtx  context.CancelFunc
}

// MakeIndexer makes a new indexer.
func MakeIndexer(dataDir string, ledger Ledger, inMemory bool) (*Indexer, *IndexStore, error) {
	indexStore := MakeIndexStore(indexStoreName, "goleveldb", dataDir)
	ctx, cancel := context.WithCancel(context.Background())
	return &Indexer{
		indexStore: indexStore,
		l:          ledger,
		ctx:        ctx,
		cancelCtx:  cancel,
	}, indexStore, nil
}

func (idx *Indexer) GetTxByHash(hash []byte) (tib TxInBlock, err error) {
	tib, err = idx.indexStore.GetTxByHash(hash)
	if err != nil {
		return tib, err
	}
	return tib, nil
}

func (idx *Indexer) QueryTxByHash(hash []byte) (tx *appinterface.ResponseTx, err error) {
	tx, err = idx.indexStore.Get(hash)
	if err != nil {
		return tx, err
	}
	return tx, nil
}

func (idx *Indexer) TxSearch(param string, page, perPage int, orderBy string) (*appinterface.ResultTxSearch, error) {
	q, err := query.New(param)
	if err != nil {
		return &appinterface.ResultTxSearch{Txs: nil, TotalCount: 0}, err
	}
	conditions, err := q.Conditions()
	if orderBy == "DESC" {
		orderBy = OrderByDesc
	} else {
		orderBy = OrderByAsc
	}

	results, err := idx.indexStore.Search(conditions, orderBy)
	if err != nil {
		return nil, err
	}
	totalCount := len(results)
	perPage = validatePerPage(perPage)
	page, err = validatePage(page, perPage, totalCount)
	if err != nil {
		return nil, err
	}
	skipCount := validateSkipCount(page, perPage)
	apiResults := make([]*appinterface.ResponseTx, minInt(perPage, totalCount-skipCount))
	// if there's no tx in the results array, we don't need to loop through the apiResults array
	for i := 0; i < len(apiResults); i++ {
		r := results[skipCount+i]
		height := r.Height
		index := r.Index

		//if prove {
		//	block := blockStore.LoadBlock(height)
		//	proof = block.Data.Txs.Proof(int(index)) // XXX: overflow on 32-bit machines
		//}

		apiResults[i] = &appinterface.ResponseTx{
			//Hash:     r.Tx.Hash(),
			Height:   height,
			Index:    index,
			Response: r.Response,
			Tx:       r.Tx,
			//Proof:    proof,
		}
	}

	return &appinterface.ResultTxSearch{Txs: apiResults, TotalCount: totalCount}, nil
}

// GetRoundByTXID takes a transactionID an returns its round number
func (idx *Indexer) GetRoundByTXID(txID string) (uint64, error) {
	txn, err := idx.IDB.GetTransactionByID(txID)
	if err != nil {
		return 0, err
	}
	return uint64(txn.Round), nil
}

// GetRoundsByAddressAndDate takes an address, date range and maximum number of txns to return , and returns all
// blocks that contain the relevant transaction. if top is 0, it defaults to 100.
func (idx *Indexer) GetRoundsByAddressAndDate(addr string, top uint64, from, to int64) ([]uint64, error) {
	rounds, err := idx.IDB.GetTransactionsRoundsByAddrAndDate(addr, top, from, to)
	if err != nil {
		return nil, err
	}
	return rounds, nil
}

// GetRoundsByAddress takes an address and the number of transactions to return
// and returns all blocks that contain transaction where the address was the
// sender or the receiver.
func (idx *Indexer) GetRoundsByAddress(addr string, top uint64) ([]uint64, error) {
	rounds, err := idx.IDB.GetTransactionsRoundsByAddr(addr, top)
	if err != nil {
		return nil, err
	}
	return rounds, nil
}

// Shutdown closes the indexer
func (idx *Indexer) Shutdown() {
	idx.cancelCtx()
}

func validatePerPage(perPage int) int {
	if perPage < 1 {
		return defaultPerPage
	} else if perPage > maxPerPage {
		return maxPerPage
	}
	return perPage
}

func validatePage(page, perPage, totalCount int) (int, error) {
	if perPage < 1 {
		panic(fmt.Sprintf("zero or negative perPage: %d", perPage))
	}

	if page == 0 {
		return 1, nil // default
	}

	pages := ((totalCount - 1) / perPage) + 1
	if pages == 0 {
		pages = 1 // one page (even if it's empty)
	}
	if page < 0 || page > pages {
		return 1, fmt.Errorf("page should be within [0, %d] range, given %d", pages, page)
	}

	return page, nil
}

func validateSkipCount(page, perPage int) int {
	skipCount := (page - 1) * perPage
	if skipCount < 0 {
		return 0
	}

	return skipCount
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
