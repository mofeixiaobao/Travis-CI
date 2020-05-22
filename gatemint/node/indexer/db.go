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
	"github.com/gatechain/gatemint/util/db"
)

const (
	dbName  = "indexer.sqlite"
	maxRows = 100
)

var schema = `
	CREATE TABLE IF NOT EXISTS transactions(
		txid CHAR(52) PRIMARY KEY NOT NULL,
		from_addr CHAR(58) DEFAULT NULL,
		to_addr CHAR(58) DEFAULT NULL,
		round INTEGER DEFAULT NULL,
		created_at INTEGER
	);

	CREATE TABLE IF NOT EXISTS params(
		k CHAR(15) PRIMARY KEY DEFAULT NULL,
		v INTEGER DEFAULT NULL,
		UNIQUE (k)
	);

	INSERT OR IGNORE INTO params (k, v) VALUES ('maxRound', 1);

	CREATE INDEX IF NOT EXISTS idx ON transactions (
		created_at	DESC,
		from_addr,
		to_addr
	);
`

// Transaction represents a transaction in the system
type Transaction struct {
	TXID      string
	From      string `db:"from_addr_r"`
	To        string `db:"to_addr_r"`
	Round     uint32
	CreatedAt uint32 `db:"created_at"`
}

// DB is a the db access layer for Indexer
type DB struct {
	// DB Accessors
	dbr db.Accessor
	dbw db.Accessor

	// DBPath holds the db file path
	DBPath string
}

// GetTransactionByID takes a transaction ID and returns its transaction record
func (idb *DB) GetTransactionByID(txid string) (Transaction, error) {
	query := `
		SELECT 
			txid, 
			from_addr,
			to_addr,
			round,
			created_at
		FROM
			transactions
		WHERE
		txid = $1
	`

	var txn Transaction
	if err := idb.dbr.Handle.QueryRow(query, txid).Scan(&txn.TXID, &txn.From, &txn.To, &txn.Round, &txn.CreatedAt); err != nil {
		return Transaction{}, err
	}

	return txn, nil
}

// GetTransactionsRoundsByAddr takes an address and returns all its transaction rounds records
// if top is 0, it will return 25 transactions by default
func (idb *DB) GetTransactionsRoundsByAddr(addr string, top uint64) ([]uint64, error) {
	query := `
		SELECT DISTINCT
			round
		FROM
			transactions
		WHERE
		from_addr = $1 OR to_addr = $1 
		ORDER BY created_at DESC
		LIMIT $2;
	`

	// limit
	if top == 0 {
		top = maxRows
	}

	var rounds []uint64
	var rnd uint64
	rows, err := idb.dbr.Handle.Query(query, addr, top)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&rnd)
		if err != nil {
			return nil, err
		}
		rounds = append(rounds, rnd)
	}

	err = rows.Err()

	if err != nil {
		return nil, err
	}

	return rounds, nil
}

// GetTransactionsRoundsByAddrAndDate takes an address and a date range (as seconds from epoch) and returns all
// of its transaction rounds records.
// if top is 0, it will return 100 transactions by default
func (idb *DB) GetTransactionsRoundsByAddrAndDate(addr string, top uint64, from, to int64) ([]uint64, error) {
	query := `
		SELECT DISTINCT
			round
		FROM
			transactions
		WHERE
		created_at > $1 AND created_at < $2
		AND 
		(from_addr = $3 OR to_addr = $3)
		LIMIT $4;
	`

	// limit
	if top == 0 {
		top = maxRows
	}

	var rounds []uint64
	var rnd uint64
	rows, err := idb.dbr.Handle.Query(query, from, to, addr, top)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&rnd)
		if err != nil {
			return nil, err
		}

		rounds = append(rounds, rnd)
	}

	err = rows.Err()

	if err != nil {
		return nil, err
	}

	return rounds, nil
}

// MaxRound returns the latest block in the DB
func (idb *DB) MaxRound() (uint64, error) {
	var rnd uint64
	if err := idb.dbr.Handle.QueryRow("SELECT v from params where k = 'maxRound'").Scan(&rnd); err != nil {
		return 0, err
	}
	return rnd, nil
}

// Close closes the db connections
func (idb *DB) Close() {
	idb.dbw.Close()
	idb.dbr.Close()
}
