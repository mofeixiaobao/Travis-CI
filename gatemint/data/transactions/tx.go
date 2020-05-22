package transactions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/protocol"
)

// Tx is an arbitrary byte array.
// NOTE: Tx has no types at this level, so when wire encoded it's just length-prefixed.
// Might we want types here ?
type Tx []byte

type TxWithValidInfo struct {
	TxInfo          Tx
	FirstValidRound basics.Round
	LastValidRound  basics.Round
	Fee             uint64
}

// Hash computes the TMHASH hash of the wire encoded transaction.
func (tx Tx) Hash() []byte {
	txId := tx.ComputeID()
	return txId[:]
}

// String returns the hex-encoded transaction as a string.
func (tx Tx) String() string {
	return fmt.Sprintf("Tx{%X}", []byte(tx))
}

func (tx Tx) ComputeID() Txid {
	return Txid(crypto.Hash(tx))
}

func (tx Tx) ComputeEncodingLen() int {
	return len(protocol.Encode(&tx))
}

// Alive checks to see if the transaction is still alive (can be applied) at the specified Round.
func (tx TxWithValidInfo) Alive(round basics.Round) error {
	// Check round validity
	if round < tx.FirstValidRound || round > tx.LastValidRound {
		return TxnDeadError{
			Round:      round,
			FirstValid: tx.FirstValidRound,
			LastValid:  tx.LastValidRound,
		}
	}
	return nil
}

// WellFormed checks that the transaction looks reasonable on its own (but not necessarily valid against the actual ledger). It does not check signatures.
func (tx TxWithValidInfo) WellFormed(maxTxnLife uint64) error {
	if tx.LastValidRound < tx.FirstValidRound {
		return fmt.Errorf("transaction invalid range (%v--%v)", tx.FirstValidRound, tx.LastValidRound)
	}
	if tx.LastValidRound-tx.FirstValidRound > basics.Round(maxTxnLife) {
		return fmt.Errorf("transaction window size excessive (%v--%v)", tx.FirstValidRound, tx.LastValidRound)
	}
	return nil
}

// Txs is a slice of Tx.
type Txs []Tx

// Hash returns the Merkle root hash of the transaction hashes.
// i.e. the leaves of the tree are the hashes of the txs.
func (txs Txs) Hash() []byte {
	// These allocations will be removed once Txs is switched to [][]byte,
	// ref #2603. This is because golang does not allow type casting slices without unsafe
	txBzs := make([][]byte, len(txs))
	for i := 0; i < len(txs); i++ {
		txBzs[i] = txs[i].Hash()
	}
	// TODO need to change merkle hash
	return txBzs[0]
}

// Index returns the index of this transaction in the list, or -1 if not found
func (txs Txs) Index(tx Tx) int {
	for i := range txs {
		if bytes.Equal(txs[i], tx) {
			return i
		}
	}
	return -1
}

// IndexByHash returns the index of this transaction hash in the list, or -1 if not found
func (txs Txs) IndexByHash(hash []byte) int {
	for i := range txs {
		if bytes.Equal(txs[i].Hash(), hash) {
			return i
		}
	}
	return -1
}

// get sha512 encoded content and return as string
// todo need to update to sha512, now is sha256
func Sha256(bytes []byte) string {
	hasher := sha256.New()
	hasher.Write(bytes)
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha256_byte(bytes []byte) []byte {
	hasher := sha256.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}
