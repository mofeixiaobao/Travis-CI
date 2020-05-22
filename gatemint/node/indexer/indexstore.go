package indexer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/gatemint/node/appinterface"
	"github.com/pkg/errors"
	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/libs/pubsub/query"
	dbm "github.com/tendermint/tm-db"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IndexStore struct {
	db dbm.DB

	mtx sync.RWMutex
}

const (
	tagKeySeparator = "/"
)

type TxInBlock struct {
	Hash   []byte `json:"hash"`
	Height uint64 `json:"height"`
	Index  uint32 `json:"index"`
	Tx     []byte `json:"tx"`
}

var cdc = amino.NewCodec()

var (
	indexStoreKey  = []byte("indexStore")
	indexStoreName = "indexstore"
)

func MakeIndexStore(storeName string, dbType string, dbDir string) *IndexStore {
	db := dbm.NewDB(storeName, dbm.DBBackendType(dbType), dbDir)
	return NewIndexStore(db)
}

func NewIndexStore(db dbm.DB) *IndexStore {
	return &IndexStore{
		db: db,
	}
}

func (is *IndexStore) GetTxByHash(hash []byte) (tib TxInBlock, err error) {
	valueBytes := is.db.Get(hash)
	err = cdc.UnmarshalJSON(valueBytes, &tib)
	if err != nil {
		return tib, err
	}
	return tib, nil
}

func (is *IndexStore) Get(hash []byte) (res *appinterface.ResponseTx, err error) {
	valueBytes := is.db.Get(hash)
	if valueBytes == nil {
		return nil, nil
	}
	err = cdc.UnmarshalBinaryBare(valueBytes, &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

func (is *IndexStore) AddBatch(txes []appinterface.ResponseTx) error {
	storeBatch := is.db.NewBatch()
	defer storeBatch.Close()
	for _, result := range txes {
		var tx transactions.Tx
		tx = result.Tx
		hash := tx.Hash()
		// index tx by events
		is.indexEvents(result, hash, storeBatch)
		storeBatch.Set(keyForHeight(result), hash)

		// index tx by hash
		rawBytes, err := cdc.MarshalBinaryBare(result)
		if err != nil {
			return err
		}
		storeBatch.Set(hash, rawBytes)
	}
	storeBatch.Write()
	return nil
}
func (is *IndexStore) Search(conditions []query.Condition, orderBy string) ([]*appinterface.ResponseTx, error) {
	var hashesInitialized bool
	filteredHashes := make(map[string][]byte)

	// get a list of conditions (like "tx.height > 5")
	//conditions := q.Conditions()

	// if there is a hash condition, return the result immediately
	hash, err, ok := lookForHash(conditions)
	if err != nil {
		return nil, errors.Wrap(err, "error during searching for a hash in the query")
	} else if ok {
		res, err := is.Get(hash)
		if res == nil {
			return []*appinterface.ResponseTx{}, nil
		}
		return []*appinterface.ResponseTx{res}, errors.Wrap(err, "error while retrieving the result")
	}

	// conditions to skip because they're handled before "everything else"
	skipIndexes := make([]int, 0)

	// extract ranges
	// if both upper and lower bounds exist, it's better to get them in order not
	// no iterate over kvs that are not within range.
	ranges, rangeIndexes := lookForRanges(conditions)
	if len(ranges) > 0 {
		skipIndexes = append(skipIndexes, rangeIndexes...)

		for _, r := range ranges {
			if !hashesInitialized {
				filteredHashes = is.matchRange(r, startKey(r.key), filteredHashes, true)
				hashesInitialized = true

				// Ignore any remaining conditions if the first condition resulted
				// in no matches (assuming implicit AND operand).
				if len(filteredHashes) == 0 {
					break
				}
			} else {
				filteredHashes = is.matchRange(r, startKey(r.key), filteredHashes, false)
			}
		}
	}

	// if there is a height condition ("tx.height=3"), extract it
	height := lookForHeight(conditions)

	// for all other conditions
	for i, c := range conditions {
		if intInSlice(i, skipIndexes) {
			continue
		}

		if !hashesInitialized {
			filteredHashes = is.match(c, startKeyForCondition(c, height), filteredHashes, true)
			hashesInitialized = true

			// Ignore any remaining conditions if the first condition resulted
			// in no matches (assuming implicit AND operand).
			if len(filteredHashes) == 0 {
				break
			}
		} else {
			filteredHashes = is.match(c, startKeyForCondition(c, height), filteredHashes, false)
		}
	}

	results := make([]*appinterface.ResponseTx, 0, len(filteredHashes))
	for _, h := range filteredHashes {
		res, err := is.Get(h)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get Tx{%X}", h)
		}
		results = append(results, res)
	}

	// sort by height & index by default
	if strings.Compare(orderBy, OrderByAsc) == 0 {
		sort.Slice(results, func(i, j int) bool {
			if results[i].Height == results[j].Height {
				return results[i].Index < results[j].Index
			}
			return results[i].Height < results[j].Height
		})
	}
	if strings.Compare(orderBy, OrderByDesc) == 0 {
		sort.Slice(results, func(i, j int) bool {
			if results[i].Height == results[j].Height {
				return results[i].Index > results[j].Index
			}
			return results[i].Height > results[j].Height
		})
	}

	return results, nil
}

func (is *IndexStore) indexEvents(result appinterface.ResponseTx, hash []byte, store dbm.SetDeleter) {
	for _, event := range result.Response.Events {
		// only index events with a non-empty type
		if len(event.Type) == 0 {
			continue
		}
		for _, attr := range event.Attributes {
			if len(attr.Key) == 0 {
				continue
			}
			compositeTag := fmt.Sprintf("%s.%s", event.Type, string(attr.Key))
			store.Set(keyForEvent(compositeTag, attr.Value, result), hash)
		}
	}
}

func keyForEvent(key string, value []byte, result appinterface.ResponseTx) []byte {
	return []byte(fmt.Sprintf("%s/%s/%d/%d",
		key,
		value,
		result.Height,
		result.Index,
	))
}
func keyForHeight(result appinterface.ResponseTx) []byte {
	return []byte(fmt.Sprintf("%s/%d/%d/%d",
		"tx.height",
		result.Height,
		result.Height,
		result.Index,
	))
}

func lookForHash(conditions []query.Condition) (hash []byte, err error, ok bool) {
	for _, c := range conditions {
		if c.Tag == "tx.hash" {
			decoded, err := hex.DecodeString(c.Operand.(string))
			return decoded, err, true
		}
	}
	return
}

// special map to hold range conditions
// Example: account.number => queryRange{lowerBound: 1, upperBound: 5}
type queryRanges map[string]queryRange

type queryRange struct {
	lowerBound        interface{} // int || time.Time
	upperBound        interface{} // int || time.Time
	key               string
	includeLowerBound bool
	includeUpperBound bool
}

func lookForRanges(conditions []query.Condition) (ranges queryRanges, indexes []int) {
	ranges = make(queryRanges)
	for i, c := range conditions {
		if isRangeOperation(c.Op) {
			r, ok := ranges[c.Tag]
			if !ok {
				r = queryRange{key: c.Tag}
			}
			switch c.Op {
			case query.OpGreater:
				r.lowerBound = c.Operand
			case query.OpGreaterEqual:
				r.includeLowerBound = true
				r.lowerBound = c.Operand
			case query.OpLess:
				r.upperBound = c.Operand
			case query.OpLessEqual:
				r.includeUpperBound = true
				r.upperBound = c.Operand
			}
			ranges[c.Tag] = r
			indexes = append(indexes, i)
		}
	}
	return ranges, indexes
}

func isRangeOperation(op query.Operator) bool {
	switch op {
	case query.OpGreater, query.OpGreaterEqual, query.OpLess, query.OpLessEqual:
		return true
	default:
		return false
	}
}

// matchRange returns all matching txs by hash that meet a given queryRange and
// start key. An already filtered result (filteredHashes) is provided such that
// any non-intersecting matches are removed.
//
// NOTE: filteredHashes may be empty if no previous condition has matched.
func (is *IndexStore) matchRange(r queryRange, startKey []byte, filteredHashes map[string][]byte, firstRun bool) map[string][]byte {
	// A previous match was attempted but resulted in no matches, so we return
	// no matches (assuming AND operand).
	if !firstRun && len(filteredHashes) == 0 {
		return filteredHashes
	}

	tmpHashes := make(map[string][]byte)
	lowerBound := r.lowerBoundValue()
	upperBound := r.upperBoundValue()

	it := dbm.IteratePrefix(is.db, startKey)
	defer it.Close()

LOOP:
	for ; it.Valid(); it.Next() {
		if !isTagKey(it.Key()) {
			continue
		}

		if _, ok := r.AnyBound().(int64); ok {
			v, err := strconv.ParseInt(extractValueFromKey(it.Key()), 10, 64)
			if err != nil {
				continue LOOP
			}

			include := true
			if lowerBound != nil && v < lowerBound.(int64) {
				include = false
			}

			if upperBound != nil && v > upperBound.(int64) {
				include = false
			}

			if include {
				tmpHashes[string(it.Value())] = it.Value()
			}

			// XXX: passing time in a ABCI Tags is not yet implemented
			// case time.Time:
			// 	v := strconv.ParseInt(extractValueFromKey(it.Key()), 10, 64)
			// 	if v == r.upperBound {
			// 		break
			// 	}
		}
	}

	if len(tmpHashes) == 0 || firstRun {
		// Either:
		//
		// 1. Regardless if a previous match was attempted, which may have had
		// results, but no match was found for the current condition, then we
		// return no matches (assuming AND operand).
		//
		// 2. A previous match was not attempted, so we return all results.
		return tmpHashes
	}

	// Remove/reduce matches in filteredHashes that were not found in this
	// match (tmpHashes).
	for k := range filteredHashes {
		if tmpHashes[k] == nil {
			delete(filteredHashes, k)
		}
	}

	return filteredHashes
}

func (r queryRange) lowerBoundValue() interface{} {
	if r.lowerBound == nil {
		return nil
	}

	if r.includeLowerBound {
		return r.lowerBound
	} else {
		switch t := r.lowerBound.(type) {
		case int64:
			return t + 1
		case time.Time:
			return t.Unix() + 1
		default:
			panic("not implemented")
		}
	}
}

func (r queryRange) upperBoundValue() interface{} {
	if r.upperBound == nil {
		return nil
	}

	if r.includeUpperBound {
		return r.upperBound
	} else {
		switch t := r.upperBound.(type) {
		case int64:
			return t - 1
		case time.Time:
			return t.Unix() - 1
		default:
			panic("not implemented")
		}
	}
}

func isTagKey(key []byte) bool {
	return strings.Count(string(key), tagKeySeparator) == 3
}

func (r queryRange) AnyBound() interface{} {
	if r.lowerBound != nil {
		return r.lowerBound
	} else {
		return r.upperBound
	}
}

func extractValueFromKey(key []byte) string {
	parts := strings.SplitN(string(key), tagKeySeparator, 3)
	return parts[1]
}

func startKey(fields ...interface{}) []byte {
	var b bytes.Buffer
	for _, f := range fields {
		b.Write([]byte(fmt.Sprintf("%v", f) + tagKeySeparator))
	}
	return b.Bytes()
}

// lookForHeight returns a height if there is an "height=X" condition.
func lookForHeight(conditions []query.Condition) (height int64) {
	for _, c := range conditions {
		if c.Tag == "tx.height" && c.Op == query.OpEqual {
			return c.Operand.(int64)
		}
	}
	return 0
}

func intInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// match returns all matching txs by hash that meet a given condition and start
// key. An already filtered result (filteredHashes) is provided such that any
// non-intersecting matches are removed.
//
// NOTE: filteredHashes may be empty if no previous condition has matched.
func (is *IndexStore) match(c query.Condition, startKeyBz []byte, filteredHashes map[string][]byte, firstRun bool) map[string][]byte {
	// A previous match was attempted but resulted in no matches, so we return
	// no matches (assuming AND operand).
	if !firstRun && len(filteredHashes) == 0 {
		return filteredHashes
	}

	tmpHashes := make(map[string][]byte)

	switch {
	case c.Op == query.OpEqual:
		it := dbm.IteratePrefix(is.db, startKeyBz)
		defer it.Close()

		for ; it.Valid(); it.Next() {
			tmpHashes[string(it.Value())] = it.Value()
		}

	case c.Op == query.OpContains:
		// XXX: startKey does not apply here.
		// For example, if startKey = "account.owner/an/" and search query = "account.owner CONTAINS an"
		// we can't iterate with prefix "account.owner/an/" because we might miss keys like "account.owner/Ulan/"
		it := dbm.IteratePrefix(is.db, startKey(c.Tag))
		defer it.Close()

		for ; it.Valid(); it.Next() {
			if !isTagKey(it.Key()) {
				continue
			}

			if strings.Contains(extractValueFromKey(it.Key()), c.Operand.(string)) {
				tmpHashes[string(it.Value())] = it.Value()
			}
		}
	default:
		panic("other operators should be handled already")
	}

	if len(tmpHashes) == 0 || firstRun {
		// Either:
		//
		// 1. Regardless if a previous match was attempted, which may have had
		// results, but no match was found for the current condition, then we
		// return no matches (assuming AND operand).
		//
		// 2. A previous match was not attempted, so we return all results.
		return tmpHashes
	}

	// Remove/reduce matches in filteredHashes that were not found in this
	// match (tmpHashes).
	for k := range filteredHashes {
		if tmpHashes[k] == nil {
			delete(filteredHashes, k)
		}
	}

	return filteredHashes
}

func startKeyForCondition(c query.Condition, height int64) []byte {
	if height > 0 {
		return startKey(c.Tag, c.Operand, height)
	}
	return startKey(c.Tag, c.Operand)
}
