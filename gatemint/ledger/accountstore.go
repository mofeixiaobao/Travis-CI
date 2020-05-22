package ledger

import (
	"fmt"
	"github.com/gatechain/gatemint/data/basics"
	"sync"
)
import dbm "github.com/tendermint/tm-db"

type AccountStore struct {
	db dbm.DB

	mtx   sync.RWMutex
	round uint64
}

type accountDelta struct {
	old basics.AccountData
	new basics.AccountData
}

var accountStoreKey = []byte("accountStore")

type AccountStoreState struct {
	Round uint64 `json:"round"`
}

func NewAccountStore(db dbm.DB) *AccountStore {
	bs := LoadAccountStoreState(db)
	return &AccountStore{
		round: bs.Round,
		db:    db,
	}
}

func LoadAccountStoreState(db dbm.DB) AccountStoreState {
	bytes := db.Get(accountStoreKey)
	if len(bytes) == 0 {
		return AccountStoreState{
			Round: 0,
		}
	}
	asj := AccountStoreState{}
	err := cdc.UnmarshalJSON(bytes, &asj)
	if err != nil {
		panic(fmt.Sprintf("Could not unmarshal bytes: %X", bytes))
	}
	return asj
}

// Round returns the last known contiguous block height.
func (as *AccountStore) Round() basics.Round {
	as.mtx.RLock()
	defer as.mtx.RUnlock()
	return basics.Round(as.round)
}

func (as *AccountStore) Init(initAccounts map[basics.Address]basics.AccountData) error {
	var ot basics.OverflowTracker
	var totals AccountTotals
	round := uint64(0)
	for addr, data := range initAccounts {
		accountBytes, err := cdc.MarshalJSON(data)
		if err != nil {
			panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
		}
		as.db.Set(addr[:], accountBytes)
		totals.addAccount(data, &ot)
	}
	totalsBytes, err := cdc.MarshalJSON(totals)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	as.db.Set(calcTotalsKey(), totalsBytes)
	if ot.Overflowed {
		return fmt.Errorf("overflow computing totals")
	}
	AccountStoreState{Round: round}.Save(as.db)
	as.mtx.Lock()
	as.round = round
	as.mtx.Unlock()
	as.db.SetSync(nil, nil)
	return nil
}

func (as *AccountStore) LoadAccountTotals() (at AccountTotals, err error) {
	totalsBz := as.db.Get(calcTotalsKey())
	err = cdc.UnmarshalJSON(totalsBz, &at)
	if err != nil {
		return at, err
	}
	return at, nil
}

func calcTotalsKey() []byte {
	return []byte(fmt.Sprintf("Totals"))
}

func (asj AccountStoreState) Save(db dbm.DB) {
	bytes, err := cdc.MarshalJSON(asj)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	db.SetSync(accountStoreKey, bytes)
}

func (as *AccountStore) NewRound(rnd basics.Round, accounts map[basics.Address]modifiedAccount, at AccountTotals) error {
	if rnd >= (as.Round() + 1) {
		totalsBytes, err := cdc.MarshalJSON(at)
		if err != nil {
			panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
		}
		as.db.Set(calcTotalsKey(), totalsBytes)
		for addr, account := range accounts {
			accountBytes, err := cdc.MarshalJSON(account.data)
			if err != nil {
				panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
			}
			as.db.Set(addr[:], accountBytes)
		}
		AccountStoreState{Round: uint64(rnd)}.Save(as.db)
		as.mtx.Lock()
		as.round = uint64(rnd)
		as.mtx.Unlock()
		as.db.SetSync(nil, nil)
	}
	return nil
}

func (as *AccountStore) addPartKey(addr []byte, account basics.AccountData) error {
	accountBytes, err := cdc.MarshalJSON(account)
	if err != nil {
		return err
	}
	as.db.SetSync(addr, accountBytes)
	return nil
}
func (as *AccountStore) removePartKey(addr []byte) error {
	as.db.DeleteSync(addr)
	return nil
}
func (as *AccountStore) lookup(addr []byte) (account basics.AccountData, err error) {
	as.mtx.RLock()
	defer as.mtx.RUnlock()
	accountBytes := as.db.Get(addr)
	err = cdc.UnmarshalJSON(accountBytes, &account)
	return account, err
}
