package account

import (
	dbm "github.com/tendermint/tm-db"
	"sync"
)


type ParticipationStore struct {
	db dbm.DB

	mtx   sync.RWMutex
	round uint64
}