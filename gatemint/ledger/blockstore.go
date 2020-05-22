package ledger

import (
	"fmt"
	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	dbm "github.com/tendermint/tm-db"
	"sync"
)

/*
BlockStore is a simple low level store for blocks.
*/
type BlockStore struct {
	db dbm.DB

	mtx   sync.RWMutex
	round uint64
}

var blockStoreKey = []byte("blockStore")

// BlockStoreStateJSON is the block store state JSON structure.
type BlockStoreState struct {
	Round uint64 `json:"round"`
}

// NewBlockStore returns a new BlockStore with the given DB,
// initialized to the last height that was committed to the DB.
func NewBlockStore(db dbm.DB) *BlockStore {
	bs := LoadBlockStoreState(db)
	return &BlockStore{
		round: bs.Round,
		db:    db,
	}
}

// LoadBlockStoreState returns the BlockStoreState as loaded from disk.
// If no BlockStoreState was previously persisted, it returns the zero value.
func LoadBlockStoreState(db dbm.DB) BlockStoreState {
	bytes := db.Get(blockStoreKey)
	if len(bytes) == 0 {
		return BlockStoreState{
			Round: 0,
		}
	}
	bsj := BlockStoreState{}
	err := cdc.UnmarshalJSON(bytes, &bsj)
	if err != nil {
		panic(fmt.Sprintf("Could not unmarshal bytes: %X", bytes))
	}
	return bsj
}

func (bs *BlockStore) BlockInit(initBlocks []bookkeeping.Block) error {
	next, err := blockNext(bs)
	if err != nil {
		return err
	}
	if next == 0 {
		for _, blk := range initBlocks {
			bs.BlockPut(blk, agreement.Certificate{}, evalAux{})
		}
	}
	return nil
}

func (bs *BlockStore) BlockPut(block bookkeeping.Block, certificate agreement.Certificate, aux evalAux) {
	round := uint64(block.Round())
	blockBytes, err := cdc.MarshalJSON(block)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	bs.db.Set(calcBlockHeaderKey(round), blockBytes)

	certificateBytes, err := cdc.MarshalJSON(certificate)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	bs.db.Set(calcCertKey(round), certificateBytes)

	auxBytes, err := cdc.MarshalJSON(aux)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	bs.db.Set(calcAuxKey(round), auxBytes)
	BlockStoreState{Round: round}.Save(bs.db)

	// Done!
	bs.mtx.Lock()
	bs.round = round
	bs.mtx.Unlock()

	// Flush
	//fmt.Println("@@@@ save certificate ok :", certificate.Round)
	bs.db.SetSync(nil, nil)
}

// save certificate info on every vote step
// this method maybe execute more than once on every step
func (bs *BlockStore) CertificatePut(certificate agreement.Certificate) {
	round := uint64(certificate.Round)
	certificateBytes, err := cdc.MarshalJSON(certificate)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	bs.db.Set(calcCertWithStepInfoKey(round, uint64(certificate.Period), uint64(certificate.Step)), certificateBytes)

	// Flush
	bs.db.SetSync(nil, nil)
}

func (bs *BlockStore) UnauthenticatedCertificatePut(unauthenticatedCertificate agreement.UnauthenticatedCertificate) {
	round := uint64(unauthenticatedCertificate.R.Round)
	certificateBytes, err := cdc.MarshalJSON(unauthenticatedCertificate)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	bs.db.Set(calcUnauthCertWithStepInfoKey(round, uint64(unauthenticatedCertificate.R.Period), uint64(unauthenticatedCertificate.R.Step)), certificateBytes)

	// Flush
	bs.db.SetSync(nil, nil)
}

// Save persists the blockStore state to the database as JSON.
func (bsj BlockStoreState) Save(db dbm.DB) {
	bytes, err := cdc.MarshalJSON(bsj)
	if err != nil {
		panic(fmt.Sprintf("Could not marshal state bytes: %v", err))
	}
	db.SetSync(blockStoreKey, bytes)
}

// Round returns the last known contiguous block height.
func (bs *BlockStore) Round() basics.Round {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	return basics.Round(bs.round)
}

func blockNext(bs *BlockStore) (basics.Round, error) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	if bs.round > 0 {
		return basics.Round(bs.round + 1), nil
	}
	return 0, nil
}

func (bs *BlockStore) SaveAppState(state []byte, round basics.Round) {
	bs.db.SetSync(calcAppStateKey(uint64(round)), state)
}

func calcBlockHeaderKey(round uint64) []byte {
	return []byte(fmt.Sprintf("H:%v", round))
}

func calcCertKey(round uint64) []byte {
	return []byte(fmt.Sprintf("C:%v", round))
}
func calcAppStateKey(round uint64) []byte {
	return []byte(fmt.Sprintf("AS:%v", round))
}

func calcCertWithStepInfoKey(round uint64, period uint64, step uint64) []byte {
	return []byte(fmt.Sprintf("C:%v-%v-%v", round, period, step))
}

func calcUnauthCertWithStepInfoKey(round uint64, period uint64, step uint64) []byte {
	return []byte(fmt.Sprintf("UC:%v-%v-%v", round, period, step))
}

func calcAuxKey(round uint64) []byte {
	return []byte(fmt.Sprintf("A:%v", round))
}

// LoadBlock returns the block with the given height.
// If no block is found for that height, it returns nil.
func (bs *BlockStore) LoadBlock(round basics.Round) (block bookkeeping.Block, err error) {
	//var block = new(bookkeeping.Block)
	bz := bs.db.Get(calcBlockHeaderKey(uint64(round)))

	err = cdc.UnmarshalJSON(bz, &block)
	if err != nil {
		// NOTE: The existence of meta should imply the existence of the
		// block. So, make sure meta is only saved after blocks are saved.
		return block, err
	}
	return block, nil
}

func (bs *BlockStore) LoadBlockCertEncode(round basics.Round) []byte {
	certBz := bs.db.Get(calcCertKey(uint64(round)))
	return certBz
}
func (bs *BlockStore) LoadAppState(round basics.Round) (appState []byte, err error) {
	appStateBz := bs.db.Get(calcAppStateKey(uint64(round)))
	if len(appStateBz) < 1 {
		return nil, fmt.Errorf("appState not exists %d", round)
	}
	return appStateBz, nil
}

func (bs *BlockStore) LoadAuxEncode(round basics.Round) []byte {
	auxBz := bs.db.Get(calcAuxKey(uint64(round)))
	return auxBz
}

func (bs *BlockStore) RemoveBlock(round uint64) error {

	bs.db.DeleteSync(calcBlockHeaderKey(round + 1))
	bs.round = round
	return nil
}
