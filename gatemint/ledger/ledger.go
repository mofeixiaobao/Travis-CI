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
	"context"
	"fmt"
	"github.com/gatechain/gatemint/node/appinterface"
	"github.com/gatechain/gatemint/node/indexer"
	"os"
	"time"

	"github.com/gatechain/go-deadlock"

	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/logging"
	dbm "github.com/tendermint/tm-db"
)

// Ledger is a database storing the contents of the ledger.
type Ledger struct {
	// Database connections to the DBs storing blocks and tracker state.
	// We use potentially different databases to avoid SQLite contention
	// during catchup.
	trackerDBs dbPair
	blockStore *BlockStore
	// blockQ is the buffer of added blocks that will be flushed to
	// persistent storage
	blockQ *blockQueue

	log logging.Logger

	// archival determines whether the ledger keeps all blocks forever
	// (archival mode) or trims older blocks to save space (non-archival).
	archival bool

	// genesisHash stores the genesis hash for this ledger.
	genesisHash crypto.Digest

	// State-machine trackers
	accts      accountUpdates
	txDupCache *txDupCache

	bulletin    bulletin
	notifier    blockNotifier
	time        timeTracker
	metrics     metricsTracker
	proxyApps   proxyAppTracker
	txProxyTail txProxyTail

	trackers      trackerRegistry
	trackerMu     deadlock.RWMutex
	txProxyTailMu deadlock.RWMutex

	headerCache    heapLRUCache
	preCertificate agreement.Certificate

	indexer *indexer.Indexer
}

// InitState structure defines blockchain init params
type InitState struct {
	Block       bookkeeping.Block
	Accounts    map[basics.Address]basics.AccountData
	GenesisHash crypto.Digest
}

// OpenLedger creates a Ledger object, using SQLite database filenames
// based on dbPathPrefix (in-memory if dbMem is true). genesisInitState.Blocks and
// genesisInitState.Accounts specify the initial blocks and accounts to use if the
// database wasn't initialized before.
// database wasn't initialized before.
func OpenLedger(
	log logging.Logger, dbPathPrefix string, dbMem bool, genesisInitState InitState, isArchival bool, application appinterface.Application, rootDir string, genesis bookkeeping.Genesis,
) (*Ledger, error) {
	var err error
	l := &Ledger{
		log:         log,
		archival:    isArchival,
		genesisHash: genesisInitState.GenesisHash,
	}

	l.headerCache.maxEntries = 10

	defer func() {
		if err != nil {
			l.Close()
		}
	}()

	l.trackerDBs, err = openLedgerDB(dbPathPrefix, dbMem)
	//TODO add to config
	l.blockStore = initBlockStore("blockstore", "goleveldb", dbPathPrefix)

	if err != nil {
		return nil, err
	}

	err = initBlocksDB(l, []bookkeeping.Block{genesisInitState.Block}, isArchival)
	if err != nil {
		return nil, err
	}
	// Accounts are special because they get an initialization argument (initAccounts).
	initAccounts := genesisInitState.Accounts
	if initAccounts == nil {
		initAccounts = make(map[basics.Address]basics.AccountData)
	}

	l.accts.initProto = config.Consensus[genesisInitState.Block.CurrentProtocol]
	l.accts.initAccounts = initAccounts
	l.accts.accountstore = initAccountStore("accountstore", "goleveldb", dbPathPrefix)
	//TODO	tmp block与accout及app高度不一致临时
	if l.blockStore.round > l.accts.accountstore.round {
		l.blockStore.RemoveBlock(l.accts.accountstore.round)
	}
	l.InitApplication(application, genesis, rootDir)

	l.blockQ, err = bqInit(l)
	if err != nil {
		return nil, err
	}

	l.txDupCache = txDupCacheInit()

	//l.trackers.register(&l.accts)
	//l.trackers.register(&l.txTail)
	//l.trackers.register(&l.txProxyTail)
	l.trackers.register(&l.bulletin)
	l.trackers.register(&l.notifier)
	l.trackers.register(&l.time)
	l.trackers.register(&l.metrics)
	l.trackers.register(&l.proxyApps)

	err = l.trackers.loadFromDisk(l)
	if err != nil {
		return nil, err
	}

	// Check that the genesis hash, if present, matches.

	latest := l.blockStore.Round()

	latestBlock, err := l.blockStore.LoadBlock(latest)

	hdr := latestBlock.BlockHeader
	if err != nil {
		return nil, err
	}

	params := config.Consensus[hdr.CurrentProtocol]
	if params.SupportGenesisHash && hdr.GenesisHash != genesisInitState.GenesisHash {
		return nil, fmt.Errorf(
			"latest block %d genesis hash %v does not match expected genesis hash %v",
			latest, hdr.GenesisHash, genesisInitState.GenesisHash,
		)
	}

	if err != nil {
		return nil, err
	}

	return l, nil
}

func initBlockStore(storeName string, dbType string, dbDir string) *BlockStore {
	db := dbm.NewDB(storeName, dbm.DBBackendType(dbType), dbDir)
	return NewBlockStore(db)
}
func initAccountStore(storeName string, dbType string, dbDir string) *AccountStore {
	db := dbm.NewDB(storeName, dbm.DBBackendType(dbType), dbDir)
	return NewAccountStore(db)
}

func openLedgerDB(dbPathPrefix string, dbMem bool) (trackerDBs dbPair, err error) {
	// Backwards compatibility: we used to store both blocks and tracker
	// state in a single SQLite db file.
	var trackerDBFilename string
	//var blockDBFilename string

	commonDBFilename := dbPathPrefix + ".sqlite"
	if !dbMem {
		_, err = os.Stat(commonDBFilename)
	}

	if !dbMem && os.IsNotExist(err) {
		// No common file, so use two separate files for blocks and tracker.
		trackerDBFilename = dbPathPrefix + ".tracker.sqlite"
		//blockDBFilename = dbPathPrefix + ".block.sqlite"
	} else if err == nil {
		// Legacy common file exists (or testing in-memory, where performance
		// doesn't matter), use same database for everything.
		trackerDBFilename = commonDBFilename
		//blockDBFilename = commonDBFilename
	} else {
		return
	}

	trackerDBs, err = dbOpen(trackerDBFilename, dbMem)
	if err != nil {
		return
	}

	//blockDBs, err = dbOpen(blockDBFilename, dbMem)
	//if err != nil {
	//	return
	//}
	return
}

// initLedgerDB performs DB initialization:
// - creates and populates it with genesis blocks
// - ensures DB is in good shape for archival mode and resets it if not
// - does nothing if everything looks good
func initBlocksDB(l *Ledger, initBlocks []bookkeeping.Block, isArchival bool) (err error) {
	//err = blockInit(tx, initBlocks)
	//if err != nil {
	//	return err
	//}
	l.blockStore.BlockInit(initBlocks)

	// in archival mode check if DB contains all blocks up to the latest
	//if isArchival {
	//	earliest, err := blockEarliest(tx)
	//	if err != nil {
	//		return err
	//	}
	//
	//	// Detect possible problem - archival node needs all block but have only subsequence of them
	//	// So reset the DB and init it again
	//	if earliest != basics.Round(0) {
	//		l.log.Warnf("resetting blocks DB (earliest block is %v)", earliest)
	//		err := blockResetDB(tx)
	//		if err != nil {
	//			return err
	//		}
	//		err = blockInit(tx, initBlocks)
	//		if err != nil {
	//			return err
	//		}
	//	}
	//}
	return nil
}

// Close reclaims resources used by the ledger (namely, the database connection
// and goroutines used by trackers).
func (l *Ledger) Close() {
	l.trackerDBs.close()
	l.trackers.close()
	l.txProxyTail.close()
	if l.blockQ != nil {
		l.blockQ.close()
		l.blockQ = nil
	}
	l.txDupCache.close()
}

// RegisterBlockListeners registers listeners that will be called when a
// new block is added to the ledger.
func (l *Ledger) RegisterBlockListeners(listeners []BlockListener) {
	l.notifier.register(listeners)
}

// UpdateLedgerAfterIndex
func (l *Ledger) UpdateLedgerAfterIndex() error {
	return l.txProxyTail.loadFromDiskAfterIndexer(l)
}

// notifyCommit informs the trackers that all blocks up to r have been
// written to disk.  Returns the minimum block number that must be kept
// in the database.
func (l *Ledger) notifyCommit(r basics.Round) basics.Round {
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	l.txProxyTailMu.Lock()
	l.txProxyTail.committedUpTo(r)
	l.txProxyTailMu.Unlock()

	minToSave := l.trackers.committedUpTo(r)
	// noneedto execute txProxyTail
	//l.txProxyTail.committedUpTo(r)
	if l.archival {
		// Do not forget any blocks.
		minToSave = 0
	}

	return minToSave
}

// GetAssetCreatorForRound looks up the asset creator given the numerical asset
// ID. This is necessary so that we can retrieve the AssetParams from the
// creator's balance record.

// GetAssetCreator is like GetAssetCreatorForRound, but for the latest round
// and race free with respect to ledger.Latest()
func (l *Ledger) GetAssetCreator(assetIdx basics.AssetIndex) (basics.Address, error) {
	//not support
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return basics.Address{}, nil
}

// ListAssets takes a maximum asset index and maximum result length, and
// returns up to that many asset AssetIDs from the database where asset id is
// less than or equal to the maximum.
func (l *Ledger) ListAssets(maxAssetIdx basics.AssetIndex, maxResults uint64) (results []basics.AssetLocator, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return nil, nil
}

// Lookup uses the accounts tracker to return the account state for a
// given account in a particular round.  The account values reflect
// the changes of all blocks up to and including rnd.
func (l *Ledger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	// Intentionally apply (pending) rewards up to rnd.
	data, err := l.accts.lookup(addr[:])
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// LookupWithoutRewards is like Lookup but does not apply pending rewards up
// to the requested round rnd.
func (l *Ledger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	data, err := l.accts.lookup(addr[:])
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// Totals returns the totals of all accounts at the end of round rnd.
func (l *Ledger) Totals(rnd basics.Round) (AccountTotals, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.totals(rnd)
}

func (l *Ledger) RecordAndTotals(r basics.Round, addr basics.Address) (AccountTotals, basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	total, err := l.accts.totals(r)
	if err != nil {
		return AccountTotals{}, basics.AccountData{}, err
	}
	accountData, err := l.accts.lookup(addr[:])
	if err != nil {
		return AccountTotals{}, basics.AccountData{}, err
	}
	return total, accountData, nil
}

// Deprecated
func (l *Ledger) isDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txProxyTail.isDup(currentProto, current, firstValid, lastValid, txid, txl)
}

func (l *Ledger) CheckDup(lastValid basics.Round, txid transactions.Txid) (bool, error) {
	l.txProxyTailMu.RLock()
	defer l.txProxyTailMu.RUnlock()

	return l.txProxyTail.checkDup(lastValid, txid)
}

func (l *Ledger) GetTxValidInfo(tx transactions.Tx) (transactions.TxWithValidInfo, error) {
	responseGetTxValidInfo := l.proxyApps.application.GetTxValidInfo(appinterface.RequestGetTxValidInfo{Tx: tx})
	if responseGetTxValidInfo.IsErr() {
		return transactions.TxWithValidInfo{}, fmt.Errorf("get tx valid info error: %v", responseGetTxValidInfo.Response.Log)
	}
	return transactions.TxWithValidInfo{
		TxInfo:          tx,
		FirstValidRound: basics.Round(responseGetTxValidInfo.FirstValidRound),
		LastValidRound:  basics.Round(responseGetTxValidInfo.LastValidRound),
		Fee:             responseGetTxValidInfo.Fee,
	}, nil

}

//func (l *Ledger) IsNeedRefreshCache(indexRound basics.Round, ledgerRound basics.Round) (bool, bool, basics.Round) {
//	return l.txDupCache.isNeedRefreshCache(indexRound, ledgerRound)
//}
//
//func (l *Ledger) AddBlockToDupCache(round basics.Round, blk bookkeeping.Block) error {
//	return l.txDupCache.addBlock(round, blk)
//}
//
//func (l *Ledger) DeleteBlockCache(indexRound basics.Round) error {
//	return l.txDupCache.deleteBlock(indexRound)
//}
//
//func (l *Ledger) IsTxDupCached(queryTx transactions.Tx) (bool, basics.Round) {
//	return l.txDupCache.isTxCached(queryTx)
//}

// GetRoundTxIds returns a map of the transactions ids that we have for the given round
func (l *Ledger) GetRoundTxIds(rnd basics.Round) (txMap map[transactions.Txid]bool) {
	l.txProxyTailMu.RLock()
	defer l.txProxyTailMu.RUnlock()

	return l.txProxyTail.getRoundTxIds(rnd)
}

// Latest returns the latest known block round added to the ledger.
func (l *Ledger) Latest() basics.Round {
	return l.blockQ.latest()
}

// LatestCommitted returns the last block round number written to
// persistent storage.  This block, and all previous blocks, are
// guaranteed to be available after a crash.
func (l *Ledger) LatestCommitted() basics.Round {
	return l.blockQ.latestCommitted()
}

func (l *Ledger) blockAux(rnd basics.Round) (bookkeeping.Block, evalAux, error) {
	return l.blockQ.getBlockAux(rnd)
}

// Block returns the block for round rnd.
func (l *Ledger) Block(rnd basics.Round) (blk bookkeeping.Block, err error) {
	return l.blockQ.getBlock(rnd)
}

// AppState returns the AppState of the block for round rnd.
func (l *Ledger) AppState(rnd basics.Round) (appState []byte, err error) {
	appState, err = l.blockStore.LoadAppState(rnd)
	return
}

// BlockHdr returns the BlockHeader of the block for round rnd.
func (l *Ledger) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	value, exists := l.headerCache.Get(rnd)
	if exists {
		blk = value.(bookkeeping.BlockHeader)
		return
	}

	blk, err = l.blockQ.getBlockHdr(rnd)
	if err == nil {
		l.headerCache.Put(rnd, blk)
	}
	return
}

// EncodedBlockCert returns the encoded block and the corresponding encoded certificate of the block for round rnd.
func (l *Ledger) EncodedBlockCert(rnd basics.Round) (blk []byte, cert []byte, err error) {
	return l.blockQ.getEncodedBlockCert(rnd)
}

func (l *Ledger) updatePreCertificate(certificate agreement.Certificate) {
	l.preCertificate = certificate
}

func (l *Ledger) ReadPreCertificate() agreement.Certificate {
	return l.preCertificate
}

// BlockCert returns the block and the certificate of the block for round rnd.
func (l *Ledger) BlockCert(rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	return l.blockQ.getBlockCert(rnd)
}

// AddBlock adds a new block to the ledger.  The block is stored in an
// in-memory queue and is written to the disk in the background.  An error
// is returned if this is not the expected next block number.
func (l *Ledger) AddBlock(blk bookkeeping.Block, cert agreement.Certificate) error {
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.
	updates, aux, err := l.eval(context.Background(), blk, nil, false, nil, nil)
	if err != nil {
		return err
	}

	vb := ValidatedBlock{
		blk:   blk,
		delta: updates,
		aux:   aux,
	}

	return l.AddValidatedBlock(vb, cert)
}

// AddValidatedBlock adds a new block to the ledger, after the block has
// been validated by calling Ledger.Validate().  This saves the cost of
// having to re-compute the effect of the block on the ledger state, if
// the block has previously been validated.  Otherwise, AddValidatedBlock
// behaves like AddBlock.
func (l *Ledger) AddValidatedBlock(vb ValidatedBlock, cert agreement.Certificate) error {
	// Grab the tracker lock first, to ensure newBlock() is notified before committedUpTo().
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	err := l.blockQ.putBlock(vb.blk, cert, vb.aux)
	if err != nil {
		return err
	}

	// update preCertificate
	l.preCertificate = cert

	// attention!! txProxyTail must execute before trackers, otherwise checkDup will not right
	l.txProxyTailMu.Lock()
	l.txProxyTail.newBlock(vb.blk, vb.delta)
	l.txProxyTailMu.Unlock()

	l.trackers.newBlock(vb.blk, vb.delta)

	return nil
}

// WaitForCommit waits until block r (and block before r) are durably
// written to disk.
func (l *Ledger) WaitForCommit(r basics.Round) {
	l.blockQ.waitCommit(r)
}

// Wait returns a channel that closes once a given round is stored
// durably in the ledger.
// When <-l.Wait(r) finishes, ledger is guaranteed to have round r,
// and will not lose round r after a crash.
// This makes it easy to use in a select{} statement.
func (l *Ledger) Wait(r basics.Round) chan struct{} {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.bulletin.Wait(r)
}

// Timestamp uses the timestamp tracker to return the timestamp
// from block r.
func (l *Ledger) Timestamp(r basics.Round) (int64, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.time.timestamp(r)
}

// AllBalances returns a map of every account balance as of round rnd.
//func (l *Ledger) AllBalances(rnd basics.Round) (map[basics.Address]basics.AccountData, error) {
//	l.trackerMu.RLock()
//	defer l.trackerMu.RUnlock()
//	return l.accts.allBalances(rnd)
//}

// GenesisHash returns the genesis hash for this ledger.
func (l *Ledger) GenesisHash() crypto.Digest {
	return l.genesisHash
}

// ledgerForTracker methods
func (l *Ledger) trackerDB() dbPair {
	return l.trackerDBs
}

func (l *Ledger) trackerLog() logging.Logger {
	return l.log
}

func (l *Ledger) trackerEvalVerified(blk bookkeeping.Block, aux evalAux) (StateDelta, error) {
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.
	delta, _, err := l.eval(context.Background(), blk, &aux, false, nil, nil)
	return delta, err
}

// save block Certificate info
// this method maybe execute more than once on every step
func (l *Ledger) CertificateSave(certificate agreement.Certificate) {
	l.blockStore.CertificatePut(certificate)
}

func (l *Ledger) CertificateSelect(round basics.Round) (cert agreement.Certificate, err error) {
	//certBytes := l.blockStore.LoadBlockCertEncode(round)
	//err = cdc.UnmarshalJSON(certBytes, &cert)
	//if err != nil {
	//	fmt.Println("@@@@error certificate is nil:", round)
	//	return
	//} else {
	//	fmt.Println("@@@@error certificate is not nil:", round)
	//}
	_, cert, err = l.blockQ.getBlockCert(round)
	//if err != nil{
	//	fmt.Println("@@@@error certificate is nil:", round)
	//	return
	//} else {
	//	fmt.Println("@@@@error certificate is not nil:", round)
	//}
	return
}

// save block agreement vote info
func (l *Ledger) UnauthenticatedCertificateSave(UnauthenticatedCertificate agreement.UnauthenticatedCertificate) {
	l.blockStore.UnauthenticatedCertificatePut(UnauthenticatedCertificate)
}

func (l *Ledger) InitApplication(application appinterface.Application, genesis bookkeeping.Genesis, rootDir string) error {
	l.proxyApps = proxyAppTracker{application: application, accts: &l.accts, blockstore: l.blockStore, txIndexAvailable: false}
	//l.trackers.register(&l.proxyApps)
	if l.blockStore.Round() == 0 {
		genalloc := make(map[basics.Address]basics.AccountData)
		var accts []appinterface.AccountDelta
		for _, entry := range genesis.Allocation {
			addr, err := basics.UnmarshalChecksumAddress(entry.Address)
			accts = append(accts, appinterface.AccountDelta{Power: entry.State.Power.Raw, Address: addr[:]})
			if err != nil {
				return err
			}
			_, present := genalloc[addr]
			if present {
				err = fmt.Errorf("repeated allocation to %s", entry.Address)
				return err
			}
			genalloc[addr] = entry.State
		}
		reqInitChain := appinterface.RequestInitChain{ChainId: genesis.ID(), Time: time.Unix(genesis.Timestamp, 0), Accts: accts}
		reqInitChain.AppStateBytes = genesis.ProxyAppContent
		res := l.proxyApps.application.InitChain(reqInitChain)
		if res.IsOK() {
			initAccounts := make(map[basics.Address]basics.AccountData)
			for _, account := range res.Accts {
				addr := basics.ConverAddress(account.Address)
				newAccount := genalloc[addr]
				newAccount.Power = basics.Power{Raw: account.Power}
				initAccounts[addr] = newAccount
			}
			err := l.accts.accountstore.Init(initAccounts)
			if err != nil {
				return err
			}
		} else {
			err := fmt.Errorf("cannot init app by initchain")
			return err
		}

		//l.accts.accountstore.Init()

	}
	//err := l.proxyApps.loadFromDisk(l)
	//if err != nil {
	//	return err
	//}
	return nil
}

func (l *Ledger) SetIndexer(indexer *indexer.Indexer) {
	l.indexer = indexer
}

func (l *Ledger) GetApplication() appinterface.Application {
	return l.proxyApps.application
}

// A txlease is a transaction (sender, lease) pair which uniquely specifies a
// transaction lease.
type txlease struct {
	sender basics.Address
	lease  [32]byte
}

func (l *Ledger) GetAccts() string {
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()
	str := l.accts.iterator()
	return str
}

func (l *Ledger) RegisterTxIndex(store *indexer.IndexStore, available bool) error {
	l.proxyApps.indexStore = store
	l.proxyApps.txIndexAvailable = available
	return nil
}
