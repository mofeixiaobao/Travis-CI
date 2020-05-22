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

// Package node is the Algorand node itself, with functions exposed to the frontend
package node

import (
	"context"
	"fmt"
	"github.com/gatechain/gatemint/node/appinterface"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/agreement/gossip"
	"github.com/gatechain/gatemint/catchup"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data"
	"github.com/gatechain/gatemint/data/account"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/data/pools"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/gatemint/data/transactions/verify"
	"github.com/gatechain/gatemint/ledger"
	"github.com/gatechain/gatemint/network"
	"github.com/gatechain/gatemint/node/indexer"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/gatemint/rpcs"
	"github.com/gatechain/gatemint/util/db"
	"github.com/gatechain/gatemint/util/execpool"
	"github.com/gatechain/gatemint/util/metrics"
	"github.com/gatechain/gatemint/util/timers"
	"github.com/gatechain/go-deadlock"
	"github.com/gatechain/logging"
)

const participationKeyCheckSecs = 60

// StatusReport represents the current basic status of the node
type StatusReport struct {
	LastRound             basics.Round
	LastVersion           protocol.ConsensusVersion
	NextVersion           protocol.ConsensusVersion
	NextVersionRound      basics.Round
	NextVersionSupported  bool
	LastRoundTimestamp    time.Time
	SynchronizingTime     time.Duration
	CatchupTime           time.Duration
	HasSyncedSinceStartup bool
	Step                  uint64
	Period                uint64
	ZeroTimeStamp         time.Time
	Deadline              time.Duration
	FastRecoveryDeadline  time.Duration
}

// TimeSinceLastRound returns the time since the last block was approved (locally), or 0 if no blocks seen
func (status StatusReport) TimeSinceLastRound() time.Duration {
	if status.LastRoundTimestamp.IsZero() {
		return time.Duration(0)
	}

	return time.Since(status.LastRoundTimestamp)
}

// GatemintFullNode specifies and implements a full Gatemint node.
type GatemintFullNode struct {
	nodeContextData

	mu        deadlock.Mutex
	ctx       context.Context
	cancelCtx context.CancelFunc
	config    config.Local

	ledger    *data.Ledger
	net       network.GossipNode
	phonebook *network.ThreadsafePhonebook

	transactionPool *pools.TransactionPool
	txHandler       *data.TxHandler
	accountManager  *data.AccountManager
	feeTracker      *pools.FeeTracker

	gatemintService *agreement.Service
	syncer          *catchup.Service

	indexer *indexer.Indexer

	rootDir     string
	genesisID   string
	genesisHash crypto.Digest

	log logging.Logger

	lastRoundTimestamp    time.Time
	hasSyncedSinceStartup bool

	txPoolSyncer *rpcs.TxSyncer

	cryptoPool                         execpool.ExecutionPool
	lowPriorityCryptoVerificationPool  execpool.BacklogPool
	highPriorityCryptoVerificationPool execpool.BacklogPool

	ledgerService    *rpcs.LedgerService
	wsFetcherService *rpcs.WsFetcherService // to handle inbound gossip msgs for fetching over gossip

	oldKeyDeletionNotify chan struct{}

	application appinterface.Application
}

// TxnWithStatus represents information about a single transaction,
// in particular, whether it has appeared in some block yet or not,
// and whether it was kicked out of the txpool due to some error.
type TxnWithStatus struct {
	Txn transactions.SignedTxn

	// Zero indicates no confirmation
	ConfirmedRound basics.Round

	// PoolError indicates that the transaction was kicked out of this
	// node's transaction pool (and specifies why that happened).  An
	// empty string indicates the transaction wasn't kicked out of this
	// node's txpool due to an error.
	PoolError string

	// ApplyData is the transaction.ApplyData, if committed.
	ApplyData transactions.ApplyData
}

// MakeFull sets up an Gatemint full node
// (i.e., it returns a node that participates in consensus)
func MakeFull(log logging.Logger, rootDir string, cfg config.Local, phonebookDir string, genesis bookkeeping.Genesis,
	application appinterface.Application) (*GatemintFullNode, error) {
	node := new(GatemintFullNode)
	node.rootDir = rootDir
	node.config = cfg
	node.log = log.With("name", cfg.NetAddress)
	node.genesisID = genesis.ID()
	node.genesisHash = crypto.HashObj(genesis)
	node.phonebook = network.MakeThreadsafePhonebook()
	node.application = application
	addrs, err := config.LoadPhonebook(phonebookDir)
	if err != nil {
		log.Debugf("Cannot load static phonebook: %v", err)
	}
	node.phonebook.ReplacePeerList(addrs)

	// tie network, block fetcher, and agreement services together
	p2pNode, err := network.NewWebsocketNetwork(node.log, node.config, node.phonebook, genesis.ID(), genesis.Network)
	if err != nil {
		log.Errorf("could not create websocket node: %v", err)
		return nil, err
	}
	p2pNode.SetPrioScheme(node)
	node.net = p2pNode
	node.accountManager = data.MakeAccountManager(log)

	accountListener := makeTopAccountListener(log)

	// load stored data
	genesisDir := filepath.Join(rootDir, genesis.ID())
	ledgerPathnamePrefix := filepath.Join(genesisDir, config.LedgerFilenamePrefix)

	// create initial ledger, if it doesn't exist
	os.Mkdir(genesisDir, 0700)
	var genalloc data.GenesisBalances
	genalloc, err = bootstrapData(genesis, log)
	if err != nil {
		log.Errorf("Cannot load genesis allocation: %v", err)
		return nil, err
	}

	node.cryptoPool = execpool.MakePool(node)
	node.lowPriorityCryptoVerificationPool = execpool.MakeBacklog(node.cryptoPool, 2*node.cryptoPool.GetParallelism(), execpool.LowPriority, node)
	node.highPriorityCryptoVerificationPool = execpool.MakeBacklog(node.cryptoPool, 2*node.cryptoPool.GetParallelism(), execpool.HighPriority, node)
	node.ledger, err = data.LoadLedger(node.log, ledgerPathnamePrefix, false, genesis.Proto, genalloc, node.genesisID, node.genesisHash, []ledger.BlockListener{}, cfg.Archival, application, rootDir, genesis)
	if err != nil {
		log.Errorf("Cannot initialize ledger (%s): %v", ledgerPathnamePrefix, err)
		return nil, err
	}

	node.transactionPool = pools.MakeTransactionPool(node.ledger.Ledger, cfg)

	blockListeners := []ledger.BlockListener{
		node.transactionPool,
		node,
	}

	if node.config.EnableTopAccountsReporting {
		blockListeners = append(blockListeners, &accountListener)
	}
	node.ledger.RegisterBlockListeners(blockListeners)
	node.txHandler = data.MakeTxHandler(node.transactionPool, node.ledger, node.net, node.genesisID, node.genesisHash, node.lowPriorityCryptoVerificationPool)
	node.feeTracker, err = pools.MakeFeeTracker()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// Indexer setup
	if cfg.IsIndexerActive && cfg.Archival {
		var indexStore *indexer.IndexStore
		node.indexer, indexStore, err = indexer.MakeIndexer(genesisDir, node.ledger, false)
		if err != nil {
			logging.Base().Errorf("failed to make indexer -  %v", err)
			return nil, err
		}
		node.ledger.Ledger.RegisterTxIndex(indexStore, cfg.IsIndexerActive)
	}

	// set ledger indexer
	node.ledger.SetIndexer(node.indexer)

	err = node.ledger.LoadLedgerAfterIndex()
	if err != nil {
		log.Errorf("Cannot initialize ledger (%s), because LoadLedgerAfterIndex error: %v", ledgerPathnamePrefix, err)
		return nil, err
	}

	node.ledgerService = rpcs.RegisterLedgerService(cfg, node.ledger, p2pNode, node.genesisID)
	node.wsFetcherService = rpcs.RegisterWsFetcherService(node.log, p2pNode)
	rpcs.RegisterTxService(node.transactionPool, p2pNode, node.genesisID, cfg.TxPoolSize, cfg.TxSyncServeResponseSize)

	crashPathname := filepath.Join(genesisDir, config.CrashFilename)
	crashAccess, err := db.MakeAccessor(crashPathname, false, false)
	if err != nil {
		log.Errorf("Cannot load crash data: %v", err)
		return nil, err
	}

	blockFactory := makeBlockFactory(node.ledger, node.transactionPool, node.config.EnableProcessBlockStats, node.highPriorityCryptoVerificationPool)
	blockValidator := blockValidatorImpl{l: node.ledger, tp: node.transactionPool, verificationPool: node.highPriorityCryptoVerificationPool}
	agreementLedger := agreementLedger{Ledger: node.ledger, ff: rpcs.MakeNetworkFetcherFactory(node.net, blockQueryPeerLimit, node.wsFetcherService), n: node.net}

	node.syncer = catchup.MakeService(node.log, node.config, p2pNode, node.ledger, node.wsFetcherService, blockAuthenticatorImpl{Ledger: node.ledger, AsyncVoteVerifier: agreement.MakeAsyncVoteVerifier(node.lowPriorityCryptoVerificationPool)})

	agreementParameters := agreement.Parameters{
		Logger:         log,
		Accessor:       crashAccess,
		Clock:          timers.MakeMonotonicClock(time.Now()),
		Local:          node.config,
		Network:        gossip.WrapNetwork(node.net),
		Ledger:         agreementLedger,
		BlockFactory:   blockFactory,
		BlockValidator: blockValidator,
		KeyManager:     node.accountManager,
		RandomSource:   node,
		BacklogPool:    node.highPriorityCryptoVerificationPool,
		Catchup:        node.syncer,
	}
	node.gatemintService = agreement.MakeService(agreementParameters, rootDir)

	node.txPoolSyncer = rpcs.MakeTxSyncer(node.transactionPool, node.net, node.txHandler.SolicitedTxHandler(), time.Duration(cfg.TxSyncIntervalSeconds)*time.Second, time.Duration(cfg.TxSyncTimeoutSeconds)*time.Second, cfg.TxSyncServeResponseSize)

	err = node.loadParticipationKeys()
	if err != nil {
		log.Errorf("Cannot load participation keys: %v", err)
		return nil, err
	}

	node.oldKeyDeletionNotify = make(chan struct{}, 1)
	return node, err
}

func bootstrapData(genesis bookkeeping.Genesis, log logging.Logger) (data.GenesisBalances, error) {
	genalloc := make(map[basics.Address]basics.AccountData)
	for _, entry := range genesis.Allocation {
		addr, err := basics.UnmarshalChecksumAddress(entry.Address)
		if err != nil {
			log.Errorf("Cannot parse genesis addr %s: %v", entry.Address, err)
			return data.GenesisBalances{}, err
		}

		_, present := genalloc[addr]
		if present {
			err = fmt.Errorf("repeated allocation to %s", entry.Address)
			log.Error(err)
			return data.GenesisBalances{}, err
		}

		genalloc[addr] = entry.State
	}

	//feeSink, err := basics.UnmarshalChecksumAddress(genesis.FeeSink)
	//if err != nil {
	//	log.Errorf("Cannot parse fee sink addr %s: %v", genesis.FeeSink, err)
	//	return data.GenesisBalances{}, err
	//}
	//
	//rewardsPool, err := basics.UnmarshalChecksumAddress(genesis.RewardsPool)
	//if err != nil {
	//	log.Errorf("Cannot parse rewards pool addr %s: %v", genesis.RewardsPool, err)
	//	return data.GenesisBalances{}, err
	//}

	return data.MakeTimestampedGenesisBalances(genalloc, genesis.Timestamp), nil
}

// Config returns a copy of the node's Local configuration
func (node *GatemintFullNode) Config() config.Local {
	return node.config
}

// Start the node: connect to peers and run the agreement service while obtaining a lock. Doesn't wait for initial sync.
func (node *GatemintFullNode) Start() {
	node.mu.Lock()
	defer node.mu.Unlock()

	// start accepting connections
	node.net.Start()
	node.config.NetAddress, _ = node.net.Address()

	node.syncer.Start()
	node.gatemintService.Start()
	node.txPoolSyncer.Start(node.syncer.InitialSyncDone)
	node.ledgerService.Start()
	node.txHandler.Start()

	// Set up a context we can use to cancel goroutines on Stop()
	ctx, cancel := context.WithCancel(context.Background())
	node.ctx = ctx
	node.cancelCtx = cancel

	//// start indexer
	//if idx, err := node.Indexer(); err == nil {
	//	err := idx.Start()
	//	if err != nil {
	//		node.log.Errorf("indexer failed to start, turning it off - %v", err)
	//		node.config.IsIndexerActive = false
	//	}
	//	node.log.Info("Indexer was started successfully")
	//} else {
	//	node.log.Infof("Indexer is not available - %v", err)
	//}

	// Periodically check for new participation keys
	go node.checkForParticipationKeys()

	go node.txPoolGaugeThread()
	// Delete old participation keys
	go node.oldKeyDeletionThread()

	// TODO re-enable with configuration flag post V1
	//go logging.UsageLogThread(node.ctx, node.log, 100*time.Millisecond, nil)
}

// ListeningAddress retrieves the node's current listening address, if any.
// Returns true if currently listening, false otherwise.
func (node *GatemintFullNode) ListeningAddress() (string, bool) {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.net.Address()
}

// Stop stops running the node. Once a node is closed, it can never start again.
func (node *GatemintFullNode) Stop() {
	node.mu.Lock()
	defer node.mu.Unlock()

	node.net.ClearHandlers()

	node.txHandler.Stop()
	node.net.Stop()
	node.gatemintService.Shutdown()
	node.syncer.Stop()
	node.txPoolSyncer.Stop()
	node.ledgerService.Stop()
	node.highPriorityCryptoVerificationPool.Shutdown()
	node.lowPriorityCryptoVerificationPool.Shutdown()
	node.cryptoPool.Shutdown()
	node.cancelCtx()

	if node.indexer != nil {
		node.indexer.Shutdown()
	}
}

// note: unlike the other two functions, this accepts a whole filename
func (node *GatemintFullNode) GetExistingPartHandle(filename string) (db.Accessor, error) {
	filename = filepath.Join(node.rootDir, node.genesisID, filename)

	_, err := os.Stat(filename)
	if err == nil {
		return db.MakeErasableAccessor(filename)
	}
	return db.Accessor{}, err
}

// Ledger exposes the node's ledger handle to the algod API code
func (node *GatemintFullNode) Ledger() *data.Ledger {
	return node.ledger
}

func (node *GatemintFullNode) Net() network.GossipNode {
	return node.net
}

func (node *GatemintFullNode) TransactionPool() *pools.TransactionPool {
	return node.transactionPool
}

// BroadcastSignedTxGroup broadcasts a transaction group that has already been signed.
func (node *GatemintFullNode) BroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error {
	lastRound := node.ledger.Latest()
	b, err := node.ledger.BlockHdr(lastRound)
	if err != nil {
		node.log.Errorf("could not get block header from last round %v: %v", lastRound, err)
	}
	spec := transactions.SpecialAddresses{
		FeeSink:     b.FeeSink,
		RewardsPool: b.RewardsPool,
	}
	proto := config.Consensus[b.CurrentProtocol]

	for _, tx := range txgroup {
		err = verify.Txn(&tx, spec, proto)
		if err != nil {
			node.log.Warnf("malformed transaction: %v - transaction was %+v", err, tx)
			return err
		}
	}
	err = node.transactionPool.Remember(txgroup)
	if err != nil {
		node.log.Infof("rejected by local pool: %v - transaction group was %+v", err, txgroup)
		return err
	}

	var enc []byte
	var txids []transactions.Txid
	for _, tx := range txgroup {
		enc = append(enc, protocol.Encode(tx)...)
		txids = append(txids, tx.ID())
	}
	err = node.net.Broadcast(context.TODO(), protocol.TxnTag, enc, true, nil)
	if err != nil {
		node.log.Infof("failure broadcasting transaction to network: %v - transaction group was %+v", err, txgroup)
		return err
	}
	node.log.Infof("Sent signed tx group with IDs %v", txids)
	return nil
}

// BroadcastSignedTxGroup broadcasts a transaction group that has already been signed.
func (node *GatemintFullNode) BroadcastProxyTx(tx transactions.Tx) (err error) {

	// sign verify not need
	err = node.transactionPool.RememberSingle(tx)
	if err != nil {
		node.log.Infof("rejected by local pool: %v - transaction group was %+v", err, tx)
		return err
	}

	err = node.net.Broadcast(context.TODO(), protocol.ProxyTxnTag, tx, true, nil)
	if err != nil {
		node.log.Infof("failure broadcasting transaction to network: %v - transaction group was %+v", err, tx)
		return err
	}
	//node.log.Infof("Sent signed tx group with IDs %v")
	return nil
}

// ListTxns returns SignedTxns associated with a specific account in a range of Rounds (inclusive).
// TxnWithStatus returns the round in which a particular transaction appeared,
// since that information is not part of the SignedTxn itself.
func (node *GatemintFullNode) ListTxns(addr basics.Address, minRound basics.Round, maxRound basics.Round) ([]TxnWithStatus, error) {
	result := make([]TxnWithStatus, 0)
	for r := minRound; r <= maxRound; r++ {
		h, err := node.ledger.AddressTxns(addr, r)
		if err != nil {
			return nil, err
		}
		for _, tx := range h {
			result = append(result, TxnWithStatus{
				Txn:            tx.SignedTxn,
				ConfirmedRound: r,
				ApplyData:      tx.ApplyData,
			})
		}
	}
	return result, nil
}

// GetTransaction looks for the required txID within with a specific account withing a range of rounds (inclusive) and
// returns the SignedTxn and true iff it finds the transaction.
func (node *GatemintFullNode) GetTransaction(addr basics.Address, txID transactions.Txid, minRound basics.Round, maxRound basics.Round) (TxnWithStatus, bool) {
	// start with the most recent round, and work backwards:
	// this will abort early if it hits pruned rounds
	if maxRound < minRound {
		return TxnWithStatus{}, false
	}
	r := maxRound
	for {
		h, err := node.ledger.AddressTxns(addr, r)
		if err != nil {
			return TxnWithStatus{}, false
		}
		for _, tx := range h {
			if tx.ID() == txID {
				return TxnWithStatus{
					Txn:            tx.SignedTxn,
					ConfirmedRound: r,
					ApplyData:      tx.ApplyData,
				}, true
			}
		}
		if r == minRound {
			break
		}
		r--
	}
	return TxnWithStatus{}, false
}

// GetPendingTransaction looks for the required txID in the recent ledger
// blocks, in the txpool, and in the txpool's status cache.  It returns
// the SignedTxn (with status information), and a bool to indicate if the
// transaction was found.
func (node *GatemintFullNode) GetPendingTransaction(txID transactions.Txid) (res TxnWithStatus, found bool) {
	// We need to check both the pool and the ledger's blocks.
	// If the transaction is found in a committed block, that
	// takes precedence.  But we check the pool first, because
	// otherwise there could be a race between the pool and the
	// ledger, where the block wasn't in the ledger at first,
	// but by the time we check the pool, it's not there either
	// because it committed.

	// The default return value is found=false, which is
	// appropriate if the transaction isn't found anywhere.

	// Check if it's in the pool or evicted from the pool.
	tx, txErr, found := node.transactionPool.Lookup(txID)
	if found {
		res = TxnWithStatus{
			Txn:            tx,
			ConfirmedRound: 0,
			PoolError:      txErr,
		}
		found = true

		// Keep looking in the ledger..
	}

	var maxLife basics.Round
	latest := node.ledger.Latest()
	proto, err := node.ledger.ConsensusParams(latest)
	if err == nil {
		maxLife = basics.Round(proto.MaxTxnLife)
	} else {
		node.log.Errorf("node.GetPendingTransaction: cannot get consensus params for latest round %v", latest)
	}
	maxRound := latest
	minRound := maxRound.SubSaturate(maxLife)

	for r := minRound; r <= maxRound; r++ {
		tx, found, err := node.ledger.LookupTxid(txID, r)
		if err != nil || !found {
			continue
		}
		return TxnWithStatus{
			Txn:            tx.SignedTxn,
			ConfirmedRound: r,
			ApplyData:      tx.ApplyData,
		}, true
	}

	// Return whatever we found in the pool (if anything).
	return
}

// Status returns a StatusReport structure reporting our status as Active and with our ledger's LastRound
func (node *GatemintFullNode) Status() (s StatusReport, err error) {
	s.LastRound = node.ledger.Latest()
	b, err := node.ledger.BlockHdr(s.LastRound)
	if err != nil {
		return
	}

	node.mu.Lock()
	defer node.mu.Unlock()

	s.LastVersion = b.CurrentProtocol
	s.NextVersion, s.NextVersionRound, s.NextVersionSupported = b.NextVersionInfo()
	s.SynchronizingTime = node.syncer.SynchronizingTime()
	s.LastRoundTimestamp = node.lastRoundTimestamp
	s.CatchupTime = node.syncer.SynchronizingTime()
	s.HasSyncedSinceStartup = node.hasSyncedSinceStartup

	s.Period = uint64(node.gatemintService.GetPlayer().Period)
	s.Step = uint64(node.gatemintService.GetPlayer().Step)
	s.ZeroTimeStamp = node.gatemintService.GetPlayer().ZeroTimeStamp
	s.Deadline = node.gatemintService.GetPlayer().Deadline
	s.FastRecoveryDeadline = node.gatemintService.GetPlayer().FastRecoveryDeadline
	return
}

// GenesisID returns the ID of the genesis node.
func (node *GatemintFullNode) GenesisID() string {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.genesisID
}

// GenesisHash returns the hash of the genesis configuration.
func (node *GatemintFullNode) GenesisHash() crypto.Digest {
	node.mu.Lock()
	defer node.mu.Unlock()

	return node.genesisHash
}

// PoolStats returns a PoolStatus structure reporting stats about the transaction pool
func (node *GatemintFullNode) PoolStats() PoolStats {
	r := node.ledger.Latest()
	last, err := node.ledger.Block(r)
	if err != nil {
		node.log.Warnf("GatemintFullNode: could not read ledger's last round: %v", err)
		return PoolStats{}
	}

	return PoolStats{
		NumConfirmed:   uint64(len(last.Payset)),
		NumOutstanding: uint64(node.transactionPool.PendingCount()),
		NumExpired:     uint64(node.transactionPool.NumExpired(r)),
	}
}

// ExtendPeerList dynamically adds a peer to a node's peer list.
func (node *GatemintFullNode) ExtendPeerList(peers ...string) {
	node.phonebook.ExtendPeerList(peers)
}

// ReplacePeerList replaces the current peer list with a different one
func (node *GatemintFullNode) ReplacePeerList(peers ...string) {
	node.phonebook.ReplacePeerList(peers)
}

// SuggestedFee returns the suggested fee per byte recommended to ensure a new transaction is processed in a timely fashion.
// Caller should set fee to max(MinTxnFee, SuggestedFee() * len(encoded SignedTxn))
func (node *GatemintFullNode) SuggestedFee() basics.Power {
	return node.feeTracker.EstimateFee()
}

// GetPendingTxnsFromPool returns a snapshot of every pending transactions from the node's transaction pool in a slice.
// Transactions are sorted in decreasing order. If no transactions, returns an empty slice.
func (node *GatemintFullNode) GetPendingTxnsFromPool() ([]transactions.SignedTxn, error) {
	return bookkeeping.SignedTxnGroupsFlatten(node.transactionPool.Pending()), nil
}

// Reload participation keys from disk periodically
func (node *GatemintFullNode) checkForParticipationKeys() {
	ticker := time.NewTicker(participationKeyCheckSecs * time.Second)
	for {
		select {
		case <-ticker.C:
			node.loadParticipationKeys()
		case <-node.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func (node *GatemintFullNode) loadParticipationKeys() error {
	// Generate a list of all potential participation key files
	genesisDir := filepath.Join(node.rootDir, node.genesisID)
	files, err := ioutil.ReadDir(genesisDir)
	if err != nil {
		return fmt.Errorf("GatemintFullNode.loadPartitipationKeys: could not read directory %v: %v", genesisDir, err)
	}

	// For each of these files
	for _, info := range files {
		// If it can't be a participation key database, skip it
		if !config.IsPartKeyFilename(info.Name()) {
			continue
		}
		filename := info.Name()

		// Fetch a handle to this database
		handle, err := node.GetExistingPartHandle(filename)
		if err != nil {
			return fmt.Errorf("GatemintFullNode.loadParticipationKeys: cannot load db %v: %v", filename, err)
		}

		// Fetch an account.Participation from the database
		part, err := account.RestoreParticipation(handle)
		if err != nil {
			handle.Close()
			if err == account.ErrUnsupportedSchema {
				node.log.Infof("Loaded participation keys from storage: %s %s", part.Address(), info.Name())
				msg := fmt.Sprintf("loadParticipationKeys: not loading unsupported participation key: %v; renaming to *.old", info.Name())
				fmt.Println(msg)
				node.log.Warn(msg)
				fullname := filepath.Join(genesisDir, info.Name())
				os.Rename(fullname, filepath.Join(fullname, ".old"))
			} else {
				return fmt.Errorf("GatemintFullNode.loadParticipationKeys: cannot load account at %v: %v", info.Name(), err)
			}
		} else {
			// Tell the AccountManager about the Participation (dupes don't matter)
			added := node.accountManager.AddParticipation(part)
			if added {
				node.log.Infof("Loaded participation keys from storage: %s %s", part.Address(), info.Name())
			} else {
				part.Close()
			}
		}
	}

	return nil
}

func (node *GatemintFullNode) txPoolGaugeThread() {
	txPoolGuage := metrics.MakeGauge(metrics.MetricName{Name: "algod_tx_pool_count", Description: "current number of available transactions in pool"})
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for true {
		select {
		case <-ticker.C:
			txPoolGuage.Set(float64(node.transactionPool.PendingCount()), nil)
		case <-node.ctx.Done():
			return
		}
	}
}

// IsArchival returns true the node is an archival node, false otherwise
func (node *GatemintFullNode) IsArchival() bool {
	return node.config.Archival
}

// OnNewBlock implements the BlockListener interface so we're notified after each block is written to the ledger
func (node *GatemintFullNode) OnNewBlock(block bookkeeping.Block, delta ledger.StateDelta) {
	// Update fee tracker
	node.feeTracker.ProcessBlock(block)

	node.mu.Lock()
	node.lastRoundTimestamp = time.Now()
	node.hasSyncedSinceStartup = true
	node.mu.Unlock()

	// Wake up oldKeyDeletionThread(), non-blocking.
	select {
	case node.oldKeyDeletionNotify <- struct{}{}:
	default:
	}
}

// oldKeyDeletionThread keeps deleting old participation keys.
// It runs in a separate thread so that, during catchup, we
// don't have to delete key for each block we received.
func (node *GatemintFullNode) oldKeyDeletionThread() {
	for {
		select {
		case <-node.ctx.Done():
			return
		case <-node.oldKeyDeletionNotify:
		}

		r := node.ledger.Latest()

		// We need to find the consensus protocol used to agree on block r,
		// since that determines the params used for ephemeral keys in block
		// r.  The params come from agreement.ParamsRound(r), which is r-2.
		hdr, err := node.ledger.BlockHdr(agreement.ParamsRound(r))
		if err != nil {
			switch err.(type) {
			case ledger.ErrNoEntry:
				// No need to warn; expected during catchup.
			default:
				node.log.Warnf("Cannot look up block %d for deleting ephemeral keys: %v", agreement.ParamsRound(r), err)
			}
		} else {
			proto := config.Consensus[hdr.CurrentProtocol]

			node.mu.Lock()
			node.accountManager.DeleteOldKeys(r+1, proto)
			node.mu.Unlock()
		}
	}
}

// Uint64 implements the randomness by calling the crypto library.
func (node *GatemintFullNode) Uint64() uint64 {
	return crypto.RandUint64()
}

// Indexer returns a pointer to nodes indexer
func (node *GatemintFullNode) Indexer() (*indexer.Indexer, error) {
	if node.indexer != nil && node.config.IsIndexerActive {
		return node.indexer, nil
	}
	return nil, fmt.Errorf("indexer is not active")
}

func (node *GatemintFullNode) TxSearch(query string, page, perPage int, orderBy string) (*appinterface.ResultTxSearch, error) {
	if node.indexer != nil && node.config.IsIndexerActive {
		return node.indexer.TxSearch(query, page, perPage, orderBy)
	}
	return nil, fmt.Errorf("indexer is not active")

}

// GetTransactionByID gets transaction by ID
func (node *GatemintFullNode) GetTransactionByID(txid transactions.Txid, rnd basics.Round) (TxnWithStatus, error) {
	stx, _, err := node.ledger.LookupTxid(txid, rnd)
	if err != nil {
		return TxnWithStatus{}, err
	}
	return TxnWithStatus{
		Txn:            stx.SignedTxn,
		ConfirmedRound: rnd,
		ApplyData:      stx.ApplyData,
	}, nil
}

//TODO delete
func (node *GatemintFullNode) InitApplication(app appinterface.Application) {
	node.application = app
}

func (node *GatemintFullNode) GetApplication() appinterface.Application {
	return node.application
}
