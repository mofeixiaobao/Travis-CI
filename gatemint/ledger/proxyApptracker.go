package ledger

import (
	"bytes"
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/node/appinterface"
	"github.com/gatechain/gatemint/node/indexer"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/logging"
	"log"
)

type proxyAppTracker struct {
	application       appinterface.Application
	accts             *accountUpdates
	blockstore        *BlockStore
	executeBlockCache map[basics.Round]appinterface.ResponseSaveToDisk
	txIndexAvailable  bool
	indexStore        *indexer.IndexStore
	// log copied from ledger
	log logging.Logger
}

func (pt *proxyAppTracker) loadFromDisk(l ledgerForTracker) error {
	pt.accts.loadFromDisk(l)
	// todo need to add
	pt.log = l.trackerLog()
	pt.executeBlockCache = make(map[basics.Round]appinterface.ResponseSaveToDisk)
	return nil
}

func (pt *proxyAppTracker) close() {
}

var Current, Max int32

func (pt *proxyAppTracker) newBlock(blk bookkeeping.Block, delta StateDelta) {
	req := buildUpdateRequest(blk)
	res := pt.application.SaveToDisk(req)
	if res.ResponseStatus.IsErr() {
		pt.log.Warnf("cannot save @round err is %d %s", uint64(blk.Round()), res.ResponseStatus.GetMsg())
		executeReq := buildExecuteRequest(blk)
		Current++
		executeRes := pt.application.Executeblock(executeReq)
		if executeRes.ResponseStatus.IsErr() {
			log.Panicf("cannot execute @round err is %d %s", uint64(blk.Round()), executeRes.ResponseStatus.GetMsg())
		}
		res = pt.application.SaveToDisk(req)
		if res.ResponseStatus.IsErr() {
			log.Panicf("cannot save @round err is %d %s", uint64(blk.Round()), res.ResponseStatus.GetMsg())
		}
	}
	delta = buildDelta(res, delta)

	pt.commit(blk.Round(), res.AppData, delta)

	pt.executeBlockCache[blk.Round()] = delta.executeBlockRes
	if Current > Max {
		Max = Current
	}
	pt.log.Infof("[ExecuteblockTimes] round: %d votes: %d payloads: %d current: %d max: %d", blk.Round(), len(agreement.Votes), len(agreement.Payloads), Current, Max)
	Current = 0
	agreement.Votes = make(map[string]int, 0)
	agreement.Payloads = make(map[string]int, 0)
}

func (pt *proxyAppTracker) commit(committedRnd basics.Round, data []byte, delta StateDelta) basics.Round {
	if len(delta.participationAccounts) > 0 {
		for _, resTxData := range delta.participationAccounts {
			txData, err := appinterface.DeliverTxResDeSerialize(resTxData)
			if err != nil {
				pt.log.Errorf("deliverTxResponseData DeSerialize error, %s", resTxData)
			} else {
				var participationData = appinterface.ParticipationData{}
				err = protocol.Decode(txData.Extra, &participationData)
				if err != nil {
					pt.log.Errorf("participationExtra  error, %s", resTxData)
				}

				if participationData.OnlineStatus == basics.Online.String() {
					if !bytes.Equal(txData.Address, participationData.Address) {
						pt.log.Errorf("participationExtra DeSerialize error, %s", txData.Address)
					} else {
						var oneTimeSignatureVerifier basics.OneTimeSignatureVerifier
						copy(oneTimeSignatureVerifier[:], participationData.VoteID[:len(oneTimeSignatureVerifier)])
						var selid crypto.VRFVerifier
						copy(selid[:], participationData.SelectionID[:len(selid)])

						account := basics.AccountData{
							Status:          basics.Online,
							Power:           basics.Power{Raw: uint64(0)},
							VoteID:          oneTimeSignatureVerifier,
							SelectionID:     selid,
							VoteKeyDilution: participationData.VoteKeyDilution,
						}

						// Check account is already online?
						oldAccountData, err := pt.accts.lookup(participationData.Address)
						if err == nil {
							// Use already exists power
							account.Power = oldAccountData.Power
						}

						_ = pt.accts.accountstore.addPartKey(participationData.Address, account)
					}
				} else if participationData.OnlineStatus == basics.Offline.String() {
					accountData, err := pt.accts.lookup(txData.Address)
					if err != nil {
						pt.log.Errorf("participation address not exists %s", txData.Address)
					} else {
						_ = pt.accts.accountstore.removePartKey(txData.Address)
						pt.accts.updateTotals(accountData)
					}
				}
			}
		}
	}

	if len(delta.accounts) > 0 {
		var ot basics.OverflowTracker
		newTotals := &pt.accts.roundTotals[0]
		for addr, acct := range delta.accounts {
			oldAccountData, err := pt.accts.lookup(acct.Address)
			if err != nil {
				pt.log.Warnf("participation address not exists %s", acct.Address)
			} else {
				macct := pt.accts.accounts[addr]

				newAccountData := oldAccountData
				power := basics.Power{Raw: acct.Power}
				newAccountData.Power = power
				macct.data = newAccountData

				pt.accts.accounts[addr] = macct
				newTotals.delAccount(oldAccountData, &ot)
				newTotals.addAccount(newAccountData, &ot)
			}
		}
	}

	// flush mempool?

	//// todo is here need to add block hash ?
	//resCommit := pt.application.Commit(appinterface.RequestCommit{Height: uint64(committedRnd)})
	//if !resCommit.Response.IsOK() {
	//	pt.log.Errorf("commit block error, %s, %s %d", resCommit.Response.Log, "last blockRound: ", committedRnd)
	//}
	// todo need to save appHash from resCommit.Data
	// appState := resCommit.Data
	// save appState to disk, key is committedRnd, value is appState
	pt.accts.committedUpTo(committedRnd)
	//pt.accts.iterator()
	//pt.log.Errorf("666666666  %s  %d ",pt.accts.dbRound,pt.accts.roundTotals[0])
	pt.blockstore.SaveAppState(data, committedRnd)

	// update mempool?
	return committedRnd
}
func (pt *proxyAppTracker) committedUpTo(committedRnd basics.Round) basics.Round {
	// flush mempool?

	// todo is here need to add block hash ?
	//resCommit := pt.application.Commit(appinterface.RequestCommit{Height: uint64(committedRnd)})
	//if !resCommit.Response.IsOK() {
	//	pt.log.Errorf("commit block error, %s, %s %d", resCommit.Response.Log, "last blockRound: ", committedRnd)
	//}
	//// todo need to save appHash from resCommit.Data
	//// appState := resCommit.Data
	//// save appState to disk, key is committedRnd, value is appState
	//pt.accts.committedUpTo(committedRnd)
	//pt.blockstore.SaveAppState(resCommit.Data, committedRnd)

	// update mempool?
	res := pt.executeBlockCache[committedRnd]
	if pt.txIndexAvailable {
		if res.ResponseStatus.IsOK() && len(res.ResponseTx) > 0 {
			pt.indexStore.AddBatch(res.ResponseTx)
		}

	}
	delete(pt.executeBlockCache, committedRnd)
	return committedRnd
}
