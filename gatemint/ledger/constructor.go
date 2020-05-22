package ledger

import (
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/node/appinterface"
	"time"
)

func buildExecuteRequest(blk bookkeeping.Block) appinterface.RequestExecuteblock {
	reqExecuteBlock := appinterface.RequestExecuteblock{}
	header := appinterface.Header{}
	header.Version = 1
	header.ChainID = blk.BlockHeader.GenesisID
	header.Height = uint64(blk.Round())
	header.Time = time.Unix(blk.BlockHeader.TimeStamp, 0)
	header.NumTxs = uint64(len(blk.PayProxySet))
	header.TotalTxs = blk.BlockHeader.TxnCounter
	lastBlkHash := crypto.Digest(blk.Branch)
	header.LastBlockId = lastBlkHash[:]
	header.ProposerAddress = blk.ProposerAddress[:]
	header.Committee = buildCommitteeType(blk.Committee)
	var softEquivocations [][]byte
	for _, value := range blk.SoftEquivocations {
		softEquivocations = append(softEquivocations, value.Sender[:])
	}
	header.SoftEquivocations = softEquivocations

	var certEquivocations [][]byte
	for _, value := range blk.CertEquivocations {
		certEquivocations = append(certEquivocations, value.Sender[:])
	}
	header.CertEquivocations = certEquivocations
	reqExecuteBlock.Header = header
	// add hash
	blkHash := crypto.Digest(blk.Hash())
	reqExecuteBlock.Hash = blkHash[:]
	if len(blk.PayProxySet) > 0 {
		var txs [][]byte
		for _, tx := range blk.PayProxySet {
			txs = append(txs, tx.Tx)
		}
		reqExecuteBlock.Txs = txs
	}
	return reqExecuteBlock
}

func buildDelta(res appinterface.ResponseSaveToDisk, delta StateDelta) StateDelta {
	// Run txs of block.
	partAccounts := make(map[int][]byte)
	for _, resTx := range res.ResponseTx {
		if resTx.Response.IsParticipation() {
			for index, resTxData := range resTx.ResponseTxData {
				partAccounts[index] = resTxData.Data
			}
		}
	}
	delta.participationAccounts = partAccounts
	updateAccounts := make(map[basics.Address]BaseAccount)
	for _, acct := range res.Accts {
		info := BaseAccount{
			Power:   acct.Power,
			Address: acct.Address,
		}
		updateAccounts[basics.ConverAddress(acct.Address)] = info
	}
	delta.accounts = updateAccounts
	delta.executeBlockRes = res
	return delta
}

func buildUpdateRequest(blk bookkeeping.Block) appinterface.RequestUpdateBlock {
	updateExecuteblock := appinterface.RequestUpdateBlock{}
	blkHash := crypto.Digest(blk.Hash())
	updateExecuteblock.Hash = blkHash[:]
	updateExecuteblock.Height = uint64(blk.Round())
	return updateExecuteblock
}
func buildCommitteeType(committees []bookkeeping.CommitteeSingle) []appinterface.CommitteeSingle {
	if len(committees) == 0 {
		return []appinterface.CommitteeSingle{}
	}
	var appCommittees []appinterface.CommitteeSingle
	for _, committee := range committees {
		appCommittees = append(appCommittees, appinterface.CommitteeSingle{CommitteeAddress: committee.CommitteeAddress, CommitteePower: committee.CommitteePower, CommitteeType: committee.CommitteeType})
	}
	return appCommittees
}
