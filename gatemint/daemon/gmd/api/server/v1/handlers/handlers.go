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

package handlers

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/agreement"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/daemon/gmd/api/server/lib"
	"github.com/gatechain/gatemint/daemon/gmd/api/spec/v1"
	"github.com/gatechain/gatemint/data"
	"github.com/gatechain/gatemint/data/account"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/bookkeeping"
	"github.com/gatechain/gatemint/data/transactions"
	"github.com/gatechain/gatemint/ledger"
	"github.com/gatechain/gatemint/node"
	"github.com/gatechain/gatemint/node/appinterface"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gorilla/mux"
)

func nodeStatus(node *node.GatemintFullNode) (res v1.NodeStatus, err error) {
	stat, err := node.Status()
	if err != nil {
		return v1.NodeStatus{}, err
	}

	return v1.NodeStatus{
		LastRound:            uint64(stat.LastRound),
		LastVersion:          string(stat.LastVersion),
		NextVersion:          string(stat.NextVersion),
		NextVersionRound:     uint64(stat.NextVersionRound),
		NextVersionSupported: stat.NextVersionSupported,
		TimeSinceLastRound:   uint64(stat.TimeSinceLastRound().Seconds()),
		CatchupTime:          stat.CatchupTime.Nanoseconds(),
		Period:               stat.Period,
		Step:                 stat.Step,
		Deadline:             uint64(stat.Deadline.Seconds()),
		FastRecoveryDeadline: uint64(stat.FastRecoveryDeadline.Seconds()),
		ZeroTimeStamp:        stat.ZeroTimeStamp,
	}, nil
}

// decorateUnknownTransactionTypeError takes an error of type errUnknownTransactionType and converts it into
// either errInvalidTransactionTypeLedger or errInvalidTransactionTypePending as needed.
func decorateUnknownTransactionTypeError(err error, txs node.TxnWithStatus) error {
	if err.Error() != errUnknownTransactionType {
		return err
	}
	if txs.ConfirmedRound != basics.Round(0) {
		return fmt.Errorf(errInvalidTransactionTypeLedger, txs.Txn.Txn.Type, txs.Txn.Txn.ID().String(), txs.ConfirmedRound)
	}
	return fmt.Errorf(errInvalidTransactionTypePending, txs.Txn.Txn.Type, txs.Txn.Txn.ID().String())
}

// txEncode copies the data fields of the internal transaction object and populate the v1.Transaction accordingly.
// if unexpected transaction type is encountered, an error is returned. The caller is expected to ignore the returned
// transaction when error is non-nil.
func txEncode(tx transactions.Transaction, ad transactions.ApplyData) (v1.Transaction, error) {
	var res v1.Transaction
	switch tx.Type {
	case protocol.PaymentTx:
		res = paymentTxEncode(tx, ad)
	case protocol.KeyRegistrationTx:
		res = keyregTxEncode(tx, ad)
	case protocol.AssetConfigTx:
		res = assetConfigTxEncode(tx, ad)
	case protocol.AssetTransferTx:
		res = assetTransferTxEncode(tx, ad)
	case protocol.AssetFreezeTx:
		res = assetFreezeTxEncode(tx, ad)
	default:
		return res, errors.New(errUnknownTransactionType)
	}

	res.Type = string(tx.Type)
	res.TxID = tx.ID().String()
	res.From = tx.Src().String()
	res.Fee = tx.TxFee().Raw
	res.FirstRound = uint64(tx.First())
	res.LastRound = uint64(tx.Last())
	res.Note = tx.Aux()
	res.FromRewards = ad.SenderRewards.Raw
	res.GenesisID = tx.GenesisID
	res.GenesisHash = tx.GenesisHash[:]
	res.Group = tx.Group[:]
	return res, nil
}

func paymentTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	payment := v1.PaymentTransactionType{
		To:           tx.Receiver.String(),
		Amount:       tx.TxAmount().Raw,
		ToRewards:    ad.ReceiverRewards.Raw,
		CloseRewards: ad.CloseRewards.Raw,
	}

	if tx.CloseRemainderTo != (basics.Address{}) {
		payment.CloseRemainderTo = tx.CloseRemainderTo.String()
		payment.CloseAmount = ad.ClosingAmount.Raw
	}

	return v1.Transaction{
		Payment: &payment,
	}
}

func keyregTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	keyreg := v1.KeyregTransactionType{
		VotePK:          tx.KeyregTxnFields.VotePK[:],
		SelectionPK:     tx.KeyregTxnFields.SelectionPK[:],
		VoteFirst:       uint64(tx.KeyregTxnFields.VoteFirst),
		VoteLast:        uint64(tx.KeyregTxnFields.VoteLast),
		VoteKeyDilution: tx.KeyregTxnFields.VoteKeyDilution,
	}

	return v1.Transaction{
		Keyreg: &keyreg,
	}
}

func assetParams(creator basics.Address, params basics.AssetParams) v1.AssetParams {
	paramsModel := v1.AssetParams{
		Total:         params.Total,
		DefaultFrozen: params.DefaultFrozen,
	}

	paramsModel.UnitName = strings.TrimRight(string(params.UnitName[:]), "\x00")
	paramsModel.AssetName = strings.TrimRight(string(params.AssetName[:]), "\x00")
	paramsModel.URL = strings.TrimRight(string(params.URL[:]), "\x00")
	if params.MetadataHash != [32]byte{} {
		paramsModel.MetadataHash = params.MetadataHash[:]
	}

	if !creator.IsZero() {
		paramsModel.Creator = creator.String()
	}

	if !params.Manager.IsZero() {
		paramsModel.ManagerAddr = params.Manager.String()
	}

	if !params.Reserve.IsZero() {
		paramsModel.ReserveAddr = params.Reserve.String()
	}

	if !params.Freeze.IsZero() {
		paramsModel.FreezeAddr = params.Freeze.String()
	}

	if !params.Clawback.IsZero() {
		paramsModel.ClawbackAddr = params.Clawback.String()
	}

	return paramsModel
}

func assetConfigTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	params := assetParams(basics.Address{}, tx.AssetConfigTxnFields.AssetParams)

	config := v1.AssetConfigTransactionType{
		AssetID: uint64(tx.AssetConfigTxnFields.ConfigAsset),
		Params:  params,
	}

	return v1.Transaction{
		AssetConfig: &config,
	}
}

func assetTransferTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	xfer := v1.AssetTransferTransactionType{
		AssetID:  uint64(tx.AssetTransferTxnFields.XferAsset),
		Amount:   tx.AssetTransferTxnFields.AssetAmount,
		Receiver: tx.AssetTransferTxnFields.AssetReceiver.String(),
	}

	if !tx.AssetTransferTxnFields.AssetSender.IsZero() {
		xfer.Sender = tx.AssetTransferTxnFields.AssetSender.String()
	}

	if !tx.AssetTransferTxnFields.AssetCloseTo.IsZero() {
		xfer.CloseTo = tx.AssetTransferTxnFields.AssetCloseTo.String()
	}

	return v1.Transaction{
		AssetTransfer: &xfer,
	}
}

func assetFreezeTxEncode(tx transactions.Transaction, ad transactions.ApplyData) v1.Transaction {
	freeze := v1.AssetFreezeTransactionType{
		AssetID:         uint64(tx.AssetFreezeTxnFields.FreezeAsset),
		Account:         tx.AssetFreezeTxnFields.FreezeAccount.String(),
		NewFreezeStatus: tx.AssetFreezeTxnFields.AssetFrozen,
	}

	return v1.Transaction{
		AssetFreeze: &freeze,
	}
}

func txWithStatusEncode(tr node.TxnWithStatus) (v1.Transaction, error) {
	s, err := txEncode(tr.Txn.Txn, tr.ApplyData)
	if err != nil {
		err = decorateUnknownTransactionTypeError(err, tr)
		return v1.Transaction{}, err
	}
	s.ConfirmedRound = uint64(tr.ConfirmedRound)
	s.PoolError = tr.PoolError
	return s, nil
}

func computeAssetIndexInPayset(tx node.TxnWithStatus, txnCounter uint64, payset []transactions.SignedTxnWithAD) (aidx uint64) {
	// Compute transaction index in block
	offset := -1
	for idx, stxnib := range payset {
		if tx.Txn.Txn.ID() == stxnib.Txn.ID() {
			offset = idx
			break
		}
	}

	// Sanity check that txn was in fetched block
	if offset < 0 {
		return 0
	}

	// Count into block to get created asset index
	return txnCounter - uint64(len(payset)) + uint64(offset) + 1
}

// computeAssetIndexFromTxn returns the created asset index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAssetIndexFromTxn(tx node.TxnWithStatus, l *data.Ledger) (aidx uint64) {
	// Must have ledger
	if l == nil {
		return 0
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return 0
	}
	// Transaction must be AssetConfig transaction
	if tx.Txn.Txn.AssetConfigTxnFields == (transactions.AssetConfigTxnFields{}) {
		return 0
	}
	// Transaction must be creating an asset
	if tx.Txn.Txn.AssetConfigTxnFields.ConfigAsset != 0 {
		return 0
	}

	// Look up block where transaction was confirmed
	blk, err := l.Block(tx.ConfirmedRound)
	if err != nil {
		return 0
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return 0
	}

	return computeAssetIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset)
}

func blockEncode(b bookkeeping.Block, c agreement.Certificate) (v1.Block, error) {
	block := v1.Block{
		Hash:              crypto.Digest(b.Hash()).String(),
		PreviousBlockHash: crypto.Digest(b.Branch).String(),
		Seed:              crypto.Digest(b.Seed()).String(),
		Proposer:          c.Proposal.OriginalProposer.String(),
		Round:             uint64(b.Round()),
		TransactionsRoot:  b.TxnRoot.String(),
		RewardsRate:       b.RewardsRate,
		RewardsLevel:      b.RewardsLevel,
		RewardsResidue:    b.RewardsResidue,
		Timestamp:         b.TimeStamp,

		UpgradeState: v1.UpgradeState{
			CurrentProtocol:        string(b.CurrentProtocol),
			NextProtocol:           string(b.NextProtocol),
			NextProtocolApprovals:  b.NextProtocolApprovals,
			NextProtocolVoteBefore: uint64(b.NextProtocolVoteBefore),
			NextProtocolSwitchOn:   uint64(b.NextProtocolSwitchOn),
		},
		UpgradeVote: v1.UpgradeVote{
			UpgradePropose: string(b.UpgradePropose),
			UpgradeApprove: b.UpgradeApprove,
		},
	}

	// Transactions
	var txns []v1.Transaction
	payset, err := b.DecodePaysetFlat()
	if err != nil {
		return v1.Block{}, err
	}

	for _, txn := range payset {
		tx := node.TxnWithStatus{
			Txn:            txn.SignedTxn,
			ConfirmedRound: b.Round(),
			ApplyData:      txn.ApplyData,
		}

		encTx, err := txWithStatusEncode(tx)
		if err != nil {
			return v1.Block{}, err
		}

		txns = append(txns, encTx)
	}

	block.Transactions = v1.TransactionList{Transactions: txns}

	// add payProxySet
	var txnps [][]byte
	payProxySet, err := b.DecodeProxyPaysetFlat()
	for _, txn := range payProxySet {
		txnps = append(txnps, txn.Tx)
	}
	block.ProxyTransactions = v1.ProxyTransactionList{ProxyTransactions: txnps}

	for _, address := range c.ProposerList {
		block.CertCommitteeInfo = append(block.CertCommitteeInfo, address.String())
	}

	for _, committee := range b.Committee {
		block.BlockCommitteeInfo = append(block.BlockCommitteeInfo, committee.CommitteeAddress.String())
	}

	return block, nil
}

// Status is an httpHandler for route GET /v1/status
func Status(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/status GetStatus
	//---
	//     Summary: Gets the current node status.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         "$ref": '#/responses/StatusResponse'
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	nodeStatus, err := nodeStatus(ctx.Node)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	response := StatusResponse{&nodeStatus}
	SendJSON(response, w, ctx.Log)
}

// WaitForBlock is an httpHandler for route GET /v1/status/wait-for-block-after/{round:[0-9]+}
func WaitForBlock(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/status/wait-for-block-after/{round}/ WaitForBlock
	// ---
	//     Summary: Gets the node status after waiting for the given round.
	//     Description: Waits for a block to appear after round {round} and returns the node's status at the time.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: round
	//         in: path
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: true
	//         description: The round to wait until returning status
	//     Responses:
	//       200:
	//         "$ref": '#/responses/StatusResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	queryRound, err := strconv.ParseUint(mux.Vars(r)["round"], 10, 64)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
		return
	}

	select {
	case <-time.After(1 * time.Minute):
	case <-ctx.Node.Ledger().Wait(basics.Round(queryRound + 1)):
	}

	nodeStatus, err := nodeStatus(ctx.Node)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	response := StatusResponse{&nodeStatus}
	SendJSON(response, w, ctx.Log)
}

// RawTransaction is an httpHandler for route POST /v1/transactions
func RawTransaction(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/transactions RawTransaction
	// ---
	//     Summary: Broadcasts a raw transaction to the network.
	//     Produces:
	//     - application/json
	//     Consumes:
	//     - application/x-binary
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: rawtxn
	//         in: body
	//         schema:
	//           type: string
	//           format: binary
	//         required: true
	//         description: The byte encoded signed transaction to broadcast to network
	//     Responses:
	//       200:
	//         "$ref": "#/responses/TransactionIDResponse"
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	var txgroup []transactions.SignedTxn
	dec := protocol.NewDecoder(r.Body)
	for {
		var st transactions.SignedTxn
		err := dec.Decode(&st)
		if err == io.EOF {
			break
		}
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
			return
		}
		txgroup = append(txgroup, st)
	}

	if len(txgroup) == 0 {
		err := errors.New("empty txgroup")
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	err := ctx.Node.BroadcastSignedTxGroup(txgroup)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	// For backwards compatibility, return txid of first tx in group
	txid := txgroup[0].ID()
	SendJSON(TransactionIDResponse{&v1.TransactionID{TxID: txid.String()}}, w, ctx.Log)
}

// AccountInformation is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]{KeyLength}}
func AccountInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{address} AccountInformation
	// ---
	//     Summary: Get account information.
	//     Description: Given a specific account public key, this call returns the accounts status, balance and spendable amounts
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: address
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//     Responses:
	//       200:
	//         "$ref": '#/responses/AccountInformationResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }

	accountInfo := v1.Account{}

	SendJSON(AccountInformationResponse{&accountInfo}, w, ctx.Log)
}

// TransactionInformation is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]{KeyLength}}/transaction/{txid:[A-Z0-9]+}
func TransactionInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{address}/transaction/{txid} TransactionInformation
	// ---
	//     Summary: Get a specific confirmed transaction.
	//     Description: >
	//       Given a wallet address and a transaction id, it returns the confirmed transaction
	//       information. This call scans up to <CurrentProtocol>.MaxTxnLife blocks in the past.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: address
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//       - name: txid
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]+"
	//         required: true
	//         description: A transaction id
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       404:
	//         description: Transaction Not Found
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryTxID := mux.Vars(r)["txid"]
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	txID := transactions.Txid{}
	if txID.UnmarshalText([]byte(queryTxID)) != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	queryAddr := mux.Vars(r)["addr"]
	if queryAddr == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoAccountSpecified), errNoAccountSpecified, ctx.Log)
		return
	}

	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedToParseAddress), errFailedToParseAddress, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	latestRound := ledger.Latest()
	stat, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}
	proto := config.Consensus[stat.LastVersion]
	// non-Archival nodes keep proto.MaxTxnLife blocks around,
	// so without the + 1 in the below calculation,
	// Node.GetTransaction will query 1 round more than is kept around
	start := latestRound - basics.Round(proto.MaxTxnLife) + 1
	if latestRound < basics.Round(proto.MaxTxnLife) {
		start = 0
	}

	if txn, ok := ctx.Node.GetTransaction(addr, txID, start, latestRound); ok {
		var responseTxs v1.Transaction
		responseTxs, err = txWithStatusEncode(txn)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}

		response := TransactionResponse{
			Body: &responseTxs,
		}

		SendJSON(response, w, ctx.Log)
		return
	}

	// We didn't find it, return a failure
	lib.ErrorResponse(w, http.StatusNotFound, errors.New(errTransactionNotFound), errTransactionNotFound, ctx.Log)
	return
}

// PendingTransactionInformation is an httpHandler for route GET /v1/transactions/pending/{txid:[A-Z0-9]+}
func PendingTransactionInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/pending/{txid} PendingTransactionInformation
	// ---
	//     Summary: Get a specific pending transaction.
	//     Description: >
	//       Given a transaction id of a recently submitted transaction, it returns information
	//       about it.  There are several cases when this might succeed:
	//
	//       - transaction committed (committed round > 0)
	//       - transaction still in the pool (committed round = 0, pool error = "")
	//       - transaction removed from pool due to error (committed round = 0, pool error != "")
	//
	//       Or the transaction may have happened sufficiently long ago that the
	//       node no longer remembers it, and this will return an error.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: txid
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]+"
	//         required: true
	//         description: A transaction id
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       404:
	//         description: Transaction Not Found
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryTxID := mux.Vars(r)["txid"]
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	txID := transactions.Txid{}
	if txID.UnmarshalText([]byte(queryTxID)) != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	if txn, ok := ctx.Node.GetPendingTransaction(txID); ok {
		ledger := ctx.Node.Ledger()
		responseTxs, err := txWithStatusEncode(txn)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}

		responseTxs.TransactionResults = &v1.TransactionResults{
			// This field will be omitted for transactions that did not
			// create an asset (or for which we could not look up the block
			// it was created in), because computeAssetIndexFromTxn will
			// return 0 in that case.
			CreatedAssetIndex: computeAssetIndexFromTxn(txn, ledger),
		}

		response := TransactionResponse{
			Body: &responseTxs,
		}

		SendJSON(response, w, ctx.Log)
		return
	}

	// We didn't find it, return a failure
	lib.ErrorResponse(w, http.StatusNotFound, errors.New(errTransactionNotFound), errTransactionNotFound, ctx.Log)
	return
}

// GetPendingTransactions is an httpHandler for route GET /v1/transactions/pending.
func GetPendingTransactions(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/pending GetPendingTransactions
	// ---
	//     Summary: Get a list of unconfirmed transactions currently in the transaction pool.
	//     Description: >
	//       Get the list of pending transactions, sorted by priority,
	//       in decreasing order, truncated at the end at MAX. If MAX = 0,
	//       returns all pending transactions.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: max
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Truncated number of transactions to display. If max=0, returns all pending txns.
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/PendingTransactionsResponse'
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	max, err := strconv.ParseUint(r.FormValue("max"), 10, 64)
	if err != nil {
		max = 0
	}

	txs, err := ctx.Node.GetPendingTxnsFromPool()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
		return
	}

	totalTxns := uint64(len(txs))
	if max > 0 && totalTxns > max {
		// we expose this truncating mechanism for the client only, for the flexibility
		// to avoid dumping the whole pool over REST or in a cli. There is no need to optimize
		// fetching a smaller transaction set at a lower level.
		txs = txs[:max]
	}

	responseTxs := make([]v1.Transaction, len(txs))
	for i, twr := range txs {
		responseTxs[i], err = txEncode(twr.Txn, transactions.ApplyData{})
		if err != nil {
			// update the error as needed
			err = decorateUnknownTransactionTypeError(err, node.TxnWithStatus{Txn: twr})
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
			return
		}
	}

	response := PendingTransactionsResponse{
		Body: &v1.PendingTransactions{
			TruncatedTxns: v1.TransactionList{
				Transactions: responseTxs,
			},
			TotalTxns: totalTxns,
		},
	}

	SendJSON(response, w, ctx.Log)
}

// GetPendingTransactionsByAddress is an httpHandler for route GET /v1/account/addr:[A-Z0-9]{KeyLength}}/transactions/pending.
func GetPendingTransactionsByAddress(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{addr}/transactions/pending GetPendingTransactionsByAddress
	// ---
	//     Summary: Get a list of unconfirmed transactions currently in the transaction pool by address.
	//     Description: >
	//       Get the list of pending transactions by address, sorted by priority,
	//       in decreasing order, truncated at the end at MAX. If MAX = 0,
	//       returns all pending transactions.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: addr
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//       - name: max
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Truncated number of transactions to display. If max=0, returns all pending txns.
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/PendingTransactionsResponse'
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryMax := r.FormValue("max")
	max, err := strconv.ParseUint(queryMax, 10, 64)
	if queryMax != "" && err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedToParseMaxValue), errFailedToParseMaxValue, ctx.Log)
		return
	}

	queryAddr := mux.Vars(r)["addr"]
	if queryAddr == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoAccountSpecified), errNoAccountSpecified, ctx.Log)
		return
	}

	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAddress, ctx.Log)
		return
	}

	txs, err := ctx.Node.GetPendingTxnsFromPool()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
		return
	}

	responseTxs := make([]v1.Transaction, 0)
	for i, twr := range txs {
		if twr.Txn.Sender == addr || twr.Txn.Receiver == addr {
			// truncate in case max was passed
			if max > 0 && uint64(i) > max {
				break
			}

			tx, err := txEncode(twr.Txn, transactions.ApplyData{})
			responseTxs = append(responseTxs, tx)
			if err != nil {
				// update the error as needed
				err = decorateUnknownTransactionTypeError(err, node.TxnWithStatus{Txn: twr})
				lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpTransactionPool, ctx.Log)
				return
			}
		}
	}

	response := PendingTransactionsResponse{
		Body: &v1.PendingTransactions{
			TruncatedTxns: v1.TransactionList{
				Transactions: responseTxs,
			},
			TotalTxns: uint64(len(responseTxs)),
		},
	}

	SendJSON(response, w, ctx.Log)
}

// AssetInformation is an httpHandler for route GET /v1/asset/{index:[0-9]+}
func AssetInformation(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/asset/{index} AssetInformation
	// ---
	//     Summary: Get asset information.
	//     Description: >
	//       Given the asset's unique index, this call returns the asset's creator,
	//       manager, reserve, freeze, and clawback addresses
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: index
	//         in: path
	//         type: integer
	//         format: int64
	//         required: true
	//         description: Asset index
	//     Responses:
	//       200:
	//         "$ref": '#/responses/AssetInformationResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errFailedRetrievingAsset), errFailedRetrievingAsset, ctx.Log)
	return

}

// Assets is an httpHandler for route GET /v1/assets
func Assets(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	result := v1.AssetList{}
	SendJSON(AssetsResponse{&result}, w, ctx.Log)
}

// SuggestedFee is an httpHandler for route GET /v1/transactions/fee
func SuggestedFee(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/fee SuggestedFee
	// ---
	//     Summary: Get the suggested fee
	//     Description: >
	//       Suggested Fee is returned in units of micro-Algos per byte.
	//       Suggested Fee may fall to zero but submitted transactions
	//       must still have a fee of at least MinTxnFee for the current
	//       network protocol.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/TransactionFeeResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	fee := v1.TransactionFee{Fee: ctx.Node.SuggestedFee().Raw}
	SendJSON(TransactionFeeResponse{&fee}, w, ctx.Log)
}

// SuggestedParams is an httpHandler for route GET /v1/transactions/params
func SuggestedParams(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/params TransactionParams
	// ---
	//     Summary: Get parameters for constructing a new transaction
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/TransactionParamsResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	stat, err := ctx.Node.Status()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedRetrievingNodeStatus, ctx.Log)
		return
	}

	gh := ctx.Node.GenesisHash()

	var params v1.TransactionParams
	params.Fee = ctx.Node.SuggestedFee().Raw
	params.GenesisID = ctx.Node.GenesisID()
	params.GenesisHash = gh[:]
	params.LastRound = uint64(stat.LastRound)
	params.ConsensusVersion = string(stat.LastVersion)

	proto := config.Consensus[stat.LastVersion]
	params.MinTxnFee = proto.MinTxnFee

	SendJSON(TransactionParamsResponse{&params}, w, ctx.Log)
}

// GetBlock is an httpHandler for route GET /v1/block/{round}
func GetBlock(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/block/{round} GetBlock
	// ---
	//     Summary: Get the block for the given round.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: round
	//         in: path
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: true
	//         description: The round from which to fetch block information.
	//     Responses:
	//       200:
	//         "$ref": '#/responses/BlockResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	queryRound, err := strconv.ParseUint(mux.Vars(r)["round"], 10, 64)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
		return
	}

	ledger := ctx.Node.Ledger()
	b, c, err := ledger.BlockCert(basics.Round(queryRound))
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedLookingUpLedger, ctx.Log)
		return
	}
	block, err := blockEncode(b, c)

	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
		return
	}

	SendJSON(BlockResponse{&block}, w, ctx.Log)
}

// GetSupply is an httpHandler for route GET /v1/ledger/supply
func GetSupply(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/ledger/supply GetSupply
	//---
	//     Summary: Get the current supply reported by the ledger.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       200:
	//         "$ref": '#/responses/SupplyResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	//old algo api not support
	//latest := ctx.Node.Ledger().Latest()
	//
	//totals, err := ctx.Node.Ledger().Totals(latest)
	//if err != nil {
	//	err = fmt.Errorf("GetSupply(): round %d failed: %v", latest, err)
	//	lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
	//	return
	//}
	//supply := v1.Supply{
	//	Round:       uint64(latest),
	//	TotalMoney:  totals.Participating().Raw,
	//	OnlineMoney: totals.Online.Money.Raw,
	//}
	SendJSON(SupplyResponse{}, w, ctx.Log)
}

func parseTime(t string) (res time.Time, err error) {
	// check for just date
	res, err = time.Parse("2006-01-02", t)
	if err == nil {
		return
	}

	// check for date and time
	res, err = time.Parse(time.RFC3339, t)
	if err == nil {
		return
	}

	return
}

// Transactions is an httpHandler for route GET /v1/account/{addr:[A-Z0-9]+}/transactions
func Transactions(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/account/{address}/transactions Transactions
	// ---
	//     Summary: Get a list of confirmed transactions.
	//     Description: Returns the list of confirmed transactions between within a date range. This call is available only when the indexer is running.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: address
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]{58}"
	//         required: true
	//         description: An account public key
	//       - name: firstRound
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Do not fetch any transactions before this round.
	//       - name: lastRound
	//         in: query
	//         type: integer
	//         format: int64
	//         minimum: 0
	//         required: false
	//         description: Do not fetch any transactions after this round.
	//       - name: fromDate
	//         in: query
	//         type: string
	//         format: date
	//         required: false
	//         description: Do not fetch any transactions before this date. (enabled only with indexer)
	//       - name: toDate
	//         in: query
	//         type: string
	//         format: date
	//         required: false
	//         description: Do not fetch any transactions after this date. (enabled only with indexer)
	//       - name: max
	//         in: query
	//         type: integer
	//         format: int64
	//         required: false
	//         description: maximum transactions to show (default to 100)
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionsResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	queryAddr := mux.Vars(r)["addr"]
	addr, err := basics.UnmarshalChecksumAddress(queryAddr)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedToParseAddress, ctx.Log)
		return
	}

	max, err := strconv.ParseUint(r.FormValue("max"), 10, 64)
	if err != nil {
		max = 100
	}

	// Get different params
	firstRound := r.FormValue("firstRound")
	lastRound := r.FormValue("lastRound")
	fromDate := r.FormValue("fromDate")
	toDate := r.FormValue("toDate")

	var rounds []uint64
	var txs []node.TxnWithStatus
	// Were rounds provided?
	if firstRound != "" && lastRound != "" {
		// Are they valid?
		fR, err := strconv.ParseUint(firstRound, 10, 64)
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
			return
		}

		lR, err := strconv.ParseUint(lastRound, 10, 64)
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, errFailedParsingRoundNumber, ctx.Log)
			return
		}

		txs, err = ctx.Node.ListTxns(addr, basics.Round(fR), basics.Round(lR))
		if err != nil {
			switch err.(type) {
			case ledger.ErrNoEntry:
				if !ctx.Node.IsArchival() {
					lib.ErrorResponse(w, http.StatusInternalServerError, err, errBlockHashBeenDeletedArchival, ctx.Log)
					return
				}
			}

			lib.ErrorResponse(w, http.StatusInternalServerError, err, err.Error(), ctx.Log)
			return
		}

	} else {
		// is indexer on?
		indexer, err := ctx.Node.Indexer()
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, errNoRoundsSpecified, ctx.Log)
			return
		}

		// Were dates provided?
		if fromDate != "" && toDate != "" {
			fd, err := parseTime(fromDate)
			if err != nil {
				lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
				return
			}

			td, err := parseTime(toDate)
			if err != nil {
				lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
				return
			}

			rounds, err = indexer.GetRoundsByAddressAndDate(addr.String(), max, fd.Unix(), td.Unix())
			if err != nil {
				lib.ErrorResponse(w, http.StatusInternalServerError, err, err.Error(), ctx.Log)
				return
			}

		} else {
			// return last [max] transactions
			rounds, err = indexer.GetRoundsByAddress(addr.String(), max)
			if err != nil {
				lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedGettingInformationFromIndexer, ctx.Log)
				return
			}
		}
	}

	if len(rounds) > 0 {
		for _, rnd := range rounds {
			txns, _ := ctx.Node.ListTxns(addr, basics.Round(rnd), basics.Round(rnd))
			txs = append(txs, txns...)

			// They may be more txns in the round than requested, break.
			if uint64(len(txs)) > max {
				break
			}
		}
	}

	// clip length to [max]
	if uint64(len(txs)) > max {
		txs = txs[:max]
	}

	responseTxs := make([]v1.Transaction, len(txs))
	for i, twr := range txs {
		responseTxs[i], err = txWithStatusEncode(twr)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}
	}

	response := TransactionsResponse{
		&v1.TransactionList{
			Transactions: responseTxs,
		},
	}

	SendJSON(response, w, ctx.Log)
}

// GetTransactionByID is an httpHandler for route GET /v1/transaction/{txid}
func GetTransactionByID(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transaction/{txid} Transaction
	// ---
	//     Summary: Get an information of a single transaction.
	//     Description: Returns the transaction information of the given txid. Works only if the indexer is enabled.
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: txid
	//         in: path
	//         type: string
	//         pattern: "[A-Z0-9]+"
	//         required: true
	//         description: A transaction id
	//     Responses:
	//       200:
	//         "$ref": '#/responses/TransactionResponse'
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       404:
	//         description: Transaction Not Found
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	indexer, err := ctx.Node.Indexer()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errIndexerNotRunning, ctx.Log)
		return
	}

	queryTxID := mux.Vars(r)["txid"]
	if queryTxID == "" {
		lib.ErrorResponse(w, http.StatusBadRequest, fmt.Errorf(errNoTxnSpecified), errNoTxnSpecified, ctx.Log)
		return
	}

	var txID transactions.Txid
	if err := txID.UnmarshalText([]byte(queryTxID)); err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	rnd, err := indexer.GetRoundByTXID(queryTxID)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedGettingInformationFromIndexer, ctx.Log)
		return
	}

	if txn, err := ctx.Node.GetTransactionByID(txID, basics.Round(rnd)); err == nil {
		var responseTxs v1.Transaction
		responseTxs, err = txWithStatusEncode(txn)
		if err != nil {
			lib.ErrorResponse(w, http.StatusInternalServerError, err, errFailedToParseTransaction, ctx.Log)
			return
		}

		response := TransactionResponse{
			Body: &responseTxs,
		}

		SendJSON(response, w, ctx.Log)
		return
	}

	// We didn't find it, return a failure
	lib.ErrorResponse(w, http.StatusNotFound, errors.New(errTransactionNotFound), errTransactionNotFound, ctx.Log)
	return
}

func AppQuery(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("read body err, %v\n", err)
		return
	}
	var param appinterface.RequestQuery

	if err = protocol.DecodeJSON(body, &param); err != nil {
		fmt.Printf("Unmarshal err, %v\n", err)
		return
	}
	res := ctx.Node.GetApplication().Query(param)
	resBody := v1.Response{
		Response: res,
	}

	SendJSON(AppResponse{&resBody}, w, ctx.Log)
}

func Tx(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("read body err, %v\n", err)
		return
	}
	indexer, err := ctx.Node.Indexer()
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, "indexer init err", ctx.Log)
		return
	}
	tx, err := indexer.QueryTxByHash(body)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, "GetTxByHash -- no response", ctx.Log)
		return
	}
	if tx == nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, "GetTxByHash -- no response", ctx.Log)
		return
	}
	SendJSON(TxResponse{tx}, w, ctx.Log)
}

// RawTransaction is an httpHandler for route POST /v1/transactions-test
// this transaction is onlyf for single transaction
// because algo don't care what the tx is
func BroadcastTx(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/transactions RawTransaction
	// ---
	//     Summary: Broadcasts a raw transaction to the network.
	//     Produces:
	//     - application/json
	//     Consumes:
	//     - application/x-binary
	//     Schemes:
	//     - http
	//     Parameters:
	//       - name: rawtxn
	//         in: body
	//         schema:
	//           type: string
	//           format: binary
	//         required: true
	//         description: The byte encoded signed transaction to broadcast to network
	//     Responses:
	//       200:
	//         "$ref": "#/responses/TransactionIDResponse"
	//       400:
	//         description: Bad Request
	//         schema: {type: string}
	//       500:
	//         description: Internal Error
	//         schema: {type: string}
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }

	broadCastMethod := r.Header.Get("broadCastMethod")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}

	if broadCastMethod == "async" {
		go broadCastTxInfo(ctx, r, body)
		var tx transactions.Tx = body
		SendJSON(BroadcastResponse{&v1.ResultBroadcastTx{Code: 00, Data: tx, Log: "async broadcast tx success", Hash: tx.Hash(), TxId: tx.ComputeID().String()}}, w, ctx.Log)
	} else {
		err := broadCastTxInfo(ctx, r, body)
		if err != nil {
			//lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
			var tx transactions.Tx = body
			SendJSON(BroadcastResponse{&v1.ResultBroadcastTx{Code: 01, Data: tx, Log: "sync broadcast tx error:" + err.Error(), Hash: tx.Hash(), TxId: tx.ComputeID().String()}}, w, ctx.Log)
		} else {
			var tx transactions.Tx = body
			SendJSON(BroadcastResponse{&v1.ResultBroadcastTx{Code: 00, Data: tx, Log: "sync broadcast tx success", Hash: tx.Hash(), TxId: tx.ComputeID().String()}}, w, ctx.Log)
		}
	}
}

//func broadCastTxInfo(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request, body []byte) error {
//	err = ctx.Node.BroadcastProxyTx(body)
//	if err != nil {
//		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
//		return err
//	}
//}

func broadCastTxInfo(ctx lib.ReqContext, r *http.Request, body []byte) error {
	err := ctx.Node.BroadcastProxyTx(body)
	return err
}

// GenParticipationKeys is an httpHandler for route GET /v1/genParticipationKeys
func GenParticipationKey(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/params TransactionParams
	// ---
	//     Summary: Get parameters for constructing a new transaction
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/TransactionParamsResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
		return
	}
	address := basics.ConverAddress(body)
	addressName := address.String()
	fileName := fmt.Sprintf("%s.%d.%d.partkey", addressName, 0, 0)
	var resBody = v1.ParticipationKeyResponse{}
	handle, err := ctx.Node.GetExistingPartHandle(fileName)
	if err == nil {
		//isExisting
		handle.Close()
		lib.ErrorResponse(w, http.StatusBadRequest, err, fmt.Sprintf("address already exist ParticipationKeys"), ctx.Log)
		return
	} else {
		ledger := ctx.Node.Ledger()
		blkHdr, _ := ledger.BlockHdr(ledger.Latest())
		proto := config.Consensus[blkHdr.CurrentProtocol]
		keyDilution := proto.DefaultKeyDilution
		fileName = filepath.Join(ctx.Node.Config().RootDir, ctx.Node.GenesisID(), fileName)
		first := ledger.Latest()
		last := basics.RefreshPartRound(first, keyDilution)
		part, err := account.PersistParticipationKeys(fileName, address, first, basics.Round(last), keyDilution)
		if err != nil {
			lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
			return
		}
		partData := appinterface.ParticipationData{Address: body, SelectionID: part.VRFSecrets().PK[:], VoteKeyDilution: part.KeyDilution, VoteID: part.VotingSecrets().OneTimeSignatureVerifier[:]}
		resBody.Data = protocol.Encode(partData)
		resBody.FileName = fileName
		resBody.ParticipationKey = partData
		part.Close()
	}

	SendJSON(GenParticipationKeyResponse{Body: &resBody}, w, ctx.Log)
}

// GetParticipationKey is an httpHandler for route GET /v1/getParticipationKey
func GetParticipationKey(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/transactions/params TransactionParams
	// ---
	//     Summary: Get parameters for constructing a new transaction
	//     Produces:
	//     - application/json
	//     Schemes:
	//     - http
	//     Responses:
	//       "200":
	//         "$ref": '#/responses/TransactionParamsResponse'
	//       401: { description: Invalid API Token }
	//       default: { description: Unknown Error }
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
		return
	}
	address := basics.ConverAddress(body)
	addressName := address.String()
	fileName := fmt.Sprintf("%s.%d.%d.partkey", addressName, 0, 0)
	handle, err := ctx.Node.GetExistingPartHandle(fileName)
	var resBody = v1.ParticipationKeyResponse{}
	if err != nil {
		//not exist
		lib.ErrorResponse(w, http.StatusBadRequest, err, fmt.Sprintf("address not exist ParticipationKeys"), ctx.Log)
		return
	}
	part, err := account.RestoreParticipation(handle)
	// Don't override 'unsupported schema' error
	if err != nil && err != account.ErrUnsupportedSchema {
		err = fmt.Errorf("couldn't restore existing participation file %s: %v", fileName, err)
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}
	partData := appinterface.ParticipationData{Address: body, SelectionID: part.VRFSecrets().PK[:], VoteKeyDilution: part.KeyDilution, VoteID: part.VotingSecrets().OneTimeSignatureVerifier[:]}
	resBody.Data = protocol.Encode(partData)
	resBody.FileName = fileName
	resBody.ParticipationKey = partData
	handle.Close()
	SendJSON(GetParticipationKeyResponse{Body: &resBody}, w, ctx.Log)
}

func GetConAccount(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, errInternalFailure, ctx.Log)
		return
	}
	address := basics.ConverAddress(body)
	partData, _ := ctx.Node.Ledger().Lookup(ctx.Node.Ledger().Latest(), address)
	var resBody = v1.ResultConAccount{}
	if err != nil {
		resBody.Status = false
		err = fmt.Errorf("couldn't find participation account  %s: %v", address.String(), err)
		SendJSON(GetConAccountResponse{Body: &resBody}, w, ctx.Log)
	}
	resBody.Status = true
	resBody.Power = partData.Power.Raw
	resBody.Address = address[:]
	SendJSON(GetConAccountResponse{Body: &resBody}, w, ctx.Log)
}

func ListLocalConAccounts(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	genesisDir := filepath.Join(ctx.Node.Config().RootDir, ctx.Node.GenesisID())
	files, err := ioutil.ReadDir(genesisDir)
	var pdList []appinterface.ParticipationData
	for _, info := range files {
		// If it can't be a participation key database, skip it
		if !config.IsPartKeyFilename(info.Name()) {
			continue
		}
		handle, err := ctx.Node.GetExistingPartHandle(info.Name())
		if err != nil {
			err = fmt.Errorf("Get Handle error    %v %s", err, info.Name())
		} else {
			part, err := account.RestoreParticipation(handle)
			if err == nil {
				addr := part.Address()
				partData := appinterface.ParticipationData{Address: addr[:], SelectionID: part.VRFSecrets().PK[:], VoteKeyDilution: part.KeyDilution, VoteID: part.VotingSecrets().OneTimeSignatureVerifier[:]}
				pdList = append(pdList, partData)
			}

		}
	}
	if len(pdList) < 1 {
		err = fmt.Errorf("couldn't find participation accounts   %v", err)
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}
	SendJSON(GetLocalConAccountsResponse{Body: &pdList}, w, ctx.Log)
}

func CheckConAccts(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	str := ctx.Node.Ledger().GetAccts()
	total, _ := ctx.Node.Ledger().Totals(ctx.Node.Ledger().Latest())
	str += fmt.Sprintf("MoneyInDisk: %d", total.Money.Raw)
	SendJSON(CheckConAcctsResponse{Body: &str}, w, ctx.Log)
}

const maxAddressNum = 100

func GetPeers(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	peers := ctx.Node.Net().GetPeersInfo(maxAddressNum)
	if len(peers) < 1 {
		err := fmt.Errorf("the node has no peers")
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}
	SendJSON(StringArrayResponse{Body: peers}, w, ctx.Log)
}

func GetPhonebook(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	peers := ctx.Node.Net().GetPhonebook(maxAddressNum)
	if len(peers) < 1 {
		err := fmt.Errorf("the node's phonebook is empty")
		lib.ErrorResponse(w, http.StatusBadRequest, err, err.Error(), ctx.Log)
		return
	}
	SendJSON(StringArrayResponse{Body: peers}, w, ctx.Log)
}

func TxSearch(ctx lib.ReqContext, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("read body err, %v\n", err)
		return
	}
	var param appinterface.RequestTxSearch

	if err = protocol.DecodeJSON(body, &param); err != nil {
		fmt.Printf("Unmarshal err, %v\n", err)
		return
	}
	res, err := ctx.Node.TxSearch(param.Param, param.Page, param.Limit, param.OrderBy)
	if err != nil {
		lib.ErrorResponse(w, http.StatusInternalServerError, err, "not match", ctx.Log)
		return
	}
	SendJSON(TxSearchRes{Body: res}, w, ctx.Log)
}
