package appinterface

import (
	"fmt"
	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/gatechain/crypto/merkle"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/protocol"
	"strings"
	"time"
)

type Header struct {
	// basic block info
	Version  uint64    `protobuf:"bytes,1,opt,name=version,proto3" json:"version"`
	ChainID  string    `protobuf:"bytes,2,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
	Height   uint64    `protobuf:"varint,3,opt,name=height,proto3" json:"height,omitempty"`
	Time     time.Time `protobuf:"bytes,4,opt,name=time,proto3,stdtime" json:"time"`
	NumTxs   uint64    `protobuf:"varint,5,opt,name=num_txs,json=numTxs,proto3" json:"num_txs,omitempty"`
	TotalTxs uint64    `protobuf:"varint,6,opt,name=total_txs,json=totalTxs,proto3" json:"total_txs,omitempty"`
	// prev block info
	LastBlockId     []byte `protobuf:"bytes,7,opt,name=last_block_id,json=lastBlockId,proto3" json:"last_block_id"`
	ProposerAddress []byte `protobuf:"bytes,8,opt,name=proposer_address,json=proposerAddress,proto3" json:"proposer_address,omitempty"`
	ConsensusData   []byte `protobuf:"bytes,9,opt,name=consensus_data,json=consensusData,proto3" json:"consensus_data,omitempty"`

	Committee    []CommitteeSingle `json:"committee"`
	Equivocation `json:"equivocation"`
}

type CommitteeSingle struct {
	CommitteeAddress basics.Address
	CommitteePower   uint64
	CommitteeType    uint8
}

type Equivocation struct {
	SoftEquivocations [][]byte `json:"softEquivocations"`
	CertEquivocations [][]byte `json:"certEquivocations"`
}

type RequestQuery struct {
	Data   []byte `json:"data"`
	Path   string `json:"path"`
	Height int64  `json:"height"`
	Prove  bool   `json:"Prove"`
}

type RequestTxSearch struct {
	Param   string `json:"param"`
	Page    int    `json:"page"`
	Limit   int    `json:"limit"`
	OrderBy string `json:"orderBy"`
}

// Result of searching for txs
type ResultTxSearch struct {
	Txs        []*ResponseTx `json:"txs"`
	TotalCount int           `json:"total_count"`
}

type QueryOptions struct {
	Height int64
	Prove  bool
}
type ResponseQuery struct {
	Code uint32 `json:"code"`
	// bytes data = 2; // use "value" instead.
	Log   string `json:"log"`
	Info  string `json:"info"`
	Index int64  `json:"index"`
	Key   []byte `json:"key"`
	Value []byte `json:"value"`

	//TODO need to change to gt merkle tree
	Proof     *merkle.Proof `json:"proof"`
	Height    int64         `json:"height"`
	Codespace string        `json:"codespace"`
}

type ResponseStatus struct {
	Type      string
	Code      uint32
	Log       string
	GasWanted uint64
	GasUsed   uint64
	Events    []Event
}
type Event struct {
	Type       string   `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	Attributes []KVPair `protobuf:"bytes,2,rep,name=attributes,proto3" json:"attributes,omitempty"`
}
type KVPair struct {
	Key   []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

type RequestCheckTx struct {
	Tx []byte
}

type ResponseCheckTx struct {
	Height int64  `json:"height"`
	Index  uint32 `json:"index"`
	Tx     []byte `json:"tx"`
	ResponseTxValidInfo
	Response ResponseStatus
}

type ResponseTxValidInfo struct {
	FirstValidRound uint64
	LastValidRound  uint64
	Fee             uint64
}

type RequestInitChain struct {
	Time          time.Time
	ChainId       string
	AppStateBytes []byte
	ConsensusData []byte
	Accts         []AccountDelta
}

type ResponseInitChain struct {
	Accts    []AccountDelta
	Response ResponseStatus
}

type RequestBeginBlock struct {
	Hash          []byte //BlockHash
	Header        Header //BlockHeader
	ConsensusData []byte
}

type ResponseBeginBlock struct {
	Response ResponseStatus
}

type RequestDeliverTx struct {
	Round        uint64
	Tx           []byte
	IndexInBlock int
}

type ResponseDeliverTx struct {
	Response     ResponseStatus
	ResponseData []byte
}

type DeliverTxResopnseData struct {
	Address []byte
	Extra   []byte
}

func (pex DeliverTxResopnseData) Serialize() []byte {
	dataBytes := protocol.Encode(pex)
	return dataBytes
}

func DeliverTxResDeSerialize(data []byte) (DeliverTxResopnseData, error) {
	var dtx DeliverTxResopnseData
	err := protocol.Decode(data, &dtx)
	if err != nil {
		return DeliverTxResopnseData{}, fmt.Errorf("deSerialize deliverTx resopnse date error, %v", err)
	}
	return dtx, nil
}

type RequestEndBlock struct {
	Height  uint64
	BlockID []byte
}

type AccountDelta struct {
	Power   uint64
	Address []byte
}
type ResponseEndBlock struct {
	Accts    []AccountDelta
	Response ResponseStatus
}

type RequestCommit struct {
	Height  uint64
	BlockID []byte
}

type ResponseCommit struct {
	Data     []byte
	Response ResponseStatus
}

type RequestGetTxValidInfo struct {
	Tx []byte
}

type ResponseGetTxValidInfo struct {
	ResponseTxValidInfo
	Response ResponseStatus
}

type ParticipationData struct {
	Address         []byte
	VoteID          []byte
	SelectionID     []byte
	VoteKeyDilution uint64
	OnlineStatus    string
}

func (pd ParticipationData) String() string {
	var sb strings.Builder
	sb.WriteString("ParticipationData:\n")
	if pd.Address != nil {
		sb.WriteString(fmt.Sprintf("  Address: 		%s\n", basics.ConverAddress(pd.Address)))
	}
	if pd.VoteID != nil {
		sb.WriteString(fmt.Sprintf("  VoteID: 		%s\n", base32.EncodeToString(pd.VoteID)))
	}
	if pd.SelectionID != nil {
		sb.WriteString(fmt.Sprintf("  SelectionID: 		%s\n", base32.EncodeToString(pd.SelectionID)))
	}
	return strings.TrimSpace(sb.String())
}

type RequestExecuteblock struct {
	ConsensusData []byte
	Hash          []byte
	Header        Header
	Txs           [][]byte
}

type ResponseExecuteblock struct {
	ResponseStatus ResponseStatus
}

type ResponseTx struct {
	Height         int64          `json:"height"`
	Index          uint32         `json:"index"`
	Tx             []byte         `json:"tx"`
	Response       ResponseStatus `json:"response"`
	ResponseTxData []ResponseTxExtra
}
type ResponseTxExtra struct {
	Data  []byte
	Index uint64
}
type RequestUpdateBlock struct {
	Hash   []byte
	Height uint64
}

type ResponseSaveToDisk struct {
	//Data           []byte
	ResponseStatus ResponseStatus
	ResponseTx     []ResponseTx
	AppData        []byte
	Accts          []AccountDelta
	//Response       ResponseStatus
}
