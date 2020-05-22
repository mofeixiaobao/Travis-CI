package consensus

import (
	"encoding/json"
)

const ConsensusTag = "consensusLogInfo"
const ConsensusTagEnd = "consensusLogInfoEnd"

type ConsensusInfo struct {
	Round  uint64
	Period uint64
	Step   uint64

	Committee
	Equivocations
	Propose string
	Soft    string
	Cert    string

	Sender string

	MemoInfo string
}

type Committee struct {
	ProposeList []string
	SoftList    []string
	CertList    []string
	NextList    []string
}

type Equivocations struct {
	SoftEquivocations []string
	CertEquivocations []string
}

func (con *ConsensusInfo) JsonSerial() (string, error) {
	jsons, err := json.Marshal(con) //转换成JSON返回的是byte[]
	if err != nil {
		return "", err
	}
	return string(jsons), nil
}
