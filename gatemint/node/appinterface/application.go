package appinterface

type Application interface {
	Query(RequestQuery) ResponseQuery // Query for state

	CheckTx(RequestCheckTx) ResponseCheckTx

	InitChain(RequestInitChain) ResponseInitChain

	Executeblock(RequestExecuteblock) ResponseExecuteblock

	SaveToDisk(RequestUpdateBlock) ResponseSaveToDisk

	GetTxValidInfo(RequestGetTxValidInfo) ResponseGetTxValidInfo
}

//-------------------------------------------------------
// BaseApplication is a base form of Application

var _ Application = (*ProxyBaseApplication)(nil)

type ProxyBaseApplication struct {
}

func (ProxyBaseApplication) Query(req RequestQuery) ResponseQuery {
	return ResponseQuery{Code: CodeTypeOK}
}

func (ProxyBaseApplication) CheckTx(req RequestCheckTx) ResponseCheckTx {
	return ResponseCheckTx{Response: ResponseStatus{Code: CodeTypeOK}, ResponseTxValidInfo: ResponseTxValidInfo{Fee: 1, FirstValidRound: 1, LastValidRound: 800}}
}

func (ProxyBaseApplication) InitChain(req RequestInitChain) ResponseInitChain {
	//return ResponseInitChain{Response: ResponseStatus{Code: CodeTypeOK}}
	return ResponseInitChain{
		Response: ResponseStatus{Code: CodeTypeOK},
		Accts:    req.Accts,
	}
}

func (ProxyBaseApplication) Executeblock(req RequestExecuteblock) ResponseExecuteblock {
	return ResponseExecuteblock{ResponseStatus: ResponseStatus{Code: CodeTypeOK}}
}

func (ProxyBaseApplication) SaveToDisk(req RequestUpdateBlock) ResponseSaveToDisk {
	return ResponseSaveToDisk{ResponseStatus: ResponseStatus{Code: CodeTypeOK}}
	//return ResponseSaveToDisk{Response: ResponseStatus{Code: CodeTypeOK}}
}

func (ProxyBaseApplication) GetTxValidInfo(RequestGetTxValidInfo) ResponseGetTxValidInfo {
	return ResponseGetTxValidInfo{Response: ResponseStatus{Code: CodeTypeOK}, ResponseTxValidInfo: ResponseTxValidInfo{Fee: 1, FirstValidRound: 1, LastValidRound: 800}}
}
