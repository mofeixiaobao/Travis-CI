package appinterface

import "fmt"

const (
	CodeTypeOK            uint32 = 0
	CodeTypeError         uint32 = 1
	CodeTypeParticipation uint32 = 2
)

func (r ResponseStatus) IsOK() bool {
	return r.Code == CodeTypeOK
}

func (r ResponseStatus) IsErr() bool {
	return r.Code != CodeTypeOK && r.Code != CodeTypeParticipation
}

func (r ResponseStatus) IsParticipation() bool {
	return r.Code == CodeTypeParticipation
}

// IsOK returns true if Code is OK.
func (r ResponseCheckTx) IsOK() bool {
	return r.Response.IsOK()
}

// IsErr returns true if Code is something other than OK.
func (r ResponseCheckTx) IsErr() bool {
	return r.Response.IsErr()
}

func (r ResponseInitChain) IsOK() bool {
	return r.Response.IsOK()
}

// IsErr returns true if Code is something other than OK.
func (r ResponseInitChain) IsErr() bool {
	return r.Response.IsErr()
}

// IsErr returns true if Code is something other than OK.
func (r ResponseBeginBlock) IsErr() bool {
	return r.Response.IsErr()
}

// IsOK returns true if Code is OK.
func (r ResponseQuery) IsOK() bool {
	return r.Code == CodeTypeOK
}

// IsErr returns true if Code is something other than OK.
func (r ResponseQuery) IsErr() bool {
	return r.Code != CodeTypeOK
}

// IsErr returns true if Code is something other than OK.
func (r ResponseEndBlock) IsErr() bool {
	return r.Response.IsErr()
}

// IsOK returns true if Code is OK.
func (r ResponseGetTxValidInfo) IsOK() bool {
	return r.Response.IsOK()
}

// IsErr returns true if Code is something other than OK.
func (r ResponseGetTxValidInfo) IsErr() bool {
	return r.Response.IsErr()
}

func (r ResponseStatus) GetMsg() string {
	return fmt.Sprintf("response code: %v , log: %v", r.Code, r.Log)
}

//---------------------------------------------------------------------------
// override JSON marshalling so we emit defaults (ie. disable omitempty)
//
//var (
//	jsonpbMarshaller = jsonpb.Marshaler{
//		EnumsAsInts:  true,
//		EmitDefaults: true,
//	}
//	jsonpbUnmarshaller = jsonpb.Unmarshaler{}
//)
//
//func (r *ResponseCheckTx) MarshalJSON() ([]byte, error) {
//	s, err := jsonpbMarshaller.MarshalToString(r)
//	return []byte(s), err
//}
//
//func (r *ResponseCheckTx) UnmarshalJSON(b []byte) error {
//	reader := bytes.NewBuffer(b)
//	return jsonpbUnmarshaller.Unmarshal(reader, r)
//}
//
//func (r *ResponseDeliverTx) MarshalJSON() ([]byte, error) {
//	s, err := jsonpbMarshaller.MarshalToString(r)
//	return []byte(s), err
//}
//
//func (r *ResponseDeliverTx) UnmarshalJSON(b []byte) error {
//	reader := bytes.NewBuffer(b)
//	return jsonpbUnmarshaller.Unmarshal(reader, r)
//}
//
//func (r *ResponseQuery) MarshalJSON() ([]byte, error) {
//	s, err := jsonpbMarshaller.MarshalToString(r)
//	return []byte(s), err
//}
//
//func (r *ResponseQuery) UnmarshalJSON(b []byte) error {
//	reader := bytes.NewBuffer(b)
//	return jsonpbUnmarshaller.Unmarshal(reader, r)
//}
//
//func (r *ResponseCommit) MarshalJSON() ([]byte, error) {
//	s, err := jsonpbMarshaller.MarshalToString(r)
//	return []byte(s), err
//}
//
//func (r *ResponseCommit) UnmarshalJSON(b []byte) error {
//	reader := bytes.NewBuffer(b)
//	return jsonpbUnmarshaller.Unmarshal(reader, r)
//}
//
//// Some compile time assertions to ensure we don't
//// have accidental runtime surprises later on.
//
//// jsonEncodingRoundTripper ensures that asserted
//// interfaces implement both MarshalJSON and UnmarshalJSON
//type jsonRoundTripper interface {
//	json.Marshaler
//	json.Unmarshaler
//}
//
//var _ jsonRoundTripper = (*ResponseCommit)(nil)
//var _ jsonRoundTripper = (*ResponseQuery)(nil)
//var _ jsonRoundTripper = (*ResponseDeliverTx)(nil)
//var _ jsonRoundTripper = (*ResponseCheckTx)(nil)
//var _ jsonRoundTripper = (*ResponseSetOption)(nil)
