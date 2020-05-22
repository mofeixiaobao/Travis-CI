package indexer

type Operator uint8

const (
	// "<="
	OpLessEqual Operator = iota
	// ">="
	OpGreaterEqual
	// "<"
	OpLess
	// ">"
	OpGreater
	// "="
	OpEqual
	// "CONTAINS"; used to check if a string contains a certain sub string.
	OpContains

	OrderByAsc = "asc"

	OrderByDesc = "desc"
)

// Condition represents a single condition within a query and consists of tag
// (e.g. "tx.gas"), operator (e.g. "=") and operand (e.g. "7").
type Condition struct {
	Tag     string
	Op      Operator
	Operand interface{}
}
