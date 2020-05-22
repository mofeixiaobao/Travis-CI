package pools

import (
	"container/heap"
	"github.com/gatechain/gatemint/data/transactions"
)

type txMaxHeap []transactions.TxWithValidInfo

func (vm txMaxHeap) Len() int {
	return len(vm)
}

func (vm txMaxHeap) Less(i, j int) bool {
	// because maxHeap ,so use >
	return vm[j].Fee < (vm[i].Fee)
	//return h[i] > h[j]
}

func (vm *txMaxHeap) Swap(i, j int) {
	(*vm)[i], (*vm)[j] = (*vm)[j], (*vm)[i]
}

func (vm *txMaxHeap) Push(x interface{}) {
	*vm = append(*vm, x.(transactions.TxWithValidInfo))
}

// Pop the last element of maxHeap
func (vm *txMaxHeap) Pop() interface{} {
	res := (*vm)[len(*vm)-1]
	*vm = (*vm)[:len(*vm)-1]
	return res
}

func initMaxHeap() txMaxHeap {
	vm := make(txMaxHeap, 0)
	heap.Init(&vm)
	return vm
}
