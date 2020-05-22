package agreement

import (
	"bytes"
	"container/heap"
)

type voteMaxHeap []vote

func (vm voteMaxHeap) Len() int {
	return len(vm)
}

func (vm voteMaxHeap) Less(i, j int) bool {
	// because maxHeap ,so use >
	return vm[j].Cred.Less(vm[i].Cred)
	//return h[i] > h[j]
}

func (vm *voteMaxHeap) Swap(i, j int) {
	(*vm)[i], (*vm)[j] = (*vm)[j], (*vm)[i]
}

func (vm *voteMaxHeap) Push(x interface{}) {
	*vm = append(*vm, x.(vote))
}

// Pop the last element of maxHeap
func (vm *voteMaxHeap) Pop() interface{} {
	res := (*vm)[len(*vm)-1]
	*vm = (*vm)[:len(*vm)-1]
	return res
}

func initMaxHeap() voteMaxHeap {
	vm := make(voteMaxHeap, 0)
	heap.Init(&vm)
	return vm
}

func (vm voteMaxHeap) addVote(maxHeapNum int, value vote) (voteMaxHeap, bool) {
	//h := make(MaxHeap, 0)
	//heap.Init(&h)
	isAddOK := false
	for _, voteValue := range vm {
		if bytes.Compare(voteValue.R.Proposal.OriginalProposer[:], value.R.Proposal.OriginalProposer[:]) == 0 {
			return vm, isAddOK
		}
	}
	if vm.Len() < maxHeapNum {
		heap.Push(&vm, value)
		isAddOK = true
	} else {
		//maxValue := vm.Pop()
		maxValue := heap.Pop(&vm)
		if value.Cred.Less(maxValue.(vote).Cred) {
			//heap.Pop(&vm)
			heap.Push(&vm, value)
			isAddOK = true
		} else {
			heap.Push(&vm, maxValue)
		}
	}
	return vm, isAddOK
}
