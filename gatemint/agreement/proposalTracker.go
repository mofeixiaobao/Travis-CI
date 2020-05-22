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

package agreement

import (
	"fmt"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/consensus"
	"github.com/gatechain/logging"
)

// A proposalSeeker finds the vote with the lowest credential until freeze() is
// called.
type proposalSeeker struct {
	// Lowest contains the vote with the lowest credential seen so far.
	Lowest vote
	// Filled is set if any vote has been seen.
	Filled bool
	// Frozen is set once freeze is called.  When Frozen is set, Lowest and
	// Filled will no longer be modified.
	Frozen bool

	// start committee set
	CommitteeVote   voteMaxHeap
	VoteArray       []string
	FrozenVoteArray []string
	StageVoteArray  []string
	//CommitteeFilled bool

	// end committee set
}

// accept compares a given vote with the current lowest-credentialled vote and
// sets it if freeze has not been called.
func (s proposalSeeker) accept(v vote, committeeNum int, isStaging bool, r routerHandle) (proposalSeeker, bool, error) {

	voteMaxHeap, isAddOk := s.CommitteeVote.addVote(committeeNum, v)
	if isAddOk {
		s.CommitteeVote = voteMaxHeap
	}

	if isStaging {
		s.StageVoteArray = append(s.StageVoteArray, v.R.Proposal.OriginalProposer.String())
		if isAddOk {
			return s, true, nil
		} else {
			return s, false, errProposalTrackerStaged{}
		}
	}

	if s.Frozen {
		s.FrozenVoteArray = append(s.FrozenVoteArray, v.R.Proposal.OriginalProposer.String())
		if isAddOk {
			return s, true, nil
		} else {
			return s, false, errProposalSeekerFrozen{}
		}
	} else {
		s.VoteArray = append(s.VoteArray, v.R.Proposal.OriginalProposer.String())
	}

	//voteMaxHeap, isAddOk := s.CommitteeVote.addVote(committeeNum, v)
	//if isAddOk {
	//	s.CommitteeVote = voteMaxHeap
	//}
	if s.Filled && !v.Cred.Less(s.Lowest.Cred) {
		if !isAddOk {
			return s, false, errProposalSeekerNotLess{NewSender: v.R.Sender, LowestSender: s.Lowest.R.Sender}
		} else {
			return s, true, nil
		}
	} else {
		s.Lowest = v
		s.Filled = true
		return s, false, nil
	}
}

// freeze freezes the state of the proposalSeeker so that future calls no longer
// change its state.
func (s proposalSeeker) freeze() proposalSeeker {
	s.Frozen = true
	return s
}

// A proposalTracker is a proposalMachinePeriod which de-duplicates
// proposal-votes seen in a given period and records the lowest credential seen
// and the period's staging proposal-value.
//
// It handles the following type(s) of event: voteVerified, voteFilterRequest, proposalFrozen, readStaging, and
// softThreshold.
// It returns the following type(s) of event: voteFiltered, proposalAccepted, readStaging,
// and proposalFrozen.
type proposalTracker struct {
	// Duplicate holds the set of senders which has been seen by the
	// proposalTracker.  A duplicate proposal-vote or an equivocating
	// proposal-vote is dropped by a proposalTracker.
	Duplicate map[basics.Address]bool
	// Freezer holds a proposalSeeker, which seeks the proposal-vote with
	// the lowest credential seen by the proposalTracker.
	Freezer proposalSeeker
	// Staging holds the proposalValue of the softThreshold delivered to
	// this proposalTracker (if any).
	Staging proposalValue
}

func (t *proposalTracker) T() stateMachineTag {
	return proposalMachinePeriod
}

func (t *proposalTracker) underlying() listener {
	return t
}

// A proposalTracker handles five types of events.
//
// - voteFilterRequest returns a voteFiltered event if a given proposal-vote
//   from a given sender has already been seen.  Otherwise it returns an empty
//   event.
//
// - voteVerified is issued when a relevant proposal-vote has passed
//   cryptographic verification.  If the proposalTracker has already seen a
//   proposal-vote from the same sender, a voteFiltered event is returned.  If
//   the proposal-vote's credential is not lowest than the current lowest
//   credential, or if a proposalFrozen or softThreshold event has already been delivered,
//   voteFiltered is also returned.  Otherwise, a proposalAccepted event is
//   returned.  The returned event contains the proposal-value relevant to the
//   current period.
//
// - proposalFrozen is issued after the state machine has timed out waiting for
//   the vote with the lowest credential value and has settled on a value to
//   soft-vote.  A proposalFrozen event tells this state machine to stop
//   accepting new proposal-votes.  The proposalFrozen is returned and the best
//   vote proposal-value is returned.  If none exists, bottom is returned.
//
// - softThreshold is issued after the state machine has received a threshold of
//   soft votes for some value in the proposalTracker's period.  The
//   softThreshold event sets the proposalTracker's staging value.  A
//   proposalAccepted event is returned, which contains the proposal-value
//   relevant to the current period.
//
// - readStaging returns the a stagingValueEvent with the proposal-value
//   believed to be the staging value (i.e., sigma(S, r, p)) by the
//   proposalTracker in period p.
func (t *proposalTracker) handle(r routerHandle, p player, e event) event {
	switch e.t() {
	case voteFilterRequest:
		v := e.(voteFilterRequestEvent).RawVote
		if t.Duplicate[v.Sender] {
			err := errProposalTrackerSenderDup{Sender: v.Sender, Round: v.Round, Period: v.Period}
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}
		return emptyEvent{}

	case voteVerified:
		if t.Duplicate == nil {
			t.Duplicate = make(map[basics.Address]bool)
		}
		e := e.(messageEvent)
		v := e.Input.Vote
		r.t.committeeLog.Infof("vote verified received at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, ",
			v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String())
		if t.Duplicate[v.R.Sender] {
			err := errProposalTrackerSenderDup{Sender: v.R.Sender, Round: v.R.Round, Period: v.R.Period}
			r.t.committeeLog.Infof("vote filtered 1 at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, ",
				v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String())
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}
		t.Duplicate[v.R.Sender] = true

		//if t.Staging != bottom {
		//	err := errProposalTrackerStaged{}
		//	r.t.committeeLog.Infof("vote filtered 2 at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, ",
		//		v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String())
		//	return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		//}

		var err error
		var isOther bool

		committeeNum := config.Consensus[e.Proto.Version].CommitteeNum
		t.Freezer, isOther, err = t.Freezer.accept(v, committeeNum, t.Staging != bottom, r)

		if err != nil {
			err := errProposalTrackerPS{Sub: err}
			r.t.committeeLog.Infof("vote filtered 3 at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, error is : %v",
				v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String(), err)
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}

		consensusInfo := makeConsensusWithAcceptProposalVote(p, v, "proposalVoteVerified")
		consensusInfoStrin, _ := consensusInfo.JsonSerial()
		r.t.log.Infof("%s:%s", consensus.ConsensusTag, consensusInfoStrin)

		var proposeListMap map[string]string
		proposeListMap = make(map[string]string)
		//var proposeList []string
		for _, proposeInfo := range t.Freezer.CommitteeVote {
			proposeListMap[proposeInfo.R.Proposal.OriginalProposer.String()] = ""
		}
		if isOther {
			r.t.committeeLog.Infof("vote saved at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, "+
				"committeeInfo is %v", v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String(), proposeListMap)
			return proposalSavedEvent{
				Round:    v.R.Round,
				Period:   v.R.Period,
				Proposal: v.R.Proposal,
			}
		} else {
			r.t.committeeLog.Infof("vote accepted at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, "+
				"committeeInfo is %v", v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String(), proposeListMap)
			return proposalAcceptedEvent{
				Round:    v.R.Round,
				Period:   v.R.Period,
				Proposal: v.R.Proposal,
			}
		}
	case proposalFrozen:
		e := e.(proposalFrozenEvent)
		e.Proposal = t.Freezer.Lowest.R.Proposal
		e.CommitteeVote = t.Freezer.CommitteeVote
		t.Freezer = t.Freezer.freeze()
		consensusInfo := makeConsensusWithProposalFrozen(p, t.Freezer, "proposalFrozen")
		consensusInfoStrin, _ := consensusInfo.JsonSerial()
		r.t.log.Infof("%s:%s", consensus.ConsensusTag, consensusInfoStrin)
		return e

	case committeeFrozen:
		e := e.(committeeFrozenEvent)
		e.Proposal = t.Freezer.Lowest.R.Proposal
		e.CommitteeVote = t.Freezer.CommitteeVote
		consensusInfo := makeConsensusWithProposalFrozen(p, t.Freezer, "committeeFrozen")
		consensusInfoStrin, _ := consensusInfo.JsonSerial()
		r.t.log.Infof("%s:%s", consensus.ConsensusTag, consensusInfoStrin)

		// add log
		var proposeList []basics.Address
		for _, proposeInfo := range t.Freezer.CommitteeVote {
			proposeList = append(proposeList, proposeInfo.R.Proposal.OriginalProposer)
		}

		voteMap := make(map[string]string)
		frozenVoteMap := make(map[string]string)
		stageVoteMap := make(map[string]string)
		for _, voteMapInfo := range t.Freezer.VoteArray {
			voteMap[voteMapInfo] = ""
		}
		for _, frozenVoteMapInfo := range t.Freezer.FrozenVoteArray {
			frozenVoteMap[frozenVoteMapInfo] = ""
		}
		for _, stageVoteMapInfo := range t.Freezer.StageVoteArray {
			stageVoteMap[stageVoteMapInfo] = ""
		}

		r.t.committeeLog.Infof("commiteeFrozen info , player status is (%v, %v, %v) , voteMap info is : %v, FrozenVoteMap info is : %v, StageVoteMap info is : %v ,"+
			"committeeInfo is %v", p.Round, p.Period, p.Step, voteMap, frozenVoteMap, stageVoteMap, proposeList)
		// end add log
		return e

	case softThreshold:
		e := e.(thresholdEvent)
		t.Staging = e.Proposal

		return proposalAcceptedEvent{
			Round:    e.Round,
			Period:   e.Period,
			Proposal: e.Proposal,
		}

	case readStaging:
		se := e.(stagingValueEvent)
		se.Proposal = t.Staging
		return se
	}

	logging.Base().Panicf("proposalTracker: bad event type: observed an event of type %v", e.t())
	panic("not reached")
}

// errors

type errProposalSeekerFrozen struct{}

func (err errProposalSeekerFrozen) Error() string {
	return "proposalSeeker.accept: seeker is already frozen"
}

type errProposalSeekerNotLess struct {
	NewSender    basics.Address
	LowestSender basics.Address
}

func (err errProposalSeekerNotLess) Error() string {
	return fmt.Sprintf("proposalSeeker.accept: credential from %v is not less than credential from %v", err.NewSender, err.LowestSender)
}

type errProposalTrackerSenderDup struct {
	Sender basics.Address
	Round  round
	Period period
}

func (err errProposalTrackerSenderDup) Error() string {
	return fmt.Sprintf("proposalTracker: filtered vote: sender %v had already sent a vote in round %v period %v", err.Sender, err.Round, err.Period)

}

type errProposalTrackerStaged struct{}

func (err errProposalTrackerStaged) Error() string {
	return "proposalTracker: value already staged"
}

type errProposalTrackerPS struct {
	Sub error
}

func (err errProposalTrackerPS) Error() string {
	return fmt.Sprintf("proposalTracker: filtered vote: %v", err.Sub)
}

func makeConsensusWithAcceptProposalVote(p player, v vote, memoInfo string) consensus.ConsensusInfo {
	var consensusInfo consensus.ConsensusInfo
	consensusInfo.Round = uint64(p.Round)
	consensusInfo.Period = uint64(p.Period)
	consensusInfo.Step = uint64(p.Step)
	consensusInfo.ProposeList = append(consensusInfo.ProposeList, v.R.Proposal.OriginalProposer.String())
	consensusInfo.MemoInfo = memoInfo
	return consensusInfo
}

func makeConsensusWithProposalFrozen(p player, ps proposalSeeker, memoInfo string) consensus.ConsensusInfo {
	var consensusInfo consensus.ConsensusInfo
	consensusInfo.Round = uint64(p.Round)
	consensusInfo.Period = uint64(p.Period)
	consensusInfo.Step = uint64(p.Step)
	consensusInfo.Propose = ps.Lowest.R.Proposal.OriginalProposer.String()
	consensusInfo.MemoInfo = memoInfo
	return consensusInfo
}
