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
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/data/consensus"
	"github.com/gatechain/go-deadlock"
	"github.com/gatechain/logging"
	"time"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/protocol"
)

// The player implements the top-level state machine functionality of the
// agreement protocol.
type player struct {
	// Round, Period, and Step hold the current round, period, and step of
	// the player state machine.
	Round  round
	Period period
	Step   step

	// LastConcluding holds the largest step reached in the last period.  As
	// described in the spec, it affects the propagation of next-vote
	// messages.
	LastConcluding step

	// Deadline contains the time of the next timeout expected by the player
	// state machine (relevant to the start of the current period).
	Deadline time.Duration
	// Napping is set when the player is expecting a random timeout (i.e.,
	// to determine when the player chooses to send a next-vote).
	Napping bool

	// FastRecoveryDeadline contains the next timeout expected for fast
	// partition recovery.
	FastRecoveryDeadline time.Duration

	// Pending holds the player's proposalTable, which stores proposals that
	// must be verified after some vote has been verified.
	Pending proposalTable

	// SoftCommitCertificate contains the last softCommit certificate
	//LastSoftCommitCertificate Certificate

	ProposalListMu deadlock.RWMutex
	//ProposalList   voteMaxHeap
	//end  committee consensus

	// empty block
	ZeroTimeStamp  time.Time
	TimeOutAddDur  time.Duration
	IsMakeProposal bool
	//IsHaveNewTx    bool
	// end empty block
}

func (p *player) T() stateMachineTag {
	return playerMachine
}

func (p *player) underlying() actor {
	return p
}

// Precondition: passed-in player is equal to player
// Postcondition: each messageEvent is processed exactly once
func (p *player) handle(r routerHandle, e event) []action {
	var actions []action

	if e.t() == none {
		return nil
	}
	switch e := e.(type) {
	case messageEvent:
		p.ZeroTimeStamp = e.zeroTime
		return p.handleMessageEvent(r, e)
	case thresholdEvent:
		return p.handleThresholdEvent(r, e)
	case timeoutEvent:
		p.ZeroTimeStamp = e.zeroTime
		// if have any timeOutEvent, player don't need to update deadline when have any tx arrived
		if e.T == fastTimeout {
			return p.handleFastTimeout(r, e)
		}
		if e.T == newTxArrived {
			switch p.Step {
			case soft:
				if !p.IsMakeProposal {
					logging.Base().Info("handle newTxArrived , enter propose")
					return p.handleTxArrivedTimeout(r, e)
				} else {
					logging.Base().Info("handle newTxArrived , but proposed before, do not need enter propose")
					return actions
				}
			default:
				logging.Base().Infof("otherProposalTimeoutEvent do not need to handle , p.step is : %v, ", p.Step)
				return actions
			}
		}
		if e.T == proposalTimeout {
			switch p.Step {
			case soft:
				logging.Base().Info("handle proposalTimeoutEvent , enter propose")
				return p.handleProposeTimeout(r, e)
			default:
				logging.Base().Infof("otherProposalTimeoutEvent do not need to handle ")
				return actions
			}
		}

		if !p.Napping {
			r.t.logTimeout(*p)
		}
		switch p.Step {
		case soft:
			actions = p.issueSoftVote(r)
			p.Step = cert
			// update tracer state to match player
			r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})
			return actions
		case cert:
			p.Step = next
			// update tracer state to match player
			r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})
			return p.issueNextVote(r)
		default:
			if p.Napping {
				return p.issueNextVote(r) // sets p.Napping to false
			}
			// not napping, so we should enter a new step
			p.Step++ // note: this must happen before next timeout setting.
			// TODO add unit test to ensure that deadlines increase monotonically here

			lower, upper := p.Step.nextVoteRanges()
			delta := time.Duration(e.RandomEntropy % uint64(upper-lower))

			p.Napping = true
			p.Deadline = lower + delta + p.TimeOutAddDur
			return actions
		}
	case roundInterruptionEvent:
		var version protocol.ConsensusVersion
		if e.Proto.Err != nil {
			r.t.log.Errorf("failed to read protocol version for roundInterruptionEvent (proto %v): %v", e.Proto.Version, e.Proto.Err)
			version = protocol.ConsensusCurrentVersion
		} else {
			version = e.Proto.Version
		}
		return p.enterRound(r, e, e.Round, version)
	case checkpointEvent:
		return p.handleCheckpointEvent(r, e)
	case emptyEvent:
		//var actions []action
		return actions
	default:
		panic("bad event")
	}
}

func (p *player) handleProposeTimeout(r routerHandle, e timeoutEvent) []action {
	var actions []action

	if !p.IsMakeProposal {
		p.IsMakeProposal = true
		as := pseudonodeAction{T: assemble, Round: p.Round, Period: 0}
		actions = append(actions, as)
	}
	logging.Base().Info("enter handleProposeTimeout")
	return actions
}

func (p *player) handleTxArrivedTimeout(r routerHandle, e timeoutEvent) []action {
	var actions []action
	//if !p.IsMakeProposal {
	//	p.IsMakeProposal = true
	//	as := pseudonodeAction{T: assemble, Round: p.Round, Period: 0}
	//	actions = append(actions, as)
	//}
	p.IsMakeProposal = true
	as := pseudonodeAction{T: assemble, Round: p.Round, Period: 0}
	actions = append(actions, as)
	//p.IsHaveNewTx = true
	logging.Base().Info("enter handleTxArrivedTimeout")

	p.TimeOutAddDur = time.Now().Sub(p.ZeroTimeStamp)
	p.Deadline = filterTimeout + p.TimeOutAddDur
	return actions
}

func (p *player) handleFastTimeout(r routerHandle, e timeoutEvent) []action {
	if e.Proto.Err != nil {
		r.t.log.Errorf("failed to read protocol version for fastTimeout event (proto %v): %v", e.Proto.Version, e.Proto.Err)
		return nil
	}
	r.t.log.Infof("handleFastTimeout , event round info is : %v", e.Round)

	lambda := config.Consensus[e.Proto.Version].FastRecoveryLambda
	k := (p.FastRecoveryDeadline + lambda - 1) / lambda // round up
	lower, upper := k*lambda, (k+1)*lambda
	delta := time.Duration(e.RandomEntropy % uint64(upper-lower))
	if p.FastRecoveryDeadline == 0 {
		// don't vote the first time
		p.FastRecoveryDeadline = lower + delta + lambda // add lambda for extra delay the first time
		return nil
	}
	p.FastRecoveryDeadline = lower + delta
	r.t.logFastTimeout(*p)
	return p.issueFastVote(r)
}

func (p *player) issueSoftVote(r routerHandle) (actions []action) {
	defer func() {
		p.Deadline = deadlineTimeout + p.TimeOutAddDur
	}()

	e := r.dispatch(*p, proposalFrozenEvent{}, proposalMachinePeriod, p.Round, p.Period, 0)
	a := pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: soft, Proposal: e.(proposalFrozenEvent).Proposal}
	//p.ProposalList = e.(proposalFrozenEvent).CommitteeVote
	r.t.logProposalFrozen(a.Proposal, a.Round, a.Period)
	r.t.timeR().RecStep(p.Period, soft, a.Proposal)

	res := r.dispatch(*p, nextThresholdStatusRequestEvent{}, voteMachinePeriod, p.Round, p.Period-1, 0)
	nextStatus := res.(nextThresholdStatusEvent) // panic if violate postcondition
	if p.Period > 0 && !nextStatus.Bottom && nextStatus.Proposal != bottom {
		// did not see bottom: vote for our starting value
		// we check if answer.Proposal != bottom because we may have arrived here due to a fast-forward/soft threshold
		// If we arrive due to fast-forward/soft threshold; then answer.Bottom = false and answer.Proposal = bottom
		// and we should soft-vote normally (not based on the starting value)
		a.Proposal = nextStatus.Proposal
		return append(actions, a)
	}

	if a.Proposal == bottom {
		// did not see anything: do not vote
		return nil
	}

	if p.Period > a.Proposal.OriginalPeriod {
		// leader sent reproposal: vote if we saw a quorum for that hash, even if we saw nextStatus.Bottom
		if nextStatus.Proposal != bottom && nextStatus.Proposal == a.Proposal {
			return append(actions, a)
		}
		return nil
	}

	// original proposal: vote for it
	return append(actions, a)
}

// A committableEvent is the trigger for issuing a cert vote.
func (p *player) issueCertVote(r routerHandle, e committableEvent) action {
	r.t.timeR().RecStep(p.Period, cert, e.Proposal)
	return pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: cert, Proposal: e.Proposal}
}

func (p *player) issueNextVote(r routerHandle) []action {
	actions := p.partitionPolicy(r)

	a := pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: p.Step, Proposal: bottom}

	//answer := stagedValue(*p, r, p.Round, p.Period)
	//if answer.Committable {
	//	a.Proposal = answer.Proposal
	//} else {
	//	res := r.dispatch(*p, nextThresholdStatusRequestEvent{}, voteMachinePeriod, p.Round, p.Period-1, 0)
	//	nextStatus := res.(nextThresholdStatusEvent) // panic if violate postcondition
	//	if !nextStatus.Bottom {
	//		// note that this is bottom if we fast-forwarded to this period or entered via a soft threshold.
	//		a.Proposal = nextStatus.Proposal
	//	}
	//}
	actions = append(actions, a)

	r.t.timeR().RecStep(p.Period, p.Step, a.Proposal)

	_, upper := p.Step.nextVoteRanges()
	p.Napping = false
	p.Deadline = upper + p.TimeOutAddDur
	return actions
}

func (p *player) issueFastVote(r routerHandle) (actions []action) {
	actions = p.partitionPolicy(r)

	elate := r.dispatch(*p, dumpVotesRequestEvent{}, voteMachineStep, p.Round, p.Period, late).(dumpVotesEvent).Votes
	eredo := r.dispatch(*p, dumpVotesRequestEvent{}, voteMachineStep, p.Round, p.Period, redo).(dumpVotesEvent).Votes
	edown := r.dispatch(*p, dumpVotesRequestEvent{}, voteMachineStep, p.Round, p.Period, down).(dumpVotesEvent).Votes
	votes := append(eredo, edown...)
	votes = append(elate, votes...)
	actions = append(actions, networkAction{T: broadcastVotes, UnauthenticatedVotes: votes})

	a := pseudonodeAction{T: attest, Round: p.Round, Period: p.Period, Step: down, Proposal: bottom}
	answer := stagedValue(*p, r, p.Round, p.Period)
	if answer.Committable {
		a.Step = late
		a.Proposal = answer.Proposal
	} else {
		res := r.dispatch(*p, nextThresholdStatusRequestEvent{}, voteMachinePeriod, p.Round, p.Period-1, 0)
		nextStatus := res.(nextThresholdStatusEvent) // panic if violate postcondition
		if !nextStatus.Bottom {
			// note that this is bottom if we fast-forwarded to this period or entered via a soft threshold.
			a.Step = redo
			a.Proposal = nextStatus.Proposal
		}
	}
	if a.Proposal == bottom {
		// required if we entered the period via a soft threshold
		a.Step = down
	}

	return append(actions, a)
}

func (p *player) handleCheckpointEvent(r routerHandle, e checkpointEvent) []action {
	return []action{
		checkpointAction{
			Round:  e.Round,
			Period: e.Period,
			Step:   e.Step,
			Err:    e.Err,
			done:   e.done,
		}}
}

func (p *player) handleThresholdEvent(r routerHandle, e thresholdEvent) []action {
	r.t.timeR().RecThreshold(e)

	// Special case all cert thresholds: we must not ignore them, because they are the freshest bundle
	var actions []action
	if e.t() == certThreshold {
		// this threshold must be for p.Round, and originates from the vote SM tree
		cert := Certificate(e.Bundle)
		// committee
		ec := r.dispatch(*p, committeeFrozenEvent{}, proposalMachinePeriod, p.Round, p.Period, 0)
		proposalVoteList := ec.(committeeFrozenEvent).CommitteeVote
		r.t.logCommitteeFrozen(ec.(committeeFrozenEvent).Proposal, p.Round, p.Period)

		var proposeList []basics.Address
		for _, proposeInfo := range proposalVoteList {
			proposeList = append(proposeList, proposeInfo.R.Proposal.OriginalProposer)
		}
		cert.ProposerList = proposeList
		// end committee

		res := stagedValue(*p, r, e.Round, e.Period)
		a0 := ensureAction{Payload: res.Payload, PayloadOk: res.Committable, Certificate: cert}
		actions = append(actions, a0)
		as := p.enterRound(r, e, p.Round+1, e.Proto)

		consensusInfo := makeConsensusWithCertificate(p, cert)
		consensusInfoString, _ := consensusInfo.JsonSerial()
		r.t.log.Infof("%s:%s", consensus.ConsensusTag, consensusInfoString)

		return append(actions, as...)
	}

	// We might receive a next threshold event for the previous period due to fast-forwarding or a soft threshold.
	// If we do, this is okay, but the proposalMachine contract-checker will complain.
	// TODO test this case and update the contract-checker so it does not complain when this is benign
	if p.Period >= e.Period+1 {
		return nil
	}

	switch e.t() {
	case softThreshold:
		if p.Period == e.Period {
			ec := r.dispatch(*p, e, proposalMachine, p.Round, p.Period, 0)
			if ec.t() == proposalCommittable && p.Step <= cert {
				actions = append(actions, p.issueCertVote(r, ec.(committableEvent)))
				softCert := Certificate(e.Bundle)
				consensusInfo := makeConsensusWithSoftCertificate(p, softCert)
				consensusInfoString, _ := consensusInfo.JsonSerial()
				r.t.log.Infof("%s:%s", consensus.ConsensusTag, consensusInfoString)
			}
			return actions
		}
		return p.enterPeriod(r, e, e.Period, e.Proto)
	case nextThreshold:
		return p.enterPeriod(r, e, e.Period+1, e.Proto)
	default:
		// certThreshold was handled previously
		panic("bad event")
	}
}

func (p *player) enterPeriod(r routerHandle, source thresholdEvent, target period, prov protocol.ConsensusVersion) []action {
	actions := p.partitionPolicy(r)

	// this needs to happen before changing player state so the correct old blockAssemblers can be promoted
	// TODO might be better passing through the old period explicitly in the {soft,next}Threshold event
	e := r.dispatch(*p, source, proposalMachine, p.Round, p.Period, 0)
	r.t.logPeriodConcluded(*p, target, source.Proposal)

	p.LastConcluding = p.Step
	p.Period = target
	p.Step = soft
	p.Napping = false
	p.FastRecoveryDeadline = 0 // set immediately
	p.Deadline = filterTimeout

	//p.IsMakeProposal = false

	// update tracer state to match player
	r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})

	actions = append(actions, rezeroAction{Round: p.Round})
	//p.ZeroTimeStamp = time.Now()
	p.TimeOutAddDur = 0

	if e.t() == proposalCommittable { // implies source.t() == softThreshold
		return append(actions, p.issueCertVote(r, e.(committableEvent)))
	}
	if source.t() == nextThreshold {
		proposal := source.Proposal
		if proposal == bottom {
			p.IsMakeProposal = true
			a := pseudonodeAction{T: assemble, Round: p.Round, Period: p.Period}
			return append(actions, a)
		} else if uint64(p.Period) >= p.getCommitteeBottomPeriod(prov) {
			p.IsMakeProposal = true
			a := pseudonodeAction{T: assemble, Round: p.Round, Period: p.Period}
			return append(actions, a)
		}
		a := pseudonodeAction{T: repropose, Round: p.Round, Period: p.Period, Proposal: proposal}
		return append(actions, a)
	}

	return actions
}

func (p *player) enterRound(r routerHandle, source event, target round, prov protocol.ConsensusVersion) []action {
	var actions []action

	// this happens here so that the proposalMachine contract does not complain
	e := r.dispatch(*p, source, proposalMachine, target, 0, 0)
	if source.t() != roundInterruption {
		r.t.logRoundStart(*p, target)
	}

	p.LastConcluding = p.Step
	p.Round = target
	p.Period = 0
	p.Step = soft
	p.Napping = false
	p.FastRecoveryDeadline = 0 // set immediately

	p.IsMakeProposal = false
	//p.IsHaveNewTx = false
	//p.ProposalList = make(map[period]map[basics.Address]round)

	// update tracer state to match player
	r.t.setMetadata(tracerMetadata{p.Round, p.Period, p.Step})
	r.t.resetTimingWithPipeline(target)

	// do proposal-related actions
	if p.waitForTxs(prov) {
		//p.ZeroTimeStamp = time.Now()
		p.TimeOutAddDur = p.getCreateEmptyBlocksInterval(prov) - filterTimeout
		p.Deadline = filterTimeout + p.TimeOutAddDur
		actions = append(actions, rezeroAction{Round: target})
	} else {
		//p.ZeroTimeStamp = time.Now()
		p.TimeOutAddDur = 0
		p.Deadline = filterTimeout
		p.IsMakeProposal = true
		as := pseudonodeAction{T: assemble, Round: p.Round, Period: 0}
		actions = append(actions, rezeroAction{Round: target}, as)
	}
	if e.t() == payloadPipelined {
		e := e.(payloadProcessedEvent)
		msg := message{MessageHandle: 0, Tag: protocol.ProposalPayloadTag, UnauthenticatedProposal: e.UnauthenticatedPayload} // TODO do we want to keep around the original handle?
		a := verifyPayloadAction(messageEvent{T: payloadPresent, Input: msg}, p.Round, e.Period, e.Pinned)
		actions = append(actions, a)
	}

	// we might need to handle a pipelined threshold event

	res := r.dispatch(*p, freshestBundleRequestEvent{}, voteMachineRound, p.Round, 0, 0)
	freshestRes := res.(freshestBundleEvent) // panic if violate postcondition
	if freshestRes.Ok {
		a4 := p.handle(r, freshestRes.Event)
		actions = append(actions, a4...)
	}
	return actions
}

// partitionPolicy checks if the player is in a partition, and if it is,
// it returns the list of actions necessary to recover.
//
// partitionPolicy represents an attempt to resynchronize.
//
// These actions include the repropagation of the freshest bundle, if one was seen,
// (necessarily true for p.Period > 0 or the presence of a soft threshold)
// and the repropagation of the block payload this bundle votes for, if one was seen.
func (p *player) partitionPolicy(r routerHandle) (actions []action) {
	if !p.partitioned() {
		return
	}

	res := r.dispatch(*p, freshestBundleRequestEvent{}, voteMachineRound, p.Round, 0, 0)
	bundleResponse := res.(freshestBundleEvent) // panic if violate postcondition
	if bundleResponse.Ok {
		// TODO do we want to authenticate our own bundles?
		b := bundleResponse.Event.Bundle
		r.t.logBundleBroadcast(*p, b)
		a0 := broadcastAction(protocol.VoteBundleTag, b)
		actions = append(actions, a0)
	}

	// On resynchronization, first try relaying the staged proposal from the same period as
	// the freshest bundle. If that does not exist, for instance if we saw two next quorums in a row,
	// then we fall back to relaying the pinned value, for liveness.
	// One specific scenario where this is essential, assuming we handle ensure digest asynchronously:
	// - Let the majority of honest nodes cert vote, and then see a next value quorum, and enter p + 1.
	// - They see another next value quorum, and enter p + 2.
	// - The minority of honest nodes see a certThreshold (but without a block), in period p. Assume that
	//   they are partitioned from the majority of honest nodes, until the majority reach p + 2.
	// - The minority already has the freshest bundle, so will not advance to period p + 2. However, the
	//   majority will also filter out the cert threshold (due to a stale period).
	// - Now we relay the pinned value, and then can wait for catchup.
	// - Another optimization is that we could allow cert bundles from stale periods to bypass the filter.
	//   This may be worth implementing in the future.
	bundleRound := p.Round
	bundlePeriod := p.Period
	switch {
	case bundleResponse.Ok && bundleResponse.Event.Bundle.Proposal != bottom:
		b := bundleResponse.Event.Bundle
		bundleRound = b.Round
		bundlePeriod = b.Period
		fallthrough
	case p.Period == 0:
		resStaged := stagedValue(*p, r, bundleRound, bundlePeriod)
		if resStaged.Committable {
			transmit := compoundMessage{Proposal: resStaged.Payload.u()}
			r.t.logProposalRepropagate(resStaged.Proposal, bundleRound, bundlePeriod)
			a1 := broadcastAction(protocol.ProposalPayloadTag, transmit)
			actions = append(actions, a1)
		} else {
			// even if there is no staged value, there may be a pinned value
			resPinned := pinnedValue(*p, r, bundleRound)
			if resPinned.PayloadOK {
				transmit := compoundMessage{Proposal: resPinned.Payload.u()}
				r.t.logProposalRepropagate(resPinned.Proposal, bundleRound, bundlePeriod)
				a1 := broadcastAction(protocol.ProposalPayloadTag, transmit)
				actions = append(actions, a1)
			}
		}

	}
	return
}

func (p *player) partitioned() bool {
	return p.Step >= partitionStep || p.Period >= 3
}

func (p *player) waitForTxs(prov protocol.ConsensusVersion) bool {
	cfg := config.Consensus[prov]
	return !cfg.CreateEmptyBlocks || cfg.CreateEmptyBlocksInterval > 0
}

func (p *player) getCommitteeBottomPeriod(prov protocol.ConsensusVersion) uint64 {
	cfg := config.Consensus[prov]
	return cfg.CommitteeBottomPeriod
}

func (p *player) getCreateEmptyBlocksInterval(prov protocol.ConsensusVersion) time.Duration {
	cfg := config.Consensus[prov]
	return cfg.CreateEmptyBlocksInterval
}

func (p *player) handleMessageEvent(r routerHandle, e messageEvent) (actions []action) {
	// is it a proposal-vote? (i.e., vote where step = 0)
	proposalVote := false
	switch e.t() {
	case votePresent, voteVerified:
		uv := e.Input.UnauthenticatedVote
		proposalVote = (uv.R.Step == propose)
	}

	// wrap message event with current player round, etc. for freshness computation
	delegatedE := filterableMessageEvent{
		messageEvent: e,
		FreshnessData: freshnessData{
			PlayerRound:          p.Round,
			PlayerPeriod:         p.Period,
			PlayerStep:           p.Step,
			PlayerLastConcluding: p.LastConcluding,
		},
	}

	// if so, process it separately
	if proposalVote {
		doneProcessing := true // TODO check that this is still required
		defer func() {
			tail := e.Tail
			if e.t() == voteVerified {
				tail = p.Pending.pop(e.TaskIndex)
			}

			if tail == nil || !doneProcessing {
				return
			}

			ev := *tail // make surer the event we handle is messageEvent, not *messageEvent
			suffix := p.handle(r, ev)
			actions = append(actions, suffix...)
		}()

		//p.addProposeInfo(e.Input.UnauthenticatedVote.R.Proposal.OriginalProposer)

		ef := r.dispatch(*p, delegatedE, proposalMachine, 0, 0, 0)
		switch ef.t() {
		case voteMalformed:
			err := ef.(filteredEvent).Err
			return append(actions, disconnectAction(e, err))
		case voteFiltered:
			err := ef.(filteredEvent).Err
			return append(actions, ignoreAction(e, err))
		}

		if e.t() == votePresent {
			doneProcessing = false
			seq := p.Pending.push(e.Tail)
			uv := e.Input.UnauthenticatedVote
			return append(actions, verifyVoteAction(e, uv.R.Round, uv.R.Period, seq))
		}
		switch ef.t() {
		case proposalSaved:
			v := e.Input.Vote
			a := relayAction(e, protocol.AgreementVoteTag, v.u())
			r.t.committeeLog.Infof("proposal saved at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, "+
				" vote add to relayAction for %v", v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String(), v.R.Proposal)
			return append(actions, a)
		default:
			v := e.Input.Vote
			a := relayAction(e, protocol.AgreementVoteTag, v.u())
			r.t.committeeLog.Infof("proposal accepted at (%v, %v, %v) , player status is (%v, %v, %v) , proposal address is : %v, sender is : %v, "+
				" vote add to relayAction for %v", v.R.Round, v.R.Period, v.R.Step, p.Round, p.Period, p.Step, v.R.Proposal.OriginalProposer.String(), v.R.Sender.String(), v.R.Proposal)
			ep := ef.(proposalAcceptedEvent)
			if ep.PayloadOk {
				transmit := compoundMessage{
					Proposal: ep.Payload.u(),
					Vote:     v.u(),
				}
				a = broadcastAction(protocol.ProposalPayloadTag, transmit)
			}
			return append(actions, a)
		}
		//v := e.Input.Vote
		//a := relayAction(e, protocol.AgreementVoteTag, v.u())
		//ep := ef.(proposalAcceptedEvent)
		//if ep.PayloadOk {
		//	transmit := compoundMessage{
		//		Proposal: ep.Payload.u(),
		//		Vote:     v.u(),
		//	}
		//	a = broadcastAction(protocol.ProposalPayloadTag, transmit)
		//}
		//return append(actions, a)
	}

	switch e.t() {
	case payloadPresent, payloadVerified, payloadPresentSelf, payloadVerifiedSelf:
		presentSelf := e.t() == payloadPresentSelf
		if presentSelf {
			actions = append(actions, relayAction(e, protocol.ProposalPayloadTag, compoundMessage{Proposal: e.Input.UnauthenticatedProposal, Vote: e.Input.UnauthenticatedVote}))
			delegatedE.T = payloadPresent
		}
		verifiedSeft := e.t() == payloadVerifiedSelf
		if verifiedSeft {
			delegatedE.T = payloadVerified
		}
		// todo here need to judge e.err
		if (e.t() == payloadVerified || verifiedSeft) && e.Input.TxNum > 0 {
			version := getProtoFromEvent(e.Proto)
			if !p.IsMakeProposal && p.waitForTxs(version) {
				//p.IsHaveNewTx = true
				logging.Base().Infof("have tx block verified， reset player deadline")
				fmt.Println("have tx block verified， reset player deadline")
				p.TimeOutAddDur = time.Now().Sub(p.ZeroTimeStamp)
				p.Deadline = filterTimeout + p.TimeOutAddDur

				logging.Base().Info("enter handle payloadVerified assemble")
				fmt.Println(time.Now().UTC(), "enter handle payloadVerified assemble")
				p.IsMakeProposal = true
				as := pseudonodeAction{T: assemble, Round: p.Round, Period: 0}
				actions = append(actions, as)
				//return actions
			}
			//if !p.IsMakeProposal {
			//	logging.Base().Info("enter handle payloadVerified assemble")
			//	fmt.Println(time.Now().UTC(), "enter handle payloadVerified assemble")
			//	p.IsMakeProposal = true
			//	as := pseudonodeAction{T: assemble, Round: p.Round, Period: 0}
			//	actions = append(actions, as)
			//	return actions
			//}
		}
		ef := r.dispatch(*p, delegatedE, proposalMachine, 0, 0, 0)
		switch ef.t() {
		case payloadMalformed:
			err := makeSerErrf("rejected message since it was invalid: %v", ef.(filteredEvent).Err)
			return append(actions, ignoreAction(e, err))
		case payloadRejected:
			return append(actions, ignoreAction(e, ef.(payloadProcessedEvent).Err))
		case payloadPipelined:
			ep := ef.(payloadProcessedEvent)
			if presentSelf {
				return append(actions, verifyPayloadSelfAction(e, ep.Round, ep.Period, ep.Pinned))
			}
			if ep.Round == p.Round {
				return append(actions, verifyPayloadAction(e, ep.Round, ep.Period, ep.Pinned))
			}
		}

		if !verifiedSeft {
			var uv unauthenticatedVote
			switch ef.t() {
			case payloadPipelined, payloadAccepted:
				uv = ef.(payloadProcessedEvent).Vote.u()
			case proposalCommittable:
				uv = ef.(committableEvent).Vote.u()
			}
			up := e.Input.UnauthenticatedProposal

			a := relayAction(e, protocol.ProposalPayloadTag, compoundMessage{Proposal: up, Vote: uv})
			actions = append(actions, a)
		}

		if ef.t() == proposalCommittable && p.Step <= cert {
			actions = append(actions, p.issueCertVote(r, ef.(committableEvent)))
		}
		return actions

	case votePresent, voteVerified:
		ef := r.dispatch(*p, delegatedE, voteMachine, 0, 0, 0)
		switch ef.t() {
		case voteMalformed:
			// TODO Add Metrics here to capture telemetryspec.VoteRejectedEvent details
			// 	Reason:           fmt.Sprintf("rejected malformed message: %v", e.Err),
			err := makeSerErrf("rejected message since it was invalid: %v", ef.(filteredEvent).Err)
			return append(actions, disconnectAction(e, err))
		case voteFiltered:
			err := ef.(filteredEvent).Err
			return append(actions, ignoreAction(e, err))
		}
		if e.t() == votePresent {
			uv := e.Input.UnauthenticatedVote
			return append(actions, verifyVoteAction(e, uv.R.Round, uv.R.Period, 0))
		} // else e.t() == voteVerified
		v := e.Input.Vote
		actions = append(actions, relayAction(e, protocol.AgreementVoteTag, v.u()))
		a1 := p.handle(r, ef)
		return append(actions, a1...)

	case bundlePresent, bundleVerified:
		ef := r.dispatch(*p, delegatedE, voteMachine, 0, 0, 0)
		switch ef.t() {
		case bundleMalformed:
			err := makeSerErrf("rejected message since it was invalid: %v", ef.(filteredEvent).Err)
			return append(actions, disconnectAction(e, err))
		case bundleFiltered:
			err := ef.(filteredEvent).Err
			return append(actions, ignoreAction(e, err))
		}
		if e.t() == bundlePresent {
			ub := e.Input.UnauthenticatedBundle
			return append(actions, verifyBundleAction(e, ub.Round, ub.Period))
		}
		a0 := relayAction(e, protocol.VoteBundleTag, ef.(thresholdEvent).Bundle)
		a1 := p.handle(r, ef)
		return append(append(actions, a0), a1...)
	}

	panic("bad event")
}

func getProtoFromEvent(eventProto ConsensusVersionView) protocol.ConsensusVersion {
	var version protocol.ConsensusVersion
	if eventProto.Err != nil {
		logging.Base().Errorf("failed to read protocol version for roundInterruptionEvent (proto %v): %v", eventProto.Version, eventProto.Err)
		version = protocol.ConsensusCurrentVersion
	} else {
		version = eventProto.Version
	}
	return version
}

//func (p *player) addProposeInfo(proposerAddress basics.Address) {
//	p.ProposalListMu.Lock()
//	defer p.ProposalListMu.Unlock()
//
//	var emptyAddress basics.Address
//	if bytes.Compare(proposerAddress[:], emptyAddress[:]) == 0 {
//		return
//	}
//	if p.ProposalList == nil {
//		p.ProposalList = make(map[period]map[basics.Address]round)
//	}
//	periodInfo := p.ProposalList[p.Period]
//	if periodInfo == nil || len(periodInfo) == 0 {
//		p.ProposalList[p.Period] = make(map[basics.Address]round)
//	}
//	p.ProposalList[p.Period][proposerAddress] = p.Round
//}

func makeConsensusWithSoftCertificate(p *player, cert Certificate) consensus.ConsensusInfo {
	var consensusInfo consensus.ConsensusInfo
	consensusInfo.Round = uint64(cert.Round)
	consensusInfo.Period = uint64(cert.Period)
	consensusInfo.Step = uint64(cert.Step)

	consensusInfo.MemoInfo = "softCommittee"
	for _, value := range cert.Votes {
		consensusInfo.SoftList = append(consensusInfo.SoftList, value.Sender.String())
	}
	return consensusInfo
}

func makeConsensusWithCertificate(p *player, cert Certificate) consensus.ConsensusInfo {
	var consensusInfo consensus.ConsensusInfo
	consensusInfo.Round = uint64(cert.Round)
	consensusInfo.Period = uint64(cert.Period)
	consensusInfo.Step = uint64(cert.Step)

	for _, value := range cert.Votes {
		consensusInfo.CertList = append(consensusInfo.CertList, value.Sender.String())
	}
	consensusInfo.MemoInfo = "certCommittee"

	return consensusInfo
}
