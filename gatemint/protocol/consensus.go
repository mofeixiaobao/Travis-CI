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

package protocol

// ConsensusVersion is a string that identifies a version of the
// consensus protocol.
type ConsensusVersion string

// ConsensusV7 increases MaxBalLookback to 320 in preparation for
// the twin seeds change.
const ConsensusV1 = ConsensusVersion("v1")

// ConsensusFuture is a protocol that should not appear in any production
// network, but is used to test features before they are released.
const ConsensusFuture = ConsensusVersion(
	"future",
)

// !!! ********************* !!!
// !!! *** Please update ConsensusCurrentVersion when adding new protocol versions *** !!!
// !!! ********************* !!!

// ConsensusCurrentVersion is the latest version and should be used
// when a specific version is not provided.
const ConsensusCurrentVersion = ConsensusV1

// ConsensusTest0 is a version of ConsensusV0 used for testing
// (it has different approved upgrade paths).
const ConsensusTest0 = ConsensusVersion("test0")

// ConsensusTest1 is an extension of ConsensusTest0 that
// supports a sorted-list balance commitment.
const ConsensusTest1 = ConsensusVersion("test1")

// ConsensusTestBigBlocks is a version of ConsensusV0 used for testing
// with big block size (large MaxTxnBytesPerBlock).
// at the time versioning was introduced.
const ConsensusTestBigBlocks = ConsensusVersion("test-big-blocks")

// ConsensusTestRapidRewardRecalculation is a version of ConsensusCurrentVersion
// that decreases the RewardRecalculationInterval greatly.
const ConsensusTestRapidRewardRecalculation = ConsensusVersion("test-fast-reward-recalculation")

// ConsensusTestFastUpgrade is meant for testing of protocol upgrades:
// during testing, it is equivalent to another protocol with the exception
// of the upgrade parameters, which allow for upgrades to take place after
// only a few rounds.
func ConsensusTestFastUpgrade(proto ConsensusVersion) ConsensusVersion {
	return "test-fast-upgrade-" + proto
}
