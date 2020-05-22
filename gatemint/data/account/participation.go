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

package account

import (
	"database/sql"
	"fmt"
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/gatemint/protocol"
	"github.com/gatechain/gatemint/util/db"
)

// A Participation encapsulates a set of secrets which allows a root to
// participate in consensus. All such accounts are associated with a parent root
// account via the Address (although this parent account may not be
// resident on this machine).
//
// Participations are allowed to vote on a user's behalf for some range of
// rounds. After this range, all remaining secrets are destroyed.
//
// For correctness, all Roots should have no more than one Participation
// globally active at any time. If this condition is violated, the Root may
// equivocate. (Algorand tolerates a limited fraction of misbehaving accounts.)
//
// Participations handle persistence and deletion of secrets.
type Participation struct {
	Parent basics.Address
	VRF    *crypto.VRFSecrets
	Voting *basics.OneTimeSignatureSecrets

	KeyDilution uint64

	Store db.Accessor
}

// Address returns the root account under which this participation account is registered.
func (part Participation) Address() basics.Address {
	return part.Parent
}

// DeleteOldKeys securely deletes ephemeral keys for rounds strictly older than the given round.
func (part Participation) DeleteOldKeys(current basics.Round, proto config.ConsensusParams) <-chan error {
	keyDilution := part.KeyDilution
	if keyDilution == 0 {
		keyDilution = proto.DefaultKeyDilution
	}

	part.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(current, keyDilution), keyDilution)

	errorCh := make(chan error, 1)
	deleteOldKeys := func(encodedVotingSecrets []byte) {
		errorCh <- part.Store.Atomic(func(tx *sql.Tx) error {
			_, err := tx.Exec("UPDATE ParticipationAccount SET voting=?", encodedVotingSecrets)
			if err != nil {
				return fmt.Errorf("Participation.DeleteOldKeys: failed to update account: %v", err)
			}
			return nil
		})
		close(errorCh)
	}
	encodedVotingSecrets := protocol.Encode(part.Voting.Snapshot())
	go deleteOldKeys(encodedVotingSecrets)
	return errorCh
}

// PersistNewParent writes a new parent address to the partkey database.
func (part Participation) PersistNewParent() error {
	return part.Store.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE ParticipationAccount SET parent=?", part.Parent[:])
		return err
	})
}

// VRFSecrets returns the VRF secrets associated with this Participation account.
func (part Participation) VRFSecrets() *crypto.VRFSecrets {
	return part.VRF
}

// VotingSecrets returns the voting secrets associated with this Participation account.
func (part Participation) VotingSecrets() *basics.OneTimeSignatureSecrets {
	return part.Voting
}

// VotingSigner returns the voting secrets associated with this Participation account,
// together with the KeyDilution value.
func (part Participation) VotingSigner() basics.OneTimeSigner {
	return basics.OneTimeSigner{
		OneTimeSignatureSecrets: part.Voting,
		OptionalKeyDilution:     part.KeyDilution,
	}
}

// PersistParticipationKeys initializes the passed database with participation keys
func PersistParticipationKeys(pfilename string, address basics.Address, firstValid, lastValid basics.Round, keyDilution uint64) (part Participation, err error) {
	store, err := db.MakeErasableAccessor(pfilename)
	if lastValid < firstValid {
		err = fmt.Errorf("PersistParticipationKeys: lastValid %d is after firstValid %d", lastValid, firstValid)
		store.Close()
		return
	}

	// Compute how many distinct participation keys we should generate
	firstID := basics.OneTimeIDForRound(firstValid, keyDilution)
	lastID := basics.OneTimeIDForRound(lastValid, keyDilution)
	numBatches := lastID.Batch - firstID.Batch + 1

	// Generate them
	v := basics.GenerateOneTimeSignatureSecrets(firstID.Batch, numBatches)

	// Also generate a new VRF key, which lives in the participation keys db
	vrf := crypto.GenerateVRFSecrets()

	// Construct the Participation containing these keys to be persisted
	part = Participation{
		Parent:      address,
		VRF:         vrf,
		Voting:      v,
		KeyDilution: keyDilution,
		Store:       store,
	}

	// Persist the Participation into the database
	err = part.Persist()
	return part, err
}

// FillDBWithParticipationKeys initializes the passed database with participation keys
func FillDBWithParticipationKeys(store db.Accessor, address basics.Address, firstValid, lastValid basics.Round, keyDilution uint64) (part Participation, err error) {
	if lastValid < firstValid {
		err = fmt.Errorf("FillDBWithParticipationKeys: lastValid %d is after firstValid %d", lastValid, firstValid)
		return
	}

	// Compute how many distinct participation keys we should generate
	firstID := basics.OneTimeIDForRound(firstValid, keyDilution)
	lastID := basics.OneTimeIDForRound(lastValid, keyDilution)
	numBatches := lastID.Batch - firstID.Batch + 1

	// Generate them
	v := basics.GenerateOneTimeSignatureSecrets(firstID.Batch, numBatches)

	// Also generate a new VRF key, which lives in the participation keys db
	vrf := crypto.GenerateVRFSecrets()

	// Construct the Participation containing these keys to be persisted
	part = Participation{
		Parent:      address,
		VRF:         vrf,
		Voting:      v,
		KeyDilution: keyDilution,
		Store:       store,
	}

	// Persist the Participation into the database
	err = part.Persist()
	return part, err
}

// Persist writes a Participation out to a database on the disk
func (part Participation) Persist() error {
	rawVRF := protocol.Encode(part.VRF)
	rawVoting := protocol.Encode(part.Voting.Snapshot())

	return part.Store.Atomic(func(tx *sql.Tx) error {
		err := partInstallDatabase(tx)
		if err != nil {
			return fmt.Errorf("Participation.persist: failed to install database: %v", err)
		}

		_, err = tx.Exec("INSERT INTO ParticipationAccount (parent, vrf, voting, keyDilution) VALUES (?, ?, ?, ?)",
			part.Parent[:], rawVRF, rawVoting, part.KeyDilution)
		if err != nil {
			return fmt.Errorf("Participation.persist: failed to insert account: %v", err)
		}
		return nil
	})
}

// Migrate is called when loading participation keys.
// Calls through to the migration helper and returns the result.
func Migrate(partDB db.Accessor) error {
	return partDB.Atomic(func(tx *sql.Tx) error {
		return partMigrate(tx)
	})
}

// Close closes the underlying database handle.
func (part Participation) Close() {
	part.Store.Close()
}
