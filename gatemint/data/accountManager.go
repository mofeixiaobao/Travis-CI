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

package data

import (
	"fmt"

	"github.com/gatechain/go-deadlock"

	"github.com/gatechain/gatemint/config"
	"github.com/gatechain/gatemint/data/account"
	"github.com/gatechain/gatemint/data/basics"
	"github.com/gatechain/logging"
	"github.com/gatechain/logging/telemetryspec"
)

// AccountManager loads and manages accounts for the node
type AccountManager struct {
	mu deadlock.Mutex

	partIntervals map[account.ParticipationInterval]account.Participation

	// Map to keep track of accounts for which we've sent
	// AccountRegistered telemetry events
	registeredAccounts map[string]bool

	log logging.Logger
}

// MakeAccountManager creates a new AccountManager with a custom logger
func MakeAccountManager(log logging.Logger) *AccountManager {
	manager := &AccountManager{}
	manager.log = log
	manager.partIntervals = make(map[account.ParticipationInterval]account.Participation)
	manager.registeredAccounts = make(map[string]bool)

	return manager
}

// Keys returns a list of Participation accounts.
func (manager *AccountManager) Keys() (out []account.Participation) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partIntervals {
		out = append(out, part)
	}
	return out
}

// AddParticipation adds a new account.Participation to be managed.
// The return value indicates if the key has been added (true) or
// if this is a duplicate key (false).
func (manager *AccountManager) AddParticipation(participation account.Participation) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	address := participation.Address()

	interval := account.ParticipationInterval{
		Address: address,
	}

	// Check if we already have participation keys for this address in this interval
	_, alreadyPresent := manager.partIntervals[interval]
	if alreadyPresent {
		return false
	}

	manager.partIntervals[interval] = participation

	addressString := address.String()
	manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.PartKeyRegisteredEvent, telemetryspec.PartKeyRegisteredEventDetails{
		Address: addressString,
	})

	_, has := manager.registeredAccounts[addressString]
	if !has {
		manager.registeredAccounts[addressString] = true

		manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.AccountRegisteredEvent, telemetryspec.AccountRegisteredEventDetails{
			Address: addressString,
		})
	}

	return true
}

// DeleteOldKeys deletes all accounts' ephemeral keys strictly older than the
// current round.
func (manager *AccountManager) DeleteOldKeys(current basics.Round, proto config.ConsensusParams) {
	manager.mu.Lock()
	pendingItems := make(map[string]<-chan error, len(manager.partIntervals))
	func() {
		defer manager.mu.Unlock()
		for _, part := range manager.partIntervals {
			// we pre-create the reported error string here, so that we won't need to have the participation key object if error is detected.
			errString := fmt.Sprintf("AccountManager.DeleteOldKeys(%d): key for %s ",
				current, part.Address().String())
			errCh := part.DeleteOldKeys(current, proto)

			pendingItems[errString] = errCh
		}
	}()

	// wait all all disk flushes, and report errors as they appear.
	for errString, errCh := range pendingItems {
		err := <-errCh
		if err != nil {
			logging.Base().Warnf("%s: %v", errString, err)
		}
	}
}
