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

package ledger

import (
	"github.com/gatechain/gatemint/data/basics"
)

// MoneyCount represents a total of token of a certain class
// of accounts (split up by their Status value).
type MoneyCount struct {
	// Sum of algos of all accounts in this class.
	Money basics.Power
}

//func (ac *MoneyCount) applyRewards(rewardsPerUnit uint64, ot *basics.OverflowTracker) {
//	rewardsGottenThisRound := basics.Power{Raw: ot.Mul(ac.RewardUnits, rewardsPerUnit)}
//	ac.Money = ot.AddA(ac.Money, rewardsGottenThisRound)
//}

// AccountTotals represents the totals of algos in the system
// grouped by different account status values.
type AccountTotals struct {
	Money basics.Power
	//Totals           MoneyCount
	//Offline          MoneyCount
	//NotParticipating MoneyCount
	//
	//// Total number of algos received per reward unit since genesis
	//RewardsLevel uint64
}

func (at *AccountTotals) addAccount(data basics.AccountData, ot *basics.OverflowTracker) {
	at.Money = ot.AddA(at.Money, data.Money())
}

func (at *AccountTotals) delAccount(data basics.AccountData, ot *basics.OverflowTracker) {
	at.Money = ot.SubA(at.Money, data.Money())
}
