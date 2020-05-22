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

import "github.com/gatechain/crypto"

// crypto.HashID is a domain separation prefix for an object type that might be hashed
// This ensures, for example, the hash of a transaction will never collide with the hash of a vote
//type crypto.HashID string

// Hash IDs for specific object types, in lexicographic order to avoid dups.
const (
	AuctionBid        crypto.HashID = "aB"
	AuctionDeposit    crypto.HashID = "aD"
	AuctionOutcomes   crypto.HashID = "aO"
	AuctionParams     crypto.HashID = "aP"
	AuctionSettlement crypto.HashID = "aS"

	AgreementSelector crypto.HashID = "AS"
	BlockHeader       crypto.HashID = "BH"
	BalanceRecord     crypto.HashID = "BR"
	Credential        crypto.HashID = "CR"
	Genesis           crypto.HashID = "GE"
	Message           crypto.HashID = "MX"
	NetPrioResponse   crypto.HashID = "NPR"
	OneTimeSigKey1    crypto.HashID = "OT1"
	OneTimeSigKey2    crypto.HashID = "OT2"
	PaysetFlat        crypto.HashID = "PF"
	Payload           crypto.HashID = "PL"
	Program           crypto.HashID = "Program"
	ProgramData       crypto.HashID = "ProgData"
	ProposerSeed      crypto.HashID = "PS"
	Seed              crypto.HashID = "SD"
	TestHashable      crypto.HashID = "TE"
	TxGroup           crypto.HashID = "TG"
	Transaction       crypto.HashID = "TX"
	Vote              crypto.HashID = "VO"
)
