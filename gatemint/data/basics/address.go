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

package basics

import (
	"bytes"
	"encoding/base32"
	"fmt"

	"github.com/gatechain/crypto"
	"math"
)

type (
	// Address is a unique identifier corresponding to ownership of money
	Address crypto.Digest

	// AddressSlice is used for address sort
	AddressSlice []Address
)

const (
	checksumLength = 4
)

// GetChecksum returns the checksum as []byte
// Checksum in Algorand are the last 4 bytes of the shortAddress Hash. H(Address)[28:]
func (addr Address) GetChecksum() []byte {
	shortAddressHash := crypto.Hash(addr[:])
	checksum := shortAddressHash[len(shortAddressHash)-checksumLength:]
	return checksum
}

// GetUserAddress returns the human-readable, checksummed version of the address
func (addr Address) GetUserAddress() string {
	return addr.String()
}

func (a AddressSlice) Len() int {
	return len(a)
}
func (a AddressSlice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a AddressSlice) Less(i, j int) bool {
	compareResult := bytes.Compare(a[i][:], a[j][:])
	if compareResult <= 0 {
		return true
	} else {
		return false
	}
}

// Conver []byte address to Address object
func ConverAddress(address []byte) Address {
	var addr Address

	copy(addr[:], address[:int(math.Min(float64(len(addr)), float64(len(address))))])

	return addr
}

// UnmarshalChecksumAddress tries to unmarshal the checksummed address string.
func UnmarshalChecksumAddress(address string) (Address, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(address)
	if err != nil {
		return Address{}, fmt.Errorf("failed to decode address %s to base 32", address)
	}
	var short Address
	if len(decoded) < len(short) {
		return Address{}, fmt.Errorf("decoded bad addr: %s", address)
	}

	copy(short[:], decoded[:len(short)])
	incomingchecksum := decoded[len(decoded)-checksumLength:]

	calculatedchecksum := short.GetChecksum()
	isValid := bytes.Equal(incomingchecksum, calculatedchecksum)

	if !isValid {
		return Address{}, fmt.Errorf("address %s is malformed, checksum verification failed", address)
	}

	// Validate that we had a canonical string representation
	if short.String() != address {
		return Address{}, fmt.Errorf("address %s is non-canonical", address)
	}

	return short, nil
}

// String returns a string representation of Address
func (addr Address) String() string {
	var addrWithChecksum []byte
	addrWithChecksum = append(addr[:], addr.GetChecksum()...)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(addrWithChecksum)
}

// MarshalText returns the address string as an array of bytes
func (addr Address) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

// UnmarshalText initializes the Address from an array of bytes.
func (addr *Address) UnmarshalText(text []byte) error {
	address, err := UnmarshalChecksumAddress(string(text))
	if err == nil {
		*addr = address
		return nil
	}
	return err
}

// IsZero checks if an address is the zero value.
func (addr Address) IsZero() bool {
	return addr == Address{}
}
