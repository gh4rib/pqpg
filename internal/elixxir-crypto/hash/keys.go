////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package hash includes a general-purpose hashing algorithm, blake2b,
// that should be suitable for most of our needs.
// It also includes functions to calculate an HMAC.
package hash

import (
	"hash"

	"github.com/gh4rib/pqpg/internal/elixxir-crypto/cyclic"

	"github.com/gh4rib/pqpg/internal/xx-network-crypto/csprng"
	"github.com/gh4rib/pqpg/internal/xx-network-crypto/large"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/hkdf"
)

type NewHash interface {
	New() hash.Hash
}

// ExpandKey is a function that receives a key and expands such key to the size
// of the prime group
func ExpandKey(h func() hash.Hash, g *cyclic.Group, key []byte,
	output *cyclic.Int) *cyclic.Int {
	keyGen := hkdf.Expand(h, key, nil)

	pBytes := g.GetPBytes()
	expandedKey, err := csprng.GenerateInGroup(pBytes, len(pBytes), keyGen)
	if err != nil {
		jww.FATAL.Panicf("Key expansion failure: %v", err)
	}

	keyInt := large.NewInt(0)
	keyInt.SetBytes(expandedKey)
	g.SetLargeInt(output, keyInt)

	return output
}
