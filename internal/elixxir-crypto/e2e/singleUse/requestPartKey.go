////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/binary"

	"github.com/gh4rib/pqpg/internal/elixxir-crypto/cyclic"
	"github.com/gh4rib/pqpg/internal/elixxir-crypto/hash"

	jww "github.com/spf13/jwalterweatherman"
)

const requestPartKeySalt = "singleUseRequestKeySalt"

// NewRequestPartKey generates the key for the request message that corresponds
// with the given key number.
func NewRequestPartKey(dhKey *cyclic.Int, keyNum uint64) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf(
			"[SU] Failed to create new hash for single-use request key: %v", err)
	}

	keyNumBytes := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(keyNumBytes, keyNum)

	// Hash the DH key, key number, and salt
	h.Write(dhKey.Bytes())
	h.Write(keyNumBytes)
	h.Write([]byte(requestPartKeySalt))

	// Get hash bytes
	return h.Sum(nil)
}
