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

const responseKeySalt = "singleUseResponseKeySalt"

// NewResponseKey generates the key for the response message that corresponds
// with the given key number.
func NewResponseKey(dhKey *cyclic.Int, keyNum uint64) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf(
			"[SU] Failed to create new hash for single-use response key: %+v", err)
	}

	keyNumBytes := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(keyNumBytes, keyNum)

	// Hash the DH key, key number, and salt
	h.Write(dhKey.Bytes())
	h.Write(keyNumBytes)
	h.Write([]byte(responseKeySalt))

	// Get hash bytes
	return h.Sum(nil)
}
