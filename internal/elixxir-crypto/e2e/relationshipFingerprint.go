////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"github.com/gh4rib/pqpg/internal/elixxir-crypto/cyclic"
	"github.com/gh4rib/pqpg/internal/elixxir-crypto/hash"

	"github.com/gh4rib/pqpg/internal/xx-network-primitives/id"
	jww "github.com/spf13/jwalterweatherman"
)

// creates a unique relationship fingerprint which can be used to ensure keys
// are unique and that message IDs are unique
func MakeRelationshipFingerprint(pubkeyA, pubkeyB *cyclic.Int, sender,
	receiver *id.ID) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Failed to get hash to make relationship"+
			" fingerprint with: %s", err)
	}

	switch pubkeyA.Cmp(pubkeyB) {
	case 1:
		h.Write(pubkeyA.Bytes())
		h.Write(pubkeyB.Bytes())
	default:
		jww.WARN.Printf("Public keys the same, relationship " +
			"fingerproint uniqueness not assured")
		fallthrough
	case -1:
		h.Write(pubkeyB.Bytes())
		h.Write(pubkeyA.Bytes())
	}

	h.Write(sender.Bytes())
	h.Write(receiver.Bytes())
	return h.Sum(nil)
}
