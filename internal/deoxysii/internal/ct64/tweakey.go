package ct64

import (
	"github.com/gh4rib/pqpg/internal/deoxysii/internal/api"
	aes "github.com/gh4rib/pqpg/internal/deoxysii/internal/ext/aes/ct64"
)

// Note: This is trivial to accelerate with vector ops.  Performance
// will likely be horrific without such things.  At the point where
// there's a vector unit, it's worth doing a vectorized AES
// implementation too.

func derivedKsOrtho(dkQs *[api.STKCount][8]uint64, derivedKs *[api.STKCount][api.STKSize]byte) {
	for i := 0; i <= api.Rounds; i++ {
		aes.RkeyOrtho(dkQs[i][:], derivedKs[i][:])
	}
}

func deriveSubTweakKeysx1(stks, dkQs *[api.STKCount][8]uint64, t *[api.TweakSize]byte) {
	var tk1 [api.STKSize]byte

	copy(tk1[:], t[:])
	aes.Load4xU32(&stks[0], tk1[:])
	aes.AddRoundKey(&stks[0], dkQs[0][:])

	for i := 1; i <= api.Rounds; i++ {
		api.H(&tk1)
		aes.Load4xU32(&stks[i], tk1[:])
		aes.AddRoundKey(&stks[i], dkQs[i][:])
	}
}

func deriveSubTweakKeysx4(stks, dkQs *[api.STKCount][8]uint64, t *[4][api.TweakSize]byte) {
	var tk1 [4][api.STKSize]byte

	for i := range t {
		copy(tk1[i][:], t[i][:])
	}
	aes.Load16xU32(&stks[0], tk1[0][:], tk1[1][:], tk1[2][:], tk1[3][:])
	aes.AddRoundKey(&stks[0], dkQs[0][:])

	for i := 1; i <= api.Rounds; i++ {
		for j := range t {
			api.H(&tk1[j])
		}
		aes.Load16xU32(&stks[i], tk1[0][:], tk1[1][:], tk1[2][:], tk1[3][:])
		aes.AddRoundKey(&stks[i], dkQs[i][:])
	}
}
