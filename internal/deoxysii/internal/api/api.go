package api

import "encoding/binary"

const (
	BlockSize = 16

	KeySize   = 32
	Rounds    = 16
	TweakSize = 16
	TagSize   = 16

	STKSize  = 16
	STKCount = Rounds + 1

	PrefixADBlock  = 0x2 // 0010
	PrefixADFinal  = 0x6 // 0110
	PrefixMsgBlock = 0x0 // 0000
	PrefixMsgFinal = 0x4 // 0100
	PrefixTag      = 0x1 // 0001

	PrefixShift = 4
)

type Factory interface {
	// Name returns the name of the implementation.
	Name() string

	// New constructs a new keyed instance.
	New(key []byte) Instance
}

type Instance interface {
	// E authenticate and encrypts ad/msg with the nonce, and writes
	// ciphertext || tag to dst.
	E(nonce, dst, ad, msg []byte)

	// D decrypts and authenticates ad/ct with the nonce and writes
	// the plaintext to dst, and returns true iff the authentication
	// succeeds.
	//
	// Callers MUST scrub dst iff the call returns false.
	//
	// Note: dst is guaranteed NOT to alias with ct.
	D(nonce, dst, ad, ct []byte) bool
}

func XORBytes(out, a, b []byte, n int) {
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
}

func EncodeTagTweak(out *[TweakSize]byte, prefix byte, blockNr int) {
	// Technically, it's possible to use up to t - 4 (124) bits, for a
	// ludicrously large number of blocks.  Realistically, the numbers
	// won't ever get that high.
	binary.BigEndian.PutUint64(out[8:], uint64(blockNr))
	out[0] = prefix << PrefixShift
}

func EncodeEncTweak(out *[TweakSize]byte, tag []byte, blockNr int) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(blockNr))

	copy(out[:], tag[:])
	out[0] |= 0x80
	XORBytes(out[8:], out[8:], tmp[:], 8)
}
