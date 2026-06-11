package ct32

import (
	"encoding/binary"

	"github.com/gh4rib/pqpg/internal/deoxysii/internal/api"
	aes "github.com/gh4rib/pqpg/internal/deoxysii/internal/ext/aes/ct32"
)

func bcEncrypt(ciphertext []byte, stks *[api.STKCount][8]uint32, plaintext []byte) {
	_, _ = plaintext[:api.BlockSize], ciphertext[:api.BlockSize]

	var q [8]uint32
	aes.Load4xU32(&q, plaintext)
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	aes.Store4xU32(ciphertext, &q)
}

func bcKeystreamx2(ciphertext []byte, stks *[api.STKCount][8]uint32, nonce *[api.BlockSize]byte) {
	var q [8]uint32
	aes.RkeyOrtho(q[:], nonce[:])
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	_ = ciphertext[:api.BlockSize*2]
	aes.Store8xU32(ciphertext[0:], ciphertext[api.BlockSize:], &q)
}

func bcTagx1(tag []byte, stks *[api.STKCount][8]uint32, plaintext []byte) {
	_, _ = plaintext[:api.BlockSize], tag[:api.BlockSize]

	var q [8]uint32
	aes.Load4xU32(&q, plaintext)
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	tag0 := binary.LittleEndian.Uint32(tag[0:])
	tag1 := binary.LittleEndian.Uint32(tag[4:])
	tag2 := binary.LittleEndian.Uint32(tag[8:])
	tag3 := binary.LittleEndian.Uint32(tag[12:])

	aes.Ortho(q[:])
	tag0 ^= q[0]
	tag1 ^= q[2]
	tag2 ^= q[4]
	tag3 ^= q[6]

	binary.LittleEndian.PutUint32(tag[0:], tag0)
	binary.LittleEndian.PutUint32(tag[4:], tag1)
	binary.LittleEndian.PutUint32(tag[8:], tag2)
	binary.LittleEndian.PutUint32(tag[12:], tag3)
}

func bcTagx2(tag []byte, stks *[api.STKCount][8]uint32, plaintext []byte) {
	_, _ = plaintext[:api.BlockSize*2], tag[:api.BlockSize]

	var q [8]uint32
	aes.Load8xU32(&q, plaintext[0:], plaintext[api.BlockSize:])
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	tag0 := binary.LittleEndian.Uint32(tag[0:])
	tag1 := binary.LittleEndian.Uint32(tag[4:])
	tag2 := binary.LittleEndian.Uint32(tag[8:])
	tag3 := binary.LittleEndian.Uint32(tag[12:])

	aes.Ortho(q[:])
	tag0 ^= q[0]
	tag0 ^= q[1]
	tag1 ^= q[2]
	tag1 ^= q[3]
	tag2 ^= q[4]
	tag2 ^= q[5]
	tag3 ^= q[6]
	tag3 ^= q[7]

	binary.LittleEndian.PutUint32(tag[0:], tag0)
	binary.LittleEndian.PutUint32(tag[4:], tag1)
	binary.LittleEndian.PutUint32(tag[8:], tag2)
	binary.LittleEndian.PutUint32(tag[12:], tag3)
}
