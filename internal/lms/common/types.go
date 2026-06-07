package common

import (
	"crypto/sha256"
	"errors"
	"hash"
)

// ID is a fixed-legnth []byte used in LM-OTS and LM-OTS
type ID [ID_LEN]byte

type window uint8

const (
	WINDOW_W1 window = 1 << iota
	WINDOW_W2
	WINDOW_W4
	WINDOW_W8
)

// ByteWindow is the representation of bytes used in calculating LM-OTS signatures
type ByteWindow interface {
	Window() window
	Mask() uint8
}

// Return the actual window value
func (w window) Window() window {
	return w
}

// Return a bit mask (uint8) to bitwise AND with some value
func (w window) Mask() uint8 {
	switch w {
	case WINDOW_W1:
		return 0x01
	case WINDOW_W2:
		return 0x03
	case WINDOW_W4:
		return 0x0f
	case WINDOW_W8:
		return 0xff
	default:
		panic("invalid window")
	}
}

// LmsTypecode represents a typecode for LMS.
// See https://www.iana.org/assignments/leighton-micali-signatures/leighton-micali-signatures.xhtml#leighton-micali-signatures-1
type LmsTypecode uint32

const (
	LMS_RESERVED       LmsTypecode = 0x00000000
	LmsTypecodeFirst               = LMS_SHA256_M32_H5
	LMS_SHA256_M32_H5  LmsTypecode = 0x00000005
	LMS_SHA256_M32_H10 LmsTypecode = 0x00000006
	LMS_SHA256_M32_H15 LmsTypecode = 0x00000007
	LMS_SHA256_M32_H20 LmsTypecode = 0x00000008
	LMS_SHA256_M32_H25 LmsTypecode = 0x00000009
	LMS_SHA256_M24_H5  LmsTypecode = 0x0000000A
	LMS_SHA256_M24_H10 LmsTypecode = 0x0000000B
	LMS_SHA256_M24_H15 LmsTypecode = 0x0000000C
	LMS_SHA256_M24_H20 LmsTypecode = 0x0000000D
	LMS_SHA256_M24_H25 LmsTypecode = 0x0000000E
	LmsTypecodeLast                = LMS_SHA256_M24_H25
)

// LmotsTypecode represents a typecode for LM-OTS.
// See https://www.iana.org/assignments/leighton-micali-signatures/leighton-micali-signatures.xhtml#lm-ots-signatures
type LmotsTypecode uint32

const (
	LMOTS_RESERVED      LmotsTypecode = 0x00000000
	LmotsTypecodeFirst                = LMOTS_SHA256_N32_W1
	LMOTS_SHA256_N32_W1 LmotsTypecode = 0x00000001
	LMOTS_SHA256_N32_W2 LmotsTypecode = 0x00000002
	LMOTS_SHA256_N32_W4 LmotsTypecode = 0x00000003
	LMOTS_SHA256_N32_W8 LmotsTypecode = 0x00000004
	LMOTS_SHA256_N24_W1 LmotsTypecode = 0x00000005
	LMOTS_SHA256_N24_W2 LmotsTypecode = 0x00000006
	LMOTS_SHA256_N24_W4 LmotsTypecode = 0x00000007
	LMOTS_SHA256_N24_W8 LmotsTypecode = 0x00000008
	LmotsTypecodeLast                 = LMOTS_SHA256_N24_W8
)

// LmsAlgorithmType represents a specific instance of LMS
type LmsAlgorithmType interface {
	LmsType() (LmsTypecode, error)
	LmsParams() (LmsParam, error)
}

// LmsOtsAlgorithmType represents a specific instance of LM-OTS
type LmsOtsAlgorithmType interface {
	LmsOtsType() (LmotsTypecode, error)
	Params() (LmsOtsParam, error)
}

// Hasher represents a streaming hash function
type Hasher interface {
	New() hash.Hash
}

type Sha256Hasher struct{}

func (_ Sha256Hasher) New() hash.Hash {
	return sha256.New()
}

// LmsParam represents the parameters for a given instance of the LMS algorithm
type LmsParam struct {
	Hash Hasher // Used to return an instance of a hash function in streaming mode
	M    uint64 // number of bytes associated with each node
	H    uint64 // height of the tree
}

type LmsOtsParam struct {
	H       Hasher     // Used for hashing
	N       uint64     // number of bytes of the output of H
	W       ByteWindow // width (in bits) of Winternitz coefficients
	P       uint64     // number of N-byte elements that make up the signature
	LS      uint64     // left-shift used in checksum calculation
	SIG_LEN uint64     // total byte length for a valid signature
}

// Returns a LmsTypecode, given a uint32 of the same value
func Uint32ToLmsType(x uint32) LmsTypecode {
	return LmsTypecode(x)
}

// Returns a uint32 of the same value as the LmsTypecode
func (x LmsTypecode) ToUint32() uint32 {
	return uint32(x)
}

// Returns a LmsTypecode if within a valid range for LMS; otherwise, an error
func (x LmsTypecode) LmsType() (LmsTypecode, error) {
	if x >= LmsTypecodeFirst && x <= LmsTypecodeLast {
		return x, nil
	} else {
		return x, errors.New("LmsType(): invalid type code")
	}
}

// Returns the expected signature length for an LMS type, given an associated LM-OTS type
func (x LmsTypecode) LmsSigLength(otstc LmotsTypecode) (uint64, error) {
	if x >= LmsTypecodeFirst && x <= LmsTypecodeLast {
		params, err := x.LmsParams()
		if err != nil {
			return 0, err
		}
		otssiglen, err := otstc.LmsOtsSigLength()
		if err != nil {
			return 0, err
		}
		return uint64(4 + 4 + otssiglen + (params.H * params.M)), nil
	} else {
		return 0, errors.New("LmsSigLength(): invalid type code")
	}
}

// Returns a LmotsTypecode, given a uint32 of the same value
func Uint32ToLmotsType(x uint32) LmotsTypecode {
	return LmotsTypecode(x)
}

// Returns a uint32 of the same value as the LmotsTypecode
func (x LmotsTypecode) ToUint32() uint32 {
	return uint32(x)
}

// Returns a LmotsTypecode if within a valid range for LM-OTS; otherwise, an error
func (x LmotsTypecode) LmsOtsType() (LmotsTypecode, error) {
	if x >= LmotsTypecodeFirst && x <= LmotsTypecodeLast {
		return x, nil
	} else {
		return x, errors.New("LmsOtsType(): invalid type code")
	}
}

// Returns the expected byte length of a given LM-OTS signature algorithm
func (x LmotsTypecode) LmsOtsSigLength() (uint64, error) {
	if x >= LmotsTypecodeFirst && x <= LmotsTypecodeLast {
		params, err := x.Params()
		if err != nil {
			return 0, err
		}
		return params.SIG_LEN, nil
	} else {
		return 0, errors.New("LmsOtsSigLength(): invalid type code")
	}
}

// Returns a LmsParam corresponding to the LmsTypecode, x
func (x LmsTypecode) LmsParams() (LmsParam, error) {
	switch x {
	case LMS_SHA256_M32_H5:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    5,
		}, nil
	case LMS_SHA256_M32_H10:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    10,
		}, nil
	case LMS_SHA256_M32_H15:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    15,
		}, nil
	case LMS_SHA256_M32_H20:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    20,
		}, nil
	case LMS_SHA256_M32_H25:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    32,
			H:    25,
		}, nil
	case LMS_SHA256_M24_H5:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    24,
			H:    5,
		}, nil
	case LMS_SHA256_M24_H10:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    24,
			H:    10,
		}, nil
	case LMS_SHA256_M24_H15:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    24,
			H:    15,
		}, nil
	case LMS_SHA256_M24_H20:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    24,
			H:    20,
		}, nil
	case LMS_SHA256_M24_H25:
		return LmsParam{
			Hash: Sha256Hasher{},
			M:    24,
			H:    25,
		}, nil
	default:
		return LmsParam{}, errors.New("LmsParams(): invalid type code")
	}
}

// Returns a LmsOtsParam corresponding to the LmsTypecode, x
func (x LmotsTypecode) Params() (LmsOtsParam, error) {
	switch x {
	case LMOTS_SHA256_N32_W1:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W1,
			P:       265,
			LS:      7,
			SIG_LEN: 8516,
		}, nil
	case LMOTS_SHA256_N32_W2:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W2,
			P:       133,
			LS:      6,
			SIG_LEN: 4292,
		}, nil
	case LMOTS_SHA256_N32_W4:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W4,
			P:       67,
			LS:      4,
			SIG_LEN: 2180,
		}, nil
	case LMOTS_SHA256_N32_W8:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       sha256.Size,
			W:       WINDOW_W8,
			P:       34,
			LS:      0,
			SIG_LEN: 1124,
		}, nil
	case LMOTS_SHA256_N24_W1:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       24,
			W:       WINDOW_W1,
			P:       200,
			LS:      8,
			SIG_LEN: 4828,
		}, nil
	case LMOTS_SHA256_N24_W2:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       24,
			W:       WINDOW_W2,
			P:       101,
			LS:      6,
			SIG_LEN: 2452,
		}, nil
	case LMOTS_SHA256_N24_W4:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       24,
			W:       WINDOW_W4,
			P:       51,
			LS:      4,
			SIG_LEN: 1252,
		}, nil
	case LMOTS_SHA256_N24_W8:
		return LmsOtsParam{
			H:       Sha256Hasher{},
			N:       24,
			W:       WINDOW_W8,
			P:       26,
			LS:      0,
			SIG_LEN: 652,
		}, nil
	default:
		return LmsOtsParam{}, errors.New("Params(): invalid type code")
	}
}
