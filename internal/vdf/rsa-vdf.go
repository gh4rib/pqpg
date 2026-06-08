package vdf

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"math/big"
)

// RSATimeLock implements the vdf.Engine interface using native RSA subgroups.
type RSATimeLock struct{}

// NativeZKP represents a Fiat-Shamir Sigma Protocol proof.
type NativeZKP struct {
	T []byte `json:"t"` // Commitment
	S []byte `json:"s"` // Response
}

func NewRSATimeLock() *RSATimeLock {
	return &RSATimeLock{}
}

func (r *RSATimeLock) Generate(operations uint64) (*Puzzle, error) {
	// 1. Generate Hidden Order Group Q_n
	p, _ := rand.Prime(rand.Reader, 2048)
	q, _ := rand.Prime(rand.Reader, 2048)
	n := new(big.Int).Mul(p, q)

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)

	// 2. Select generator 'g' in the subgroup of squares Q_n
	gRaw, _ := rand.Int(rand.Reader, n)
	g := new(big.Int).Exp(gRaw, big.NewInt(2), n)

	// 3. Time Machine: Calculate e = 2^T mod phi(N)
	two := big.NewInt(2)
	tBig := new(big.Int).SetUint64(operations)
	e := new(big.Int).Exp(two, tBig, phiN)

	// Target 'h' is the solved state
	h := new(big.Int).Exp(g, e, n)

	// 4. Native Zero-Knowledge Assertion (Fiat-Shamir Sigma Protocol)
	// We prove we know 'e' such that h = g^e mod N, without revealing 'e'.

	// A. Generate massive random masking value 'r' (N * 2^128) to prevent leakage
	maskBound := new(big.Int).Lsh(n, 128)
	randomR, _ := rand.Int(rand.Reader, maskBound)

	// B. Commitment: t = g^r mod N
	tCommit := new(big.Int).Exp(g, randomR, n)

	// C. Fiat-Shamir Challenge: c = SHA512(N || g || h || t)
	hash := sha512.New()
	hash.Write(n.Bytes())
	hash.Write(g.Bytes())
	hash.Write(h.Bytes())
	hash.Write(tCommit.Bytes())
	challengeC := new(big.Int).SetBytes(hash.Sum(nil))

	// D. Response: s = r + c * e (Calculated over the integers, NO modulo)
	cTimesE := new(big.Int).Mul(challengeC, e)
	responseS := new(big.Int).Add(randomR, cTimesE)

	// E. Serialize the ZKP
	zkp := NativeZKP{
		T: tCommit.Bytes(),
		S: responseS.Bytes(),
	}
	proofBytes, _ := json.Marshal(zkp)

	return &Puzzle{
		ModulusN:  n.Bytes(),
		Generator: g.Bytes(),
		TargetH:   h.Bytes(),
		TimeT:     operations,
		ZkProof:   proofBytes,
	}, nil
}

func (r *RSATimeLock) Verify(p *Puzzle) bool {
	n := new(big.Int).SetBytes(p.ModulusN)
	g := new(big.Int).SetBytes(p.Generator)
	h := new(big.Int).SetBytes(p.TargetH)

	var zkp NativeZKP
	if err := json.Unmarshal(p.ZkProof, &zkp); err != nil {
		return false
	}

	tCommit := new(big.Int).SetBytes(zkp.T)
	responseS := new(big.Int).SetBytes(zkp.S)

	// 1. Rebuild the Fiat-Shamir Challenge: c = SHA512(N || g || h || t)
	hash := sha512.New()
	hash.Write(n.Bytes())
	hash.Write(g.Bytes())
	hash.Write(h.Bytes())
	hash.Write(tCommit.Bytes())
	challengeC := new(big.Int).SetBytes(hash.Sum(nil))

	// 2. Cryptographic Verification Math
	// Check if: g^s mod N == (t * h^c) mod N

	// LHS: g^s mod N
	lhs := new(big.Int).Exp(g, responseS, n)

	// RHS: (t * h^c) mod N
	hToTheC := new(big.Int).Exp(h, challengeC, n)
	rhs := new(big.Int).Mul(tCommit, hToTheC)
	rhs.Mod(rhs, n)

	return lhs.Cmp(rhs) == 0
}

func (r *RSATimeLock) Solve(p *Puzzle) ([]byte, error) {
	n := new(big.Int).SetBytes(p.ModulusN)
	g := new(big.Int).SetBytes(p.Generator)
	h := new(big.Int).SetBytes(p.TargetH)

	current := new(big.Int).Set(g)
	two := big.NewInt(2)

	// The sequential delay function (Inherently non-parallelizable)
	for i := uint64(0); i < p.TimeT; i++ {
		current.Exp(current, two, n)
	}

	if current.Cmp(h) != 0 {
		return nil, fmt.Errorf("puzzle solution failed to match the verified target state")
	}

	return current.Bytes(), nil
}
