package packet

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
	"github.com/klauspost/compress/zstd"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

const (
	SharedHeaderBoundary  = "-----BEGIN SHARED VAULT HEADER-----"
	SharedPayloadBoundary = "-----BEGIN SHARED VAULT PAYLOAD-----"
	SharedEndBoundary     = "-----END SHARED VAULT-----"
)

type SharedMetadata struct {
	AEADSuite      string   `json:"aead_suite"`
	Compression    string   `json:"compression"`
	Nonce          []byte   `json:"nonce"`
	VSSCommitments []string `json:"vss_commitments"` // The Public ECC Points locking the polynomial
}

// SharedVaultLock generates an Ed25519-based VSS polynomial, encrypts, and returns verified shares.
func SharedVaultLock(in io.Reader, out io.Writer, aeadSuite, compression string, parts, threshold int) ([]string, error) {
	if threshold > parts || threshold < 2 {
		return nil, errors.New("invalid VSS parameters")
	}

	registry := crypto.NewRegistry()
	aead, err := registry.GetAEAD(aeadSuite)
	if err != nil { return nil, err }

	// Initialize the v4 Edwards25519 Suite
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// 1. Generate Random Polynomial Coefficients over Ed25519 Scalar Field
	coeffs := make([]kyber.Scalar, threshold)
	for i := range coeffs {
		coeffs[i] = suite.Scalar().Pick(suite.RandomStream())
	}
	secretScalar := coeffs[0] // The Constant Term is our Vault Secret

	// 2. Derive the 32-byte AES/ChaCha Master Key using SHAKE256 KDF
	secBytes, _ := secretScalar.MarshalBinary()
	xof, _ := registry.GetXOF("SHAKE256")
	msgKey := xof.Derive(secBytes, aead.KeySize())

	// 3. Generate Feldman Public Commitments (C_j = a_j * G)
	var commitments []string
	for _, c := range coeffs {
		pt := suite.Point().Mul(c, nil)
		ptBytes, _ := pt.MarshalBinary()
		commitments = append(commitments, base64.StdEncoding.EncodeToString(ptBytes))
	}

	// 4. Evaluate Polynomial to Generate Shares (y = f(x))
	var encodedShares []string
	for i := 1; i <= parts; i++ {
		x := suite.Scalar().SetInt64(int64(i))
		y := suite.Scalar().Zero()

		// Horner's Method for Polynomial Evaluation
		for j := threshold - 1; j >= 0; j-- {
			y.Mul(y, x).Add(y, coeffs[j])
		}

		yBytes, _ := y.MarshalBinary()
		// Encode as "X-Coordinate.Y-Coordinate(Base64)"
		encodedShares = append(encodedShares, fmt.Sprintf("%d.%s", i, base64.StdEncoding.EncodeToString(yBytes)))
	}

	// 5. Initialize Streaming Metadata
	baseNonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, baseNonce)

	metadata := SharedMetadata{
		AEADSuite:      aeadSuite,
		Compression:    compression,
		Nonce:          baseNonce,
		VSSCommitments: commitments, // Bind the public math to the header
	}

	metaBytes, _ := json.Marshal(metadata)
	fmt.Fprintf(out, "%s\n%s\n%s\n", SharedHeaderBoundary, base64.StdEncoding.EncodeToString(metaBytes), SharedPayloadBoundary)

	// --- COMPRESSION PIPELINE ---
	compReader, compWriter := io.Pipe()
	go func() {
		var pipeErr error
		defer func() { compWriter.CloseWithError(pipeErr) }()
		switch compression {
		case "Zstd":
			zw, _ := zstd.NewWriter(compWriter)
			_, pipeErr = io.Copy(zw, in)
			zw.Close()
		case "Gzip":
			gw := gzip.NewWriter(compWriter)
			_, pipeErr = io.Copy(gw, in)
			gw.Close()
		default:
			_, pipeErr = io.Copy(compWriter, in)
		}
	}()

	// 6. Encrypt & Pad the Stream
	buf := make([]byte, ChunkSize)
	var chunkIndex uint64 = 0

	for {
		n, readErr := io.ReadFull(compReader, buf)
		if n > 0 {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				padLen := 4096 - (n % 4096)
				if padLen < 2 { padLen += 4096 }
				
				padBuf := make([]byte, padLen)
				_, _ = io.ReadFull(rand.Reader, padBuf)
				binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))
				
				finalPlaintext := append(buf[:n], padBuf...)
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, _ := aead.Seal(msgKey, chunkNonce, finalPlaintext, nil)
				
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				break
			} else {
				chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
				ciphertext, _ := aead.Seal(msgKey, chunkNonce, buf[:n], nil)
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
			}
		}

		if readErr == io.EOF {
			padLen := 4096
			padBuf := make([]byte, padLen)
			_, _ = io.ReadFull(rand.Reader, padBuf)
			binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))
			
			chunkNonce := buildChunkNonce(baseNonce, chunkIndex)
			ciphertext, _ := aead.Seal(msgKey, chunkNonce, padBuf, nil)
			fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF { return nil, readErr }
	}

	fmt.Fprintf(out, "%s\n", SharedEndBoundary)
	return encodedShares, nil 
}

// SharedVaultUnlock verifies shares against VSS commitments and reconstructs via Lagrange interpolation.
func SharedVaultUnlock(in io.Reader, out io.Writer, encodedShares []string) error {
	registry := crypto.NewRegistry()
	reader := bufio.NewReader(in)

	// 1. Parse the Header to extract the VSS Commitments
	for {
		line, err := reader.ReadString('\n')
		if err != nil { return errors.New("invalid file: missing outer boundary") }
		if strings.TrimSpace(line) == SharedHeaderBoundary { break }
	}

	metaB64, _ := reader.ReadString('\n')
	metaBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(metaB64))
	var metadata SharedMetadata
	if err := json.Unmarshal(metaBytes, &metadata); err != nil { return err }

	payloadBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(payloadBoundary) != SharedPayloadBoundary { return errors.New("invalid file structure") }

	// 2. FELDMAN VERIFICATION
	suite := edwards25519.NewBlakeSHA256Ed25519()
	
	var C []kyber.Point
	for _, cB64 := range metadata.VSSCommitments {
		b, _ := base64.StdEncoding.DecodeString(cB64)
		pt := suite.Point()
		_ = pt.UnmarshalBinary(b)
		C = append(C, pt)
	}

	var xs []kyber.Scalar
	var ys []kyber.Scalar

	for i, shareStr := range encodedShares {
		parts := strings.Split(shareStr, ".")
		if len(parts) != 2 { return fmt.Errorf("CRITICAL: Share %d is structurally invalid", i+1) }
		
		xInt, _ := strconv.ParseInt(parts[0], 10, 64)
		x := suite.Scalar().SetInt64(xInt)
		
		yBytes, _ := base64.StdEncoding.DecodeString(parts[1])
		y := suite.Scalar()
		_ = y.UnmarshalBinary(yBytes)

		// VSS Mathematical Proof: y * G == sum(x^j * C_j)
		lhs := suite.Point().Mul(y, nil)
		rhs := suite.Point().Null()
		xPow := suite.Scalar().SetInt64(1)
		
		for j := 0; j < len(C); j++ {
			term := suite.Point().Mul(xPow, C[j])
			rhs.Add(rhs, term)
			xPow.Mul(xPow, x)
		}

		if !lhs.Equal(rhs) {
			return fmt.Errorf("FELDMAN VSS ALARM: Share %d is a forgery! It does not belong to this vault", i+1)
		}

		xs = append(xs, x)
		ys = append(ys, y)
	}

	// 3. LAGRANGE INTERPOLATION (Reconstruct the Constant Term)
	secret := suite.Scalar().Zero()
	for i := 0; i < len(xs); i++ {
		num := suite.Scalar().SetInt64(1)
		den := suite.Scalar().SetInt64(1)

		for j := 0; j < len(xs); j++ {
			if i == j { continue }
			negXj := suite.Scalar().Neg(xs[j])
			num.Mul(num, negXj)

			diff := suite.Scalar().Sub(xs[i], xs[j])
			den.Mul(den, diff)
		}

		li := suite.Scalar().Mul(num, suite.Scalar().Inv(den))
		term := suite.Scalar().Mul(ys[i], li)
		secret.Add(secret, term)
	}

	// 4. DECRYPTION PIPELINE (Initialize cipher first)
	aead, err := registry.GetAEAD(metadata.AEADSuite)
	if err != nil { 
		return fmt.Errorf("failed to load cipher suite: %w", err) 
	}

	// Derive Master Key
	secBytes, _ := secret.MarshalBinary()
	xof, _ := registry.GetXOF("SHAKE256")
	msgKey := xof.Derive(secBytes, aead.KeySize())

	decReader, decWriter := io.Pipe()

	go func() {
		var loopErr error
		defer func() { decWriter.CloseWithError(loopErr) }()

		var chunkIndex uint64 = 0
		var prevPlaintext []byte 

		for {
			line, err := reader.ReadString('\n')
			line = strings.TrimSpace(line)

			if line == SharedEndBoundary {
				if len(prevPlaintext) < 2 { loopErr = errors.New("corrupt padding"); return }
				padLen := binary.LittleEndian.Uint16(prevPlaintext[len(prevPlaintext)-2:])
				decWriter.Write(prevPlaintext[:len(prevPlaintext)-int(padLen)])
				break
			}
			if line == "" && err == nil { continue }
			if err != nil { loopErr = errors.New("unexpected EOF"); return }

			ciphertext, _ := base64.StdEncoding.DecodeString(line)
			chunkNonce := buildChunkNonce(metadata.Nonce, chunkIndex)
			
			plaintext, err := aead.Open(msgKey, chunkNonce, ciphertext, nil)
			if err != nil { loopErr = errors.New("CRITICAL: Decryption failed. Master Key reconstructed incorrectly"); return }

			if prevPlaintext != nil { decWriter.Write(prevPlaintext) }
			prevPlaintext = plaintext 
			chunkIndex++
		}
	}()

	var errOut error
	switch metadata.Compression {
	case "Zstd":
		zr, _ := zstd.NewReader(decReader)
		defer zr.Close()
		_, errOut = io.Copy(out, zr)
	case "Gzip":
		gr, _ := gzip.NewReader(decReader)
		defer gr.Close()
		_, errOut = io.Copy(out, gr)
	default:
		_, errOut = io.Copy(out, decReader)
	}

	return errOut
}