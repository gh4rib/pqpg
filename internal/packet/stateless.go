package packet

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/identity"
	"github.com/klauspost/compress/zstd"
)

// StatelessSeal mimics traditional PGP. It generates a single shared secret without spinning a database ratchet.
func StatelessSeal(in io.Reader, out io.Writer, myKr *identity.Keyring, receiverProf *identity.Profile, compression string) error {
	registry := crypto.NewRegistry()

	msgID := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, msgID)

	// 1. Generate a single stateless Shared Secret using the receiver's Static Public Key
	ct, ss, err := crypto.EncapsulateEphemeral(receiverProf.KEMSuite, receiverProf.KEMPubKey)
	if err != nil {
		return err
	}

	// 2. Squeeze a 32-byte Message Key directly from the Shared Secret
	xof, _ := registry.GetXOF(receiverProf.XOFSuite)
	xof.Write([]byte("PQPG-Stateless-MasterKey"))
	xof.Write(ss)
	messageKey := xof.Derive(nil, 32)

	// 3. Derive Dual Keys for the Sealed Sender Protocol
	ratchetXOF, _ := registry.GetXOF(receiverProf.XOFSuite)
	ratchetXOF.Write([]byte("PQPG-SealedSender-Keys"))
	ratchetXOF.Write(messageKey)
	headerKey := ratchetXOF.Derive(nil, 32)
	payloadKey := ratchetXOF.Derive(nil, 32)

	aead, err := registry.GetAEAD(receiverProf.AEADSuite)
	if err != nil {
		return err
	}

	outerNonce := make([]byte, aead.NonceSize())
	innerNonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, outerNonce)
	_, _ = io.ReadFull(rand.Reader, innerNonce)

	// 4. Construct Outer Envelope
	outer := OuterMetadata{
		MessageID:      msgID,
		RatchetEncap:   ct,
		TargetKeyHint:  deriveKeyHint(receiverProf.KEMPubKey, receiverProf.XOFSuite), // <-- HASHED!
		MessageNumber:  0,
		OuterAEADSuite: receiverProf.AEADSuite,
		OuterXOFSuite:  receiverProf.XOFSuite,
		OuterNonce:     outerNonce,
		IsStateless:    true,
	}
	outerBytes, _ := json.Marshal(outer)
	fmt.Fprintf(out, "%s\n%s\n", OuterHeaderBoundary, base64.StdEncoding.EncodeToString(outerBytes))

	// 5. Construct Inner Envelope
	inner := InnerMetadata{
		SenderName:  myKr.Profile.Name,
		Timestamp:   time.Now().Unix(),
		DSASuite:    myKr.Profile.DSASuite,
		Compression: compression,
		InnerNonce:  innerNonce,
	}
	innerJSON, _ := json.Marshal(inner)
	innerPadded, err := padInnerHeader(innerJSON)
	if err != nil {
		return err
	}

	innerCiphertext, _ := aead.Seal(headerKey, outerNonce, innerPadded, outerBytes)
	fmt.Fprintf(out, "%s\n%s\n%s\n", InnerHeaderBoundary, base64.StdEncoding.EncodeToString(innerCiphertext), PayloadBoundary)

	fiatShamirXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	fiatShamirXOF.Write([]byte("PQPG-v1-FiatShamir-"))
	fiatShamirXOF.Write(outerBytes)
	fiatShamirXOF.Write(innerCiphertext)

	// 6. Compression Pipeline
	compReader, compWriter := io.Pipe()
	go func() {
		var err error
		defer func() { compWriter.CloseWithError(err) }()
		switch compression {
		case "Zstd":
			zw, _ := zstd.NewWriter(compWriter)
			_, err = io.Copy(zw, in)
			zw.Close()
		case "Gzip":
			gw := gzip.NewWriter(compWriter)
			_, err = io.Copy(gw, in)
			gw.Close()
		default:
			_, err = io.Copy(compWriter, in)
		}
	}()

	// 7. Stream and Encrypt Payload
	buf := make([]byte, ChunkSize)
	var chunkIndex uint64 = 0

	for {
		n, readErr := io.ReadFull(compReader, buf)
		if n > 0 {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				padLen := 4096 - (n % 4096)
				if padLen < 2 {
					padLen += 4096
				}

				padBuf := make([]byte, padLen)
				_, _ = io.ReadFull(rand.Reader, padBuf)
				binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))

				finalPlaintext := append(buf[:n], padBuf...)
				chunkNonce := buildChunkNonce(innerNonce, chunkIndex)
				ciphertext, _ := aead.Seal(payloadKey, chunkNonce, finalPlaintext, nil)

				fiatShamirXOF.Write(ciphertext)
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
				break
			} else {
				chunkNonce := buildChunkNonce(innerNonce, chunkIndex)
				ciphertext, _ := aead.Seal(payloadKey, chunkNonce, buf[:n], nil)

				fiatShamirXOF.Write(ciphertext)
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
				chunkIndex++
			}
		}
		if readErr == io.EOF {
			padLen := 4096
			padBuf := make([]byte, padLen)
			_, _ = io.ReadFull(rand.Reader, padBuf)
			binary.LittleEndian.PutUint16(padBuf[padLen-2:], uint16(padLen))

			chunkNonce := buildChunkNonce(innerNonce, chunkIndex)
			ciphertext, _ := aead.Seal(payloadKey, chunkNonce, padBuf, nil)

			fiatShamirXOF.Write(ciphertext)
			fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
			chunkIndex++
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("compression stream interrupted: %v", readErr)
		}
	}

	// 8. Finalize Signature
	digest := fiatShamirXOF.Derive(nil, 64)
	dsa, _ := registry.GetDSA(myKr.Profile.DSASuite)
	sig, err := dsa.Sign(myKr.DSAPrivKey, digest)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "%s\n%s\n%s\n", SignatureBoundary, base64.StdEncoding.EncodeToString(sig), EndBoundary)
	return nil
}

// StatelessOpen decrypts a fallback envelope with zero dependencies on BoltDB.
func StatelessOpen(in io.Reader, out io.Writer, sessionStore *identity.SessionStore, receiverKr *identity.Keyring, senderProf *identity.Profile) error {
	registry := crypto.NewRegistry()
	reader := bufio.NewReader(in)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return errors.New("invalid file: missing outer boundary")
		}
		if strings.TrimSpace(line) == OuterHeaderBoundary {
			break
		}
	}

	outerB64, _ := reader.ReadString('\n')
	outerBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(outerB64))
	if err != nil {
		return errors.New("corrupt outer base64 encoding")
	}

	var outer OuterMetadata
	if err := json.Unmarshal(outerBytes, &outer); err != nil {
		return err
	}

	if !outer.IsStateless {
		return errors.New("PROTOCOL COLLISION: This envelope belongs to an active Double Ratchet session. Please use Option 4 to decrypt.")
	}

	// BLOCK THE REPLAY ATTACK
	if err := sessionStore.CheckAndCacheMessage(outer.MessageID); err != nil {
		return err
	}

	expectedHint := deriveKeyHint(receiverKr.Profile.KEMPubKey, outer.OuterXOFSuite)
	if !bytes.Equal(outer.TargetKeyHint, expectedHint) {
		return errors.New("CRITICAL: Envelope targets an unknown or expired public key. Are you trying to open a file sent to someone else?")
	}

	innerBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(innerBoundary) != InnerHeaderBoundary {
		return errors.New("invalid file structure: expected inner metadata boundary")
	}

	innerCipherB64, _ := reader.ReadString('\n')
	innerCiphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(innerCipherB64))
	if err != nil {
		return errors.New("corrupt inner base64 encoding")
	}

	// 1. Recover the Shared Secret using our Static Private Key
	ss, err := crypto.DecapsulateEphemeral(receiverKr.Profile.KEMSuite, outer.RatchetEncap, receiverKr.KEMPrivKey)
	if err != nil {
		return errors.New("decapsulation failed: possible tampering")
	}

	// 2. Squeeze the Message Key directly from the Shared Secret
	xof, _ := registry.GetXOF(outer.OuterXOFSuite)
	xof.Write([]byte("PQPG-Stateless-MasterKey"))
	xof.Write(ss)
	messageKey := xof.Derive(nil, 32)

	ratchetXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	ratchetXOF.Write([]byte("PQPG-SealedSender-Keys"))
	ratchetXOF.Write(messageKey)
	headerKey := ratchetXOF.Derive(nil, 32)
	payloadKey := ratchetXOF.Derive(nil, 32)

	// 3. Decrypt and Unpad Inner Envelope
	aead, _ := registry.GetAEAD(outer.OuterAEADSuite)
	innerPadded, err := aead.Open(headerKey, outer.OuterNonce, innerCiphertext, outerBytes)
	if err != nil {
		return errors.New("CRITICAL: Sealed Sender Authentication Failed. Envelope tampered")
	}

	innerJSON, err := unpadInnerHeader(innerPadded)
	if err != nil {
		return err
	}

	var inner InnerMetadata
	if err := json.Unmarshal(innerJSON, &inner); err != nil {
		return err
	}

	if inner.SenderName != senderProf.Name {
		return fmt.Errorf("CRITICAL: Identity mismatch. Envelope sealed by '%s', but evaluated against '%s'", inner.SenderName, senderProf.Name)
	}

	payloadBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(payloadBoundary) != PayloadBoundary {
		return errors.New("invalid file structure: expected payload boundary")
	}

	fiatShamirXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	fiatShamirXOF.Write([]byte("PQPG-v1-FiatShamir-"))
	fiatShamirXOF.Write(outerBytes)
	fiatShamirXOF.Write(innerCiphertext)

	// 4. Decompression Pipeline
	decReader, decWriter := io.Pipe()
	go func() {
		var loopErr error
		defer func() { decWriter.CloseWithError(loopErr) }()

		var chunkIndex uint64 = 0
		var prevPlaintext []byte

		for {
			line, err := reader.ReadString('\n')
			line = strings.TrimSpace(line)

			if line == SignatureBoundary {
				if len(prevPlaintext) < 2 {
					loopErr = errors.New("corrupt padding structure")
					return
				}
				padLen := binary.LittleEndian.Uint16(prevPlaintext[len(prevPlaintext)-2:])
				decWriter.Write(prevPlaintext[:len(prevPlaintext)-int(padLen)])
				break
			}
			if line == "" && err == nil {
				continue
			}
			if err != nil {
				loopErr = errors.New("unexpected EOF")
				return
			}

			ciphertext, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				loopErr = errors.New("corrupt ciphertext")
				return
			}

			fiatShamirXOF.Write(ciphertext)
			chunkNonce := buildChunkNonce(inner.InnerNonce, chunkIndex)
			plaintext, err := aead.Open(payloadKey, chunkNonce, ciphertext, nil)
			if err != nil {
				loopErr = fmt.Errorf("CRITICAL: Payload chunk %d tampered", chunkIndex)
				return
			}

			if prevPlaintext != nil {
				decWriter.Write(prevPlaintext)
			}
			prevPlaintext = plaintext
			chunkIndex++
		}

		sigB64, _ := reader.ReadString('\n')
		signature, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))

		digest := fiatShamirXOF.Derive(nil, 64)
		dsa, _ := registry.GetDSA(inner.DSASuite)
		if !dsa.Verify(senderProf.DSAPubKey, digest, signature) {
			loopErr = errors.New("CRITICAL ALARM: FIAT-SHAMIR BINDING TAMPERED")
			return
		}
	}()

	var errOut error
	switch inner.Compression {
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
