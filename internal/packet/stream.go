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



type OuterMetadata struct {
	MessageID          []byte `json:"message_id"`
	RatchetEncap       []byte `json:"ratchet_encap"`
	TargetPubKey       []byte `json:"target_pub_key"`
	SenderEphemeralPub []byte `json:"ephemeral_pub"`
	MessageNumber      uint32 `json:"msg_num"`
	OuterAEADSuite     string `json:"outer_aead"`
	OuterXOFSuite      string `json:"outer_xof"`
	OuterNonce         []byte `json:"outer_nonce"`
	IsStateless        bool   `json:"is_stateless"`
	TargetKeyHint      []byte `json:"target_key_hint"`
}

type InnerMetadata struct {
	SenderName  string `json:"sender_name"`
	Timestamp   int64  `json:"timestamp"`
	DSASuite    string `json:"dsa_suite"`
	Compression string `json:"compression"`
	InnerNonce  []byte `json:"inner_nonce"`
}

func buildChunkNonce(baseNonce []byte, counter uint64) []byte {
	nonce := make([]byte, len(baseNonce))
	copy(nonce, baseNonce)
	offset := len(nonce) - 8
	if offset < 0 {
		offset = 0
	}
	for i := 0; i < 8 && offset+i < len(nonce); i++ {
		nonce[offset+i] ^= byte(counter >> (8 * (7 - i)))
	}
	return nonce
}

func padInnerHeader(data []byte) ([]byte, error) {
	if len(data) > InnerHeaderSize-2 {
		return nil, errors.New("CRITICAL: Inner metadata exceeds padding capacity")
	}
	padded := make([]byte, InnerHeaderSize)
	copy(padded, data)
	_, _ = io.ReadFull(rand.Reader, padded[len(data):InnerHeaderSize-2])
	binary.LittleEndian.PutUint16(padded[InnerHeaderSize-2:], uint16(len(data)))
	return padded, nil
}

func unpadInnerHeader(data []byte) ([]byte, error) {
	if len(data) != InnerHeaderSize {
		return nil, errors.New("CRITICAL: Inner header block is not exactly 1024 bytes")
	}
	trueLen := int(binary.LittleEndian.Uint16(data[InnerHeaderSize-2:]))
	if trueLen > InnerHeaderSize-2 {
		return nil, errors.New("CRITICAL: Inner header length marker corrupted")
	}
	return data[:trueLen], nil
}

// StreamSeal implements the Asymmetric Sender state of the Double Ratchet
func StreamSeal(in io.Reader, out io.Writer, sessionStore *identity.SessionStore, myKr *identity.Keyring, receiverProf *identity.Profile, compression string) error {
	registry := crypto.NewRegistry()
	contactID := receiverProf.Fingerprint

	msgID := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, msgID)

	state, err := sessionStore.LoadState(contactID)
	if err != nil {
		if errors.Is(err, identity.ErrSessionNotFound) {
			// BOOTSTRAP PHASE
			ct, ss, err := crypto.EncapsulateEphemeral(receiverProf.KEMSuite, receiverProf.KEMPubKey)
			if err != nil {
				return err
			}

			root, sendChain := crypto.AdvanceRootRatchet(receiverProf.XOFSuite, make([]byte, 32), ss)
			pub, priv, err := crypto.GenerateEphemeralKEM(myKr.Profile.KEMSuite)
			if err != nil {
				return err
			}

			state = &identity.RatchetState{
				ContactID:         contactID,
				RootKey:           root,
				SendChainKey:      sendChain,
				ReceiveChainKey:   make([]byte, 32),
				MyEphemeralPriv:   priv,
				MyEphemeralPub:    pub,
				TheirEphemeralPub: receiverProf.KEMPubKey,
				NeedsRootSpin:     false,
				LastSentEncap:     ct,
				SkippedKeys:       make(map[string][]byte),
				SessionXOFSuite:   receiverProf.XOFSuite,
			}
		} else {
			return fmt.Errorf("failed to read offline session database: %w", err)
		}
	}

	// ASYMMETRIC PING-PONG
	if state.NeedsRootSpin {
		pub, priv, err := crypto.GenerateEphemeralKEM(myKr.Profile.KEMSuite)
		if err != nil {
			return err
		}

		ct, ss, err := crypto.EncapsulateEphemeral(receiverProf.KEMSuite, state.TheirEphemeralPub)
		if err != nil {
			return err
		}

		root, sendChain := crypto.AdvanceRootRatchet(receiverProf.XOFSuite, state.RootKey, ss)

		state.RootKey = root
		state.SendChainKey = sendChain
		state.PreviousEphemeralPriv = state.MyEphemeralPriv
		state.PreviousEphemeralPub = state.MyEphemeralPub // <-- BACKUP THE PUBLIC KEY
		state.MyEphemeralPub = pub
		state.MyEphemeralPriv = priv
		state.SendCount = 0
		state.NeedsRootSpin = false
		state.LastSentEncap = ct
	}

	newSendChain, messageKey := crypto.AdvanceSymmetricRatchet(receiverProf.XOFSuite, state.SendChainKey)
	state.SendChainKey = newSendChain
	state.SendCount++

	if err := sessionStore.SaveState(state); err != nil {
		return fmt.Errorf("failed to commit ratchet state to disk: %w", err)
	}

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

	outer := OuterMetadata{
		MessageID:          msgID,
		RatchetEncap:       state.LastSentEncap,
		TargetKeyHint:      deriveKeyHint(state.TheirEphemeralPub, receiverProf.XOFSuite), // <-- HASHED!
		SenderEphemeralPub: state.MyEphemeralPub,
		MessageNumber:      state.SendCount,
		OuterAEADSuite:     receiverProf.AEADSuite,
		OuterXOFSuite:      receiverProf.XOFSuite,
		OuterNonce:         outerNonce,
	}
	outerBytes, _ := json.Marshal(outer)
	fmt.Fprintf(out, "%s\n%s\n", OuterHeaderBoundary, base64.StdEncoding.EncodeToString(outerBytes))

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

	digest := fiatShamirXOF.Derive(nil, 64)
	dsa, _ := registry.GetDSA(myKr.Profile.DSASuite)
	sig, err := dsa.Sign(myKr.DSAPrivKey, digest)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "%s\n%s\n%s\n", SignatureBoundary, base64.StdEncoding.EncodeToString(sig), EndBoundary)
	return nil
}

// StreamOpen implements the Asymmetric Receiver state of the Double Ratchet
func StreamOpen(in io.Reader, out io.Writer, sessionStore *identity.SessionStore, receiverKr *identity.Keyring, senderProf *identity.Profile) error {
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

	innerBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(innerBoundary) != InnerHeaderBoundary {
		return errors.New("invalid file structure: expected inner metadata boundary")
	}

	innerCipherB64, _ := reader.ReadString('\n')
	innerCiphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(innerCipherB64))
	if err != nil {
		return errors.New("corrupt inner base64 encoding")
	}

	contactID := senderProf.Fingerprint
	state, err := sessionStore.LoadState(contactID)

	if err != nil {
		if errors.Is(err, identity.ErrSessionNotFound) {
			if len(outer.RatchetEncap) == 0 {
				return errors.New("no active session found, and envelope contains no KEM ciphertext")
			}

			// SECURITY UPGRADE: Verify against the 32-byte Hint, not the plaintext key!
			expectedStaticHint := deriveKeyHint(receiverKr.Profile.KEMPubKey, outer.OuterXOFSuite)
			if !bytes.Equal(outer.TargetKeyHint, expectedStaticHint) {
				return errors.New("CRITICAL: Initial message does not target the static profile key. Envelope invalid.")
			}

			// BOOTSTRAP PHASE
			ss, err := crypto.DecapsulateEphemeral(receiverKr.Profile.KEMSuite, outer.RatchetEncap, receiverKr.KEMPrivKey)
			if err != nil {
				return errors.New("bootstrap decapsulation failed: unauthorized receiver")
			}

			root, recvChain := crypto.AdvanceRootRatchet(outer.OuterXOFSuite, make([]byte, 32), ss)

			state = &identity.RatchetState{
				ContactID:         contactID,
				RootKey:           root,
				SendChainKey:      make([]byte, 32),
				ReceiveChainKey:   recvChain,
				MyEphemeralPriv:   nil,
				MyEphemeralPub:    nil,
				TheirEphemeralPub: outer.SenderEphemeralPub,
				NeedsRootSpin:     true,
				SkippedKeys:       make(map[string][]byte),
				SessionXOFSuite:   outer.OuterXOFSuite,
			}
		} else {
			return err
		}
	}

	var isAlphaGlare bool
	var messageKey []byte

	// ASYMMETRIC PING-PONG
	if string(outer.SenderEphemeralPub) != string(state.TheirEphemeralPub) {
		var ss []byte
		var isStaticDecap bool
		var errDecap error

		// Generate the expected 32-byte hints for routing
		expectedStaticHint := deriveKeyHint(receiverKr.Profile.KEMPubKey, outer.OuterXOFSuite)
		expectedCurrentHint := deriveKeyHint(state.MyEphemeralPub, outer.OuterXOFSuite)
		expectedPrevHint := deriveKeyHint(state.PreviousEphemeralPub, outer.OuterXOFSuite)

		// DETERMINISTIC KEY ROUTING: Checking the hints!
		if bytes.Equal(outer.TargetKeyHint, expectedStaticHint) {
			ss, errDecap = crypto.DecapsulateEphemeral(receiverKr.Profile.KEMSuite, outer.RatchetEncap, receiverKr.KEMPrivKey)
			if errDecap != nil {
				return errors.New("static decapsulation failed")
			}
			isStaticDecap = true

			if state.ReceiveCount == 0 {
				if receiverKr.Profile.Fingerprint > senderProf.Fingerprint {
					isAlphaGlare = true
					fmt.Println("\n[*] GLARE RESOLUTION: Simultaneous Bootstrap Detected!")
					fmt.Println("[*] You are the ALPHA identity. Processing ghost-decryption. Your session survives.")
				} else {
					fmt.Println("\n[*] GLARE RESOLUTION: Simultaneous Bootstrap Detected!")
					fmt.Println("[*] You are the BETA identity. Wiping local collision and adopting their session parameters...")
					state.MyEphemeralPriv = nil
					state.MyEphemeralPub = nil
					state.PreviousEphemeralPriv = nil
					state.PreviousEphemeralPub = nil
					state.NeedsRootSpin = true
					state.SendCount = 0
				}
			}
		} else if bytes.Equal(outer.TargetKeyHint, expectedCurrentHint) {
			ss, errDecap = crypto.DecapsulateEphemeral(receiverKr.Profile.KEMSuite, outer.RatchetEncap, state.MyEphemeralPriv)
			if errDecap != nil {
				return errors.New("ephemeral decapsulation failed")
			}
		} else if len(state.PreviousEphemeralPub) > 0 && bytes.Equal(outer.TargetKeyHint, expectedPrevHint) {
			ss, errDecap = crypto.DecapsulateEphemeral(receiverKr.Profile.KEMSuite, outer.RatchetEncap, state.PreviousEphemeralPriv)
			if errDecap != nil {
				return errors.New("historical ephemeral decapsulation failed")
			}
		} else {
			return errors.New("CRITICAL: Envelope targets an unknown or expired public key. Are you trying to open a file sent to someone else?")
		}

		var root, recvChain []byte
		if isStaticDecap {
			root, recvChain = crypto.AdvanceRootRatchet(outer.OuterXOFSuite, make([]byte, 32), ss)
		} else {
			root, recvChain = crypto.AdvanceRootRatchet(outer.OuterXOFSuite, state.RootKey, ss)
		}

		// --- SECURITY UPGRADE: THE 1000-MESSAGE BOUNDARY ---
		if outer.MessageNumber > state.ReceiveCount+1000 {
			return errors.New("CRITICAL ALARM: Message exceeds the 1000-skip boundary. Possible State Exhaustion Attack dropped.")
		}

		if isAlphaGlare {
			tempChain := recvChain
			for i := uint32(0); i < outer.MessageNumber; i++ {
				newChain, mk := crypto.AdvanceSymmetricRatchet(outer.OuterXOFSuite, tempChain)
				tempChain = newChain
				if i+1 == outer.MessageNumber {
					messageKey = mk
				} else {
					missedKeyStr := fmt.Sprintf("%x_%d", outer.SenderEphemeralPub[:8], i+1)
					state.SkippedKeys[missedKeyStr] = mk
				}
			}
		} else {
			state.RootKey = root
			state.ReceiveChainKey = recvChain
			state.ReceiveCount = 0
			state.TheirEphemeralPub = outer.SenderEphemeralPub
			state.NeedsRootSpin = true
		}
	}

	// NORMAL SYMMETRIC RATCHET
	if !isAlphaGlare {
		// --- SECURITY UPGRADE: THE 1000-MESSAGE BOUNDARY ---
		if outer.MessageNumber > state.ReceiveCount+1000 {
			return errors.New("CRITICAL ALARM: Message exceeds the 1000-skip boundary. Possible State Exhaustion Attack dropped.")
		}

		vaultKey := fmt.Sprintf("%x_%d", outer.SenderEphemeralPub[:8], outer.MessageNumber)

		if savedKey, exists := state.SkippedKeys[vaultKey]; exists {
			messageKey = savedKey
			delete(state.SkippedKeys, vaultKey)
		} else {
			for state.ReceiveCount < outer.MessageNumber {
				newRecvChain, mk := crypto.AdvanceSymmetricRatchet(outer.OuterXOFSuite, state.ReceiveChainKey)
				state.ReceiveChainKey = newRecvChain
				state.ReceiveCount++

				if state.ReceiveCount == outer.MessageNumber {
					messageKey = mk
				} else {
					missedKeyStr := fmt.Sprintf("%x_%d", outer.SenderEphemeralPub[:8], state.ReceiveCount)
					state.SkippedKeys[missedKeyStr] = mk
				}
			}
		}
	}

	if messageKey == nil {
		return fmt.Errorf("CRITICAL: Ratchet desynchronized. Message %d was already processed or skipped. Are you re-testing an old file?", outer.MessageNumber)
	}

	ratchetXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	ratchetXOF.Write([]byte("PQPG-SealedSender-Keys"))
	ratchetXOF.Write(messageKey)
	headerKey := ratchetXOF.Derive(nil, 32)
	payloadKey := ratchetXOF.Derive(nil, 32)

	// 4. Decrypt and Unpad Inner Envelope
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

	if err := sessionStore.CheckAndCacheMessage(outer.MessageID); err != nil {
		return err
	}

	if err := sessionStore.SaveState(state); err != nil {
		return fmt.Errorf("failed to commit ratchet state to disk: %w", err)
	}

	payloadBoundary, _ := reader.ReadString('\n')
	if strings.TrimSpace(payloadBoundary) != PayloadBoundary {
		return errors.New("invalid file structure: expected payload boundary")
	}

	fiatShamirXOF, _ := registry.GetXOF(outer.OuterXOFSuite)
	fiatShamirXOF.Write([]byte("PQPG-v1-FiatShamir-"))
	fiatShamirXOF.Write(outerBytes)
	fiatShamirXOF.Write(innerCiphertext)

	// 5. Decompression Pipeline
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

// deriveKeyHint generates a 32-byte one-way digest to safely identify KEM keys without leaking them.
func deriveKeyHint(pubKey []byte, xofSuite string) []byte {
	registry := crypto.NewRegistry()
	xof, _ := registry.GetXOF(xofSuite)
	xof.Write([]byte("PQPG-Key-Hint-v1"))
	xof.Write(pubKey)
	return xof.Derive(nil, 32)
}
