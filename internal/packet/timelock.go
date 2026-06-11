package packet

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gh4rib/pqpg/internal/crypto"
	"github.com/gh4rib/pqpg/internal/vdf"
)

type TimeLockMetadata struct {
	AEADSuite string     `json:"aead_suite"`
	Puzzle    vdf.Puzzle `json:"puzzle"`
	Nonce     []byte     `json:"nonce"`
}

// SealTimeLockStream creates a Dead Man's Switch envelope.
func SealTimeLockStream(in io.Reader, out io.Writer, operations uint64, aeadSuite string) error {
	registry := crypto.NewRegistry()
	aead, err := registry.GetAEAD(aeadSuite)
	if err != nil {
		return err
	}

	engine := vdf.NewRSATimeLock()

	puzzle, err := engine.Generate(operations)
	if err != nil {
		return err
	}

	// --- CRITICAL FIX: PREVENT OUT OF BOUNDS PANIC FOR MASSIVE KEYS ---
	xof, _ := registry.GetXOF("SHAKE256")
	xof.Write([]byte("PQPG-TimeLock-Key-v1"))
	xof.Write(puzzle.TargetH)

	masterKey := xof.Derive(nil, aead.KeySize())
	defer crypto.Wipe(masterKey) // HYGIENE

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	metadata := TimeLockMetadata{
		AEADSuite: aeadSuite,
		Puzzle:    *puzzle,
		Nonce:     nonce,
	}

	metaBytes, _ := json.Marshal(metadata)
	fmt.Fprintf(out, "-----BEGIN PQPG TIMELOCK PUZZLE-----\n%s\n-----BEGIN TIMELOCK PAYLOAD-----\n", base64.StdEncoding.EncodeToString(metaBytes))

	buf := make([]byte, ChunkSize)
	var chunkIndex uint64 = 0

	for {
		n, err := io.ReadFull(in, buf)
		if n > 0 {
			chunkNonce := buildChunkNonce(nonce, chunkIndex)
			ciphertext, errSeal := aead.Seal(masterKey, chunkNonce, buf[:n], nil)
			if errSeal != nil {
				return fmt.Errorf("chunk encryption failed: %w", errSeal)
			}

			fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
			chunkIndex++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "-----END PQPG TIMELOCK PUZZLE-----\n")
	return nil
}

// OpenTimeLockStream verifies the ZKP, solves the puzzle over time, and safely decrypts the stream.
func OpenTimeLockStream(in io.Reader, out io.Writer, metaBase64 string) error {
	metaBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(metaBase64))
	if err != nil {
		return err
	}

	var metadata TimeLockMetadata
	if err := json.Unmarshal(metaBytes, &metadata); err != nil {
		return err
	}

	engine := vdf.NewRSATimeLock()

	if !engine.Verify(&metadata.Puzzle) {
		return vdf.ErrInvalidZKP
	}
	fmt.Println("[+] ZKP Verified. The Time-Lock puzzle is mathematically sound. Beginning sequential operations...")

	solvedState, err := engine.Solve(&metadata.Puzzle)
	if err != nil {
		return err
	}

	fmt.Println("\n[+] Puzzle Solved! Deriving decryption keys...")

	registry := crypto.NewRegistry()
	aead, err := registry.GetAEAD(metadata.AEADSuite)
	if err != nil {
		return err
	}

	// --- CRITICAL FIX: PREVENT OUT OF BOUNDS PANIC FOR MASSIVE KEYS ---
	xof, _ := registry.GetXOF("SHAKE256")
	xof.Write([]byte("PQPG-TimeLock-Key-v1"))
	xof.Write(solvedState)

	masterKey := xof.Derive(nil, aead.KeySize())
	defer crypto.Wipe(masterKey) // HYGIENE

	tempFile, err := os.CreateTemp("", "pqpg-timelock-buffer-*")
	if err != nil {
		return fmt.Errorf("failed to allocate secure buffer: %v", err)
	}
	tempFileName := tempFile.Name()
	defer func() {
		tempFile.Close()
		os.Remove(tempFileName)
	}()

	reader := bufio.NewReader(in)
	var chunkIndex uint64 = 0

	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if line == "-----BEGIN TIMELOCK PAYLOAD-----" || line == "" {
			continue
		}
		if line == "-----END PQPG TIMELOCK PUZZLE-----" {
			break
		}
		if err != nil {
			return errors.New("unexpected EOF or corrupt timelock payload")
		}

		ciphertext, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return err
		}

		chunkNonce := buildChunkNonce(metadata.Nonce, chunkIndex)
		plaintext, err := aead.Open(masterKey, chunkNonce, ciphertext, nil)
		if err != nil {
			return errors.New("CRITICAL: Decryption failed. Puzzle derivation incorrect or payload tampered")
		}

		if _, err := tempFile.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write to secure buffer: %w", err)
		}
		chunkIndex++
	}

	_, err = tempFile.Seek(0, 0)
	if err != nil {
		return err
	}
	_, errOut := io.Copy(out, tempFile)
	return errOut
}
