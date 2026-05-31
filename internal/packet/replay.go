package packet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
)

const replayCacheFile = "pqpg_seen_messages.json"

// CheckAndCacheMessage verifies if an Envelope has been processed before.
// The Post-Quantum digital signature acts as a mathematically perfect, unique MessageID.
func CheckAndCacheMessage(env *Envelope) error {
	if len(env.Signature) == 0 {
		return errors.New("envelope is missing a signature")
	}

	// Convert the signature bytes to a simple string for JSON mapping
	msgID := base64.StdEncoding.EncodeToString(env.Signature)

	// Load existing cache
	seenCache := make(map[string]int64)
	cacheData, err := os.ReadFile(replayCacheFile)
	if err == nil {
		_ = json.Unmarshal(cacheData, &seenCache)
	}

	// Check for Replay Attack
	if _, exists := seenCache[msgID]; exists {
		return errors.New("CRITICAL REPLAY ATTACK: This exact message has already been processed and decrypted on this machine")
	}

	// Log the new message with its creation timestamp
	seenCache[msgID] = env.Timestamp

	// Save the cache back to disk safely (permissions restricted to current user)
	outData, _ := json.MarshalIndent(seenCache, "", "  ")
	_ = os.WriteFile(replayCacheFile, outData, 0600)

	return nil
}