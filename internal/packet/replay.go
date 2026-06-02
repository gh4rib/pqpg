package packet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
)

const replayCacheFile = "pqpg_seen_messages.json"

// CheckAndCacheMessage verifies if a MessageID has been processed before.
func CheckAndCacheMessage(msgID []byte, timestamp int64) error {
	if len(msgID) == 0 {
		return errors.New("envelope is missing an anti-replay token")
	}

	idStr := base64.StdEncoding.EncodeToString(msgID)

	seenCache := make(map[string]int64)
	cacheData, err := os.ReadFile(replayCacheFile)
	if err == nil {
		_ = json.Unmarshal(cacheData, &seenCache)
	}

	if _, exists := seenCache[idStr]; exists {
		return errors.New("CRITICAL REPLAY ATTACK: This exact transaction token has already been decrypted on this machine")
	}

	seenCache[idStr] = timestamp

	outData, _ := json.MarshalIndent(seenCache, "", "  ")
	_ = os.WriteFile(replayCacheFile, outData, 0600)

	return nil
}