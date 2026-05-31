package packet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	armorHeader = "-----BEGIN PQC MESSAGE-----"
	armorFooter = "-----END PQC MESSAGE-----"
	lineLength  = 64
)

// EncodeArmor converts an Envelope into a printable ASCII string.
func EncodeArmor(env *Envelope) (string, error) {
	rawJSON, err := json.Marshal(env)
	if err != nil {
		return "", err
	}

	b64Str := base64.StdEncoding.EncodeToString(rawJSON)
	var sb strings.Builder
	
	sb.WriteString(armorHeader + "\n")
	
	// Break base64 string into 64-character lines
	for i := 0; i < len(b64Str); i += lineLength {
		end := i + lineLength
		if end > len(b64Str) {
			end = len(b64Str)
		}
		sb.WriteString(b64Str[i:end] + "\n")
	}
	
	sb.WriteString(armorFooter + "\n")
	
	return sb.String(), nil
}

// DecodeArmor extracts and parses an Envelope from an ASCII armored string.
func DecodeArmor(armored string) (*Envelope, error) {
	if !strings.Contains(armored, armorHeader) || !strings.Contains(armored, armorFooter) {
		return nil, errors.New("invalid or missing ASCII armor headers")
	}

	// Extract everything between the header and footer
	start := strings.Index(armored, armorHeader) + len(armorHeader)
	end := strings.Index(armored, armorFooter)
	b64Payload := armored[start:end]

	// Clean up whitespace and newlines
	b64Payload = strings.ReplaceAll(b64Payload, "\n", "")
	b64Payload = strings.ReplaceAll(b64Payload, "\r", "")
	b64Payload = strings.ReplaceAll(b64Payload, " ", "")

	rawJSON, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding failed: %w", err)
	}

	var env Envelope
	if err := json.Unmarshal(rawJSON, &env); err != nil {
		return nil, fmt.Errorf("envelope json unmarshal failed: %w", err)
	}

	return &env, nil
}