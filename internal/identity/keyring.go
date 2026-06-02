package identity

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
)

// Profile represents the public-facing identity and routing preferences of a user.
type Profile struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Comment     string `json:"comment,omitempty"`
	KEMSuite    string `json:"kem_suite"`
	DSASuite    string `json:"dsa_suite"`
	AEADSuite   string `json:"aead_suite"`
	XOFSuite    string `json:"xof_suite"`
	DSAPubKey   []byte `json:"dsa_pub_key"`
	KEMPubKey   []byte `json:"kem_pub_key"`
	Fingerprint string `json:"fingerprint"`
}

// Keyring holds the highly sensitive private key material in memory.
type Keyring struct {
	Profile    Profile
	DSAPrivKey []byte
	KEMPrivKey []byte
}

// UserID returns a standardized identity string matching open-text security conventions.
func (p *Profile) UserID() string {
	if p.Comment != "" {
		return fmt.Sprintf("%s (%s) <%s>", p.Name, p.Comment, p.Email)
	}
	return fmt.Sprintf("%s <%s>", p.Name, p.Email)
}

// CalculateFingerprint deterministically binds identity metadata to public keys.
func (p *Profile) CalculateFingerprint() (string, error) {
	registry := crypto.NewRegistry()
	xof, err := registry.GetXOF(p.XOFSuite)
	if err != nil {
		return "", fmt.Errorf("failed to load XOF for fingerprinting: %w", err)
	}

	// Construct an isolated buffer to enforce strict domain separation
	var buffer []byte
	buffer = append(buffer, []byte("PQPG-v1-PublicKey-Fingerprint-")...)
	buffer = append(buffer, []byte(p.Name+"\x00")...)
	buffer = append(buffer, []byte(p.Email+"\x00")...)
	buffer = append(buffer, []byte(p.Comment+"\x00")...)
	buffer = append(buffer, []byte(p.KEMSuite+"\x00")...)
	buffer = append(buffer, []byte(p.DSASuite+"\x00")...)
	buffer = append(buffer, p.KEMPubKey...)
	buffer = append(buffer, p.DSAPubKey...)

	// Derive a fixed 32-byte unique token
	digest := xof.Derive(buffer, 32)
	hexRaw := strings.ToUpper(hex.EncodeToString(digest))

	// Format into readable groups of 4 characters
	var blocks []string
	for i := 0; i < len(hexRaw); i += 4 {
		blocks = append(blocks, hexRaw[i:i+4])
	}

	return strings.Join(blocks, " "), nil
}

// GenerateIdentity creates a new post-quantum identity, signs the context, and saves it to disk.
func GenerateIdentity(name, email, comment, kemSuite, dsaSuite, aeadSuite, xofSuite, outDir, passphrase string) error {
	registry := crypto.NewRegistry()
	
	// FIXED: Variable names matched to function signature
	if !registry.ValidateSuite(kemSuite, dsaSuite, aeadSuite, xofSuite) {
		return fmt.Errorf("invalid or incompatible cryptographic suite parameters")
	}

	kem, err := registry.GetKEM(kemSuite)
	if err != nil {
		return fmt.Errorf("failed to initialize KEM: %w", err)
	}
	
	dsa, err := registry.GetDSA(dsaSuite)
	if err != nil {
		return fmt.Errorf("failed to initialize DSA: %w", err)
	}

	kemPub, kemPriv, err := kem.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("KEM generation failed: %w", err)
	}

	dsaPub, dsaPriv, err := dsa.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("DSA generation failed: %w", err)
	}

	profile := Profile{
		Name:      name,
		Email:     email,
		Comment:   comment,
		KEMSuite:  kemSuite,
		DSASuite:  dsaSuite,
		AEADSuite: aeadSuite,
		XOFSuite:  xofSuite,
		DSAPubKey: dsaPub,
		KEMPubKey: kemPub,
	}

	// Calculate and bake the fingerprint into the profile before writing to disk
	fp, err := profile.CalculateFingerprint()
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint binding: %w", err)
	}
	profile.Fingerprint = fp

	// FIXED: Passed 'profile' instead of undefined 'prof'
	return saveToDisk(outDir, name, profile, kemPriv, dsaPriv, passphrase)
}

func saveToDisk(dir, name string, prof Profile, kemPriv, dsaPriv []byte, passphrase string) error {
	safeName := strings.ReplaceAll(name, " ", "_")

	privDir := filepath.Join(dir, fmt.Sprintf("keys_%s", safeName), "private")
	pubDir := filepath.Join(dir, fmt.Sprintf("keys_%s", safeName), "public")

	if err := os.MkdirAll(privDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(pubDir, 0755); err != nil {
		return err
	}

	// Save Public Assets standardly
	profBytes, _ := json.MarshalIndent(prof, "", "  ")
	_ = os.WriteFile(filepath.Join(pubDir, "profile.json"), profBytes, 0644)
	_ = os.WriteFile(filepath.Join(privDir, "profile.json"), profBytes, 0600)

	// ENCRYPT PRIVATE KEYS CONSOLIDATED
	armoredPrivateBlock, err := EncryptAndArmorKeys(kemPriv, dsaPriv, passphrase)
	if err != nil {
		return fmt.Errorf("failed protecting subkeys: %v", err)
	}

	// Write single protected key file
	err = os.WriteFile(filepath.Join(privDir, "private_key.asc"), []byte(armoredPrivateBlock), 0600)
	return err
}

// LoadKeyring reads the private identity from disk.
func LoadKeyring(privDir string, passphrase string) (*Keyring, error) {
	prof, err := LoadProfile(privDir)
	if err != nil {
		return nil, err
	}

	// Load armored asset
	armoredBytes, err := os.ReadFile(filepath.Join(privDir, "private_key.asc"))
	if err != nil {
		return nil, fmt.Errorf("missing secure private key bundle file: %v", err)
	}

	// Extract keys securely through memory layer
	kemPriv, dsaPriv, err := DecryptArmoredKeys(string(armoredBytes), passphrase)
	if err != nil {
		return nil, err
	}

	// FIXED: Mapped to correct struct fields KEMPrivKey and DSAPrivKey
	return &Keyring{
		Profile:    *prof,
		KEMPrivKey: kemPriv,
		DSAPrivKey: dsaPriv,
	}, nil
}

// LoadProfile reads a public identity from disk.
func LoadProfile(pubDir string) (*Profile, error) {
	profBytes, err := os.ReadFile(filepath.Join(pubDir, "profile.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read public profile: %w", err)
	}
	var prof Profile
	if err := json.Unmarshal(profBytes, &prof); err != nil {
		return nil, err
	}
	return &prof, nil
}