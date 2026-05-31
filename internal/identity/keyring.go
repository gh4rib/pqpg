package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gh4rib/pqpg-cloudflare-circl/internal/crypto"
)

// Profile represents the public-facing identity and routing preferences of a user.
type Profile struct {
	Name      string `json:"name"`
	KEMSuite  string `json:"kem_suite"`
	DSASuite  string `json:"dsa_suite"`
	AEADSuite string `json:"aead_suite"`
	XOFSuite  string `json:"xof_suite"`
	DSAPubKey []byte `json:"dsa_pub_key"`
	KEMPubKey []byte `json:"kem_pub_key"`
}

// Keyring holds the highly sensitive private key material in memory.
type Keyring struct {
	Profile    Profile
	DSAPrivKey []byte
	KEMPrivKey []byte
}

// GenerateIdentity creates a new post-quantum identity and saves it to disk.
func GenerateIdentity(name, kemName, dsaName, aeadName, xofName, outDir string) error {
	registry := crypto.NewRegistry()
	if !registry.ValidateSuite(kemName, dsaName, aeadName, xofName) {
		return fmt.Errorf("invalid or incompatible cryptographic suite parameters")
	}

	kem, _ := registry.GetKEM(kemName)
	dsa, _ := registry.GetDSA(dsaName)

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
		KEMSuite:  kemName,
		DSASuite:  dsaName,
		AEADSuite: aeadName,
		XOFSuite:  xofName,
		DSAPubKey: dsaPub,
		KEMPubKey: kemPub,
	}

	return saveToDisk(outDir, name, profile, kemPriv, dsaPriv)
}

func saveToDisk(dir, name string, prof Profile, kemPriv, dsaPriv []byte) error {
	privDir := filepath.Join(dir, fmt.Sprintf("keys_%s", name), "private")
	pubDir := filepath.Join(dir, fmt.Sprintf("keys_%s", name), "public")

	if err := os.MkdirAll(privDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(pubDir, 0755); err != nil {
		return err
	}

	profBytes, _ := json.MarshalIndent(prof, "", "  ")
	_ = os.WriteFile(filepath.Join(pubDir, "profile.json"), profBytes, 0644)
	_ = os.WriteFile(filepath.Join(privDir, "profile.json"), profBytes, 0600)

	_ = os.WriteFile(filepath.Join(privDir, "kem.priv"), kemPriv, 0600)
	_ = os.WriteFile(filepath.Join(privDir, "dsa.priv"), dsaPriv, 0600)

	return nil
}

// LoadKeyring reads the private identity from disk.
func LoadKeyring(privDir string) (*Keyring, error) {
	profBytes, err := os.ReadFile(filepath.Join(privDir, "profile.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read profile: %w", err)
	}
	var prof Profile
	if err := json.Unmarshal(profBytes, &prof); err != nil {
		return nil, err
	}

	kemPriv, err := os.ReadFile(filepath.Join(privDir, "kem.priv"))
	if err != nil {
		return nil, err
	}
	dsaPriv, err := os.ReadFile(filepath.Join(privDir, "dsa.priv"))
	if err != nil {
		return nil, err
	}

	return &Keyring{
		Profile:    prof,
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