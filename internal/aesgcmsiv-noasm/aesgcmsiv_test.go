package aesgcmsiv

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 8452 Appendix C.2 Test Vectors for AEAD_AES_256_GCM_SIV
var aes256TestVectors = []struct {
	name       string
	key        string
	nonce      string
	aad        string
	plaintext  string
	ciphertext string
}{
	{
		name:       "Empty plaintext and AAD",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "",
		ciphertext: "07f5f4169bbf55a8400cd47ea6fd400f",
	},
	{
		name:       "8-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "0100000000000000",
		ciphertext: "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
	},
	{
		name:       "12-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "010000000000000000000000",
		ciphertext: "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
	},
	{
		name:       "16-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "01000000000000000000000000000000",
		ciphertext: "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
	},
	{
		name:       "32-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "0100000000000000000000000000000002000000000000000000000000000000",
		ciphertext: "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d",
	},
	{
		name:       "1-byte AAD, 8-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "01",
		plaintext:  "0200000000000000",
		ciphertext: "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
	},
	{
		name:       "1-byte AAD, 12-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "01",
		plaintext:  "020000000000000000000000",
		ciphertext: "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
	},
	{
		name:       "1-byte AAD, 16-byte plaintext",
		key:        "0100000000000000000000000000000000000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "01",
		plaintext:  "02000000000000000000000000000000",
		ciphertext: "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
	},
}

// RFC 8452 Appendix C.1 Test Vectors for AEAD_AES_128_GCM_SIV
var aes128TestVectors = []struct {
	name       string
	key        string
	nonce      string
	aad        string
	plaintext  string
	ciphertext string
}{
	{
		name:       "Empty plaintext and AAD",
		key:        "01000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "",
		ciphertext: "dc20e2d83f25705bb49e439eca56de25",
	},
	{
		name:       "8-byte plaintext",
		key:        "01000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "0100000000000000",
		ciphertext: "b5d839330ac7b786578782fff6013b815b287c22493a364c",
	},
	{
		name:       "12-byte plaintext",
		key:        "01000000000000000000000000000000",
		nonce:      "030000000000000000000000",
		aad:        "",
		plaintext:  "010000000000000000000000",
		ciphertext: "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639",
	},
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRFC8452VectorsAES256(t *testing.T) {
	for _, tc := range aes256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustDecodeHex(tc.key)
			nonce := mustDecodeHex(tc.nonce)
			aad := mustDecodeHex(tc.aad)
			plaintext := mustDecodeHex(tc.plaintext)
			expectedCiphertext := mustDecodeHex(tc.ciphertext)

			aead, err := New(key)
			if err != nil {
				t.Fatal(err)
			}

			ciphertext := aead.Seal(nil, nonce, plaintext, aad)

			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Errorf("Seal mismatch:\n  got:  %x\n  want: %x", ciphertext, expectedCiphertext)
			}

			decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				t.Errorf("Open failed: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Open result mismatch:\n  got:  %x\n  want: %x", decrypted, plaintext)
			}
		})
	}
}

func TestRFC8452VectorsAES128(t *testing.T) {
	for _, tc := range aes128TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustDecodeHex(tc.key)
			nonce := mustDecodeHex(tc.nonce)
			aad := mustDecodeHex(tc.aad)
			plaintext := mustDecodeHex(tc.plaintext)
			expectedCiphertext := mustDecodeHex(tc.ciphertext)

			aead, err := New(key)
			if err != nil {
				t.Fatal(err)
			}

			ciphertext := aead.Seal(nil, nonce, plaintext, aad)

			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Errorf("Seal mismatch:\n  got:  %x\n  want: %x", ciphertext, expectedCiphertext)
			}

			decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				t.Errorf("Open failed: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Open result mismatch:\n  got:  %x\n  want: %x", decrypted, plaintext)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		keyLen    int
		expectErr bool
	}{
		{16, false},
		{32, false},
		{0, true},
		{15, true},
		{24, true},
		{33, true},
	}

	for _, tc := range tests {
		key := make([]byte, tc.keyLen)
		_, err := New(key)
		if tc.expectErr && err == nil {
			t.Errorf("New(key[%d]) should have returned error", tc.keyLen)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("New(key[%d]) unexpected error: %v", tc.keyLen, err)
		}
	}
}

func TestNonceSize(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := New(key)
	if aead.NonceSize() != NonceSize {
		t.Errorf("NonceSize() = %d, want %d", aead.NonceSize(), NonceSize)
	}
}

func TestOverhead(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := New(key)
	if aead.Overhead() != TagSize {
		t.Errorf("Overhead() = %d, want %d", aead.Overhead(), TagSize)
	}
}

func TestCipherInterface(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := New(key)
	var _ cipher.AEAD = aead
}

func TestSealOpen(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	plaintext := []byte("Hello, AES-GCM-SIV!")
	additionalData := []byte("additional authenticated data")

	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted = %x, want %x", decrypted, plaintext)
	}
}

func TestAuthenticationFailure(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	plaintext := []byte("secret message")
	aad := []byte("header")

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	// Tamper with ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xff

	_, err := aead.Open(nil, nonce, tampered, aad)
	if err != ErrOpen {
		t.Errorf("Open with tampered ciphertext: got %v, want %v", err, ErrOpen)
	}

	// Wrong AAD
	_, err = aead.Open(nil, nonce, ciphertext, []byte("wrong header"))
	if err != ErrOpen {
		t.Errorf("Open with wrong AAD: got %v, want %v", err, ErrOpen)
	}
}

func TestNonceMisuseResistance(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	msg1 := []byte("message one")
	msg2 := []byte("message two")
	msgSame := []byte("message one")

	ct1 := aead.Seal(nil, nonce, msg1, nil)
	ct2 := aead.Seal(nil, nonce, msg2, nil)
	ctSame := aead.Seal(nil, nonce, msgSame, nil)

	// Same message + same nonce = same ciphertext
	if !bytes.Equal(ct1, ctSame) {
		t.Error("same message with same nonce should produce same ciphertext")
	}

	// Different messages produce different ciphertexts
	if bytes.Equal(ct1, ct2) {
		t.Error("different messages should produce different ciphertexts")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	ciphertext := aead.Seal(nil, nonce, nil, nil)
	if len(ciphertext) != TagSize {
		t.Errorf("empty plaintext ciphertext length = %d, want %d", len(ciphertext), TagSize)
	}

	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted) != 0 {
		t.Errorf("decrypted length = %d, want 0", len(decrypted))
	}
}

func BenchmarkSeal1K(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	plaintext := make([]byte, 1024)

	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(nil, nonce, plaintext, nil)
	}
}

func BenchmarkOpen1K(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, _ := New(key)
	nonce := make([]byte, NonceSize)
	plaintext := make([]byte, 1024)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Open(nil, nonce, ciphertext, nil)
	}
}
