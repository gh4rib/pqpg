package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/sha3"
)

type RatchetState struct {
	ContactID             string            `json:"contact_id"`
	RootKey               []byte            `json:"root_key"`
	SendChainKey          []byte            `json:"send_chain_key"`
	ReceiveChainKey       []byte            `json:"receive_chain_key"`
	SendCount             uint32            `json:"send_count"`
	ReceiveCount          uint32            `json:"receive_count"`
	PreviousSendCount     uint32            `json:"prev_send_count"`
	MyEphemeralPriv       []byte            `json:"my_ephemeral_priv"`
	MyEphemeralPub        []byte            `json:"my_ephemeral_pub"`
	PreviousEphemeralPriv []byte            `json:"prev_ephemeral_priv"`
	PreviousEphemeralPub  []byte            `json:"prev_ephemeral_pub"`
	TheirEphemeralPub     []byte            `json:"their_ephemeral_pub"`
	NeedsRootSpin         bool              `json:"needs_root_spin"`
	LastSentEncap         []byte            `json:"last_sent_encap"`
	SkippedKeys           map[string][]byte `json:"skipped_keys"`
	SessionXOFSuite       string            `json:"session_xof_suite"`
}

type SessionStore struct {
	db        *bbolt.DB
	masterKey []byte
}

var (
	ErrSessionNotFound = errors.New("no active cryptographic session with this contact")
	BucketSessions     = []byte("DoubleRatchetSessions")
	BucketReplayCache  = []byte("AntiReplayCache")
	BucketAddressBook  = []byte("AddressBook") // <-- NEW: Post-Quantum Contacts
)

func OpenSessionStore(privateFolderPath string, localMasterKey []byte) (*SessionStore, error) {
	dbPath := filepath.Join(privateFolderPath, "sessions.db")

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open session database: %w", err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(BucketSessions); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(BucketReplayCache); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(BucketAddressBook); err != nil {
			return err
		} // <-- ADDED
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database buckets: %w", err)
	}

	return &SessionStore{
		db:        db,
		masterKey: localMasterKey,
	}, nil
}

func (s *SessionStore) Close() error {
	return s.db.Close()
}

// blindIndex hashes the plaintext identifiers so the database keys reveal zero metadata.
func (s *SessionStore) blindIndex(identifier []byte) []byte {
	mac := hmac.New(sha3.New256, s.masterKey)
	mac.Write([]byte("PQPG-Blind-Index-v1"))
	mac.Write(identifier)
	return mac.Sum(nil)
}

func (s *SessionStore) SaveState(state *RatchetState) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		return b.Put(s.blindIndex([]byte(state.ContactID)), ciphertext)
	})
}

func (s *SessionStore) LoadState(contactID string) (*RatchetState, error) {
	var ciphertext []byte

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		val := b.Get(s.blindIndex([]byte(contactID)))
		if val == nil {
			return ErrSessionNotFound
		}

		ciphertext = make([]byte, len(val))
		copy(ciphertext, val)
		return nil
	})
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("corrupt session state: invalid ciphertext length")
	}

	nonce, actualCiphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt session state: access denied")
	}

	var state RatchetState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, err
	}

	if state.SkippedKeys == nil {
		state.SkippedKeys = make(map[string][]byte)
	}

	return &state, nil
}

func (s *SessionStore) CheckAndCacheMessage(msgID []byte) error {
	if len(msgID) == 0 {
		return errors.New("envelope is missing an anti-replay token")
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BucketReplayCache)
		blindedMsgID := s.blindIndex(msgID)

		if b.Get(blindedMsgID) != nil {
			return errors.New("CRITICAL REPLAY ATTACK: This exact transaction token has already been decrypted on this machine")
		}
		return b.Put(blindedMsgID, []byte{1})
	})
}

// ---------------------------------------------------------------------
// Feature Additions: Panic Button & Address Book
// ---------------------------------------------------------------------

// ResetSession securely wipes the ratchet state for a SPECIFIC contact.
// This forces a brand new cryptographic bootstrap on the next communication.
func (s *SessionStore) ResetSession(contactID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BucketSessions)
		return b.Delete(s.blindIndex([]byte(contactID)))
	})
}

// ImportContact AES-GCM encrypts a public profile and stores it in the Address Book bucket.
func (s *SessionStore) ImportContact(prof *Profile) error {
	plaintext, err := json.Marshal(prof)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BucketAddressBook)
		// We use the blinded fingerprint as the database key
		return b.Put(s.blindIndex([]byte(prof.Fingerprint)), ciphertext)
	})
}

// ListContacts decrypts all profiles currently saved in the Address Book.
func (s *SessionStore) ListContacts() ([]Profile, error) {
	var contacts []Profile

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BucketAddressBook)
		c := b.Cursor()

		block, err := aes.NewCipher(s.masterKey)
		if err != nil {
			return err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}

		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(v) < gcm.NonceSize() {
				continue
			}
			nonce, actualCiphertext := v[:gcm.NonceSize()], v[gcm.NonceSize():]
			plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
			if err != nil {
				continue
			} // Skip corrupt entries silently

			var prof Profile
			if err := json.Unmarshal(plaintext, &prof); err == nil {
				contacts = append(contacts, prof)
			}
		}
		return nil
	})
	return contacts, err
}
