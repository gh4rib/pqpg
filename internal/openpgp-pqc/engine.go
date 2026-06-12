package openpgp_pqc

import (
	"bytes"
	"errors"
	"io"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// OpenPGPEngine wraps the gopenpgp API, guaranteeing strict adherence
// to the draft-ietf-openpgp-pqc specification.
type OpenPGPEngine struct {
	pgp *crypto.PGPHandle
}

func NewEngine() *OpenPGPEngine {
	// The Proton v3.4.1-proton branch bundles the Post-Quantum draft
	// algorithms (Algorithm IDs 29 and 35) inside their native Proton profile.
	return &OpenPGPEngine{
		pgp: crypto.PGPWithProfile(profile.PQC()),
	}
}

// GenerateKey outputs armored OpenPGP v6 Key blocks.
// highSecurity = true uses Kyber1024+X448 and Dilithium5+Ed448.
func (e *OpenPGPEngine) GenerateKey(name, email, passphrase string, highSecurity bool) (pubArmored, privArmored string, err error) {
	keyGenHandle := e.pgp.KeyGeneration().AddUserId(name, email).New()

	var key *crypto.Key
	if highSecurity {
		key, err = keyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)
	} else {
		key, err = keyGenHandle.GenerateKey()
	}

	if err != nil {
		return "", "", err
	}

	pubKey, err := key.ToPublic()
	if err != nil {
		return "", "", err
	}
	pubArmored, err = pubKey.Armor()
	if err != nil {
		return "", "", err
	}

	if passphrase != "" {
		lockedKey, err := e.pgp.LockKey(key, []byte(passphrase))
		if err != nil {
			return "", "", err
		}
		privArmored, err = lockedKey.Armor()
	} else {
		privArmored, err = key.Armor()
	}

	return pubArmored, privArmored, err
}

// EncryptAndSignStream encrypts a file stream for a recipient, signed by the sender.
func (e *OpenPGPEngine) EncryptAndSignStream(in io.Reader, out io.Writer, recipientPub, senderPriv, senderPass string) error {
	pubKey, err := crypto.NewKeyFromArmored(recipientPub)
	if err != nil {
		return err
	}

	privKey, err := crypto.NewPrivateKeyFromArmored(senderPriv, []byte(senderPass))
	if err != nil {
		return err
	}
	defer privKey.ClearPrivateParams()

	encHandle, err := e.pgp.Encryption().Recipient(pubKey).SigningKey(privKey).New()
	if err != nil {
		return err
	}
	defer encHandle.ClearPrivateParams()

	ptWriter, err := encHandle.EncryptingWriter(out, crypto.Armor)
	if err != nil {
		return err
	}

	_, err = io.Copy(ptWriter, in)
	if err != nil {
		return err
	}

	return ptWriter.Close()
}

// DecryptAndVerifyStream decrypts an incoming PGP stream and verifies the sender's signature.
func (e *OpenPGPEngine) DecryptAndVerifyStream(in io.Reader, out io.Writer, myPriv, myPass, senderPub string) error {
	pubKey, err := crypto.NewKeyFromArmored(senderPub)
	if err != nil {
		return err
	}

	privKey, err := crypto.NewPrivateKeyFromArmored(myPriv, []byte(myPass))
	if err != nil {
		return err
	}
	defer privKey.ClearPrivateParams()

	decHandle, err := e.pgp.Decryption().DecryptionKey(privKey).VerificationKey(pubKey).New()
	if err != nil {
		return err
	}
	defer decHandle.ClearPrivateParams()

	ptReader, err := decHandle.DecryptingReader(in, crypto.Armor)
	if err != nil {
		return err
	}

	decResult, err := ptReader.ReadAllAndVerifySignature()
	if err != nil {
		return err
	}

	if sigErr := decResult.SignatureError(); sigErr != nil {
		return errors.New("CRITICAL: Signature verification failed: " + sigErr.Error())
	}

	_, err = io.Copy(out, bytes.NewReader(decResult.Bytes()))
	return err
}

// SignCleartext creates a PGP signed message where the plaintext remains readable.
func (e *OpenPGPEngine) SignCleartext(message []byte, myPriv, myPass string) (string, error) {
	privKey, err := crypto.NewPrivateKeyFromArmored(myPriv, []byte(myPass))
	if err != nil {
		return "", err
	}
	defer privKey.ClearPrivateParams()

	signer, err := e.pgp.Sign().SigningKey(privKey).New()
	if err != nil {
		return "", err
	}
	defer signer.ClearPrivateParams()

	// FIX: Cast the returned []byte to a string to match the function signature
	armored, err := signer.SignCleartext(message)
	return string(armored), err
}

// VerifyCleartext checks a PGP cleartext signed message.
func (e *OpenPGPEngine) VerifyCleartext(armoredPayload, senderPub string) error {
	pubKey, err := crypto.NewKeyFromArmored(senderPub)
	if err != nil {
		return err
	}

	verifier, err := e.pgp.Verify().VerificationKey(pubKey).New()
	if err != nil {
		return err
	}

	verifyResult, err := verifier.VerifyCleartext([]byte(armoredPayload))
	if err != nil {
		return err
	}

	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		return errors.New("signature verification failed: " + sigErr.Error())
	}
	return nil
}

// SignDetached creates a standalone .sig file for a given message.
func (e *OpenPGPEngine) SignDetached(message []byte, myPriv, myPass string) ([]byte, error) {
	privKey, err := crypto.NewPrivateKeyFromArmored(myPriv, []byte(myPass))
	if err != nil {
		return nil, err
	}
	defer privKey.ClearPrivateParams()

	signer, err := e.pgp.Sign().SigningKey(privKey).Detached().New()
	if err != nil {
		return nil, err
	}
	defer signer.ClearPrivateParams()

	return signer.Sign(message, crypto.Armor)
}

// VerifyDetached checks a standalone .sig file against a message.
func (e *OpenPGPEngine) VerifyDetached(message, signature []byte, senderPub string) error {
	pubKey, err := crypto.NewKeyFromArmored(senderPub)
	if err != nil {
		return err
	}

	verifier, err := e.pgp.Verify().VerificationKey(pubKey).New()
	if err != nil {
		return err
	}

	verifyResult, err := verifier.VerifyDetached(message, signature, crypto.Armor)
	if err != nil {
		return err
	}

	if sigErr := verifyResult.SignatureError(); sigErr != nil {
		return errors.New("signature verification failed: " + sigErr.Error())
	}
	return nil
}
