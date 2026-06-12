package pem

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gh4rib/pqpg/internal/hpqc/util"
)

// KeyMaterial
type KeyMaterial interface {
	FromBytes([]byte) error

	Bytes() []byte

	KeyType() string
}

func ToPEMString(key KeyMaterial) string {
	return string(ToPEMBytes(key))
}

func ToPEMBytes(key KeyMaterial) []byte {
	keyType := strings.ToUpper(key.KeyType())
	if util.CtIsZero(key.Bytes()) {
		panic(fmt.Sprintf("ToPEMString/%s: attempted to serialize scrubbed key", keyType))
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: key.Bytes(),
	}
	return pem.EncodeToMemory(blk)
}

func ToFile(f string, key KeyMaterial) error {
	out, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	outBuf := ToPEMBytes(key)
	writeCount, err := out.Write(outBuf)
	if err != nil {
		return err
	}
	if writeCount != len(outBuf) {
		return errors.New("partial write failure")
	}
	err = out.Sync()
	if err != nil {
		return err
	}
	return out.Close()
}

func FromPEMString(s string, key KeyMaterial) error {
	return FromPEMBytes([]byte(s), key)
}

func FromPEMBytes(b []byte, key KeyMaterial) error {
	keyType := strings.ToUpper(key.KeyType())

	blk, _ := pem.Decode(b)
	if blk == nil {
		return fmt.Errorf("failed to decode PEM data from %s PEM", keyType)
	}
	if strings.ToUpper(blk.Type) != keyType {
		return fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return key.FromBytes(blk.Bytes)
}

func FromFile(f string, key KeyMaterial) error {
	buf, err := os.ReadFile(f)
	if err != nil {
		return fmt.Errorf("pem.FromFile error: %s", err)
	}
	err = FromPEMBytes(buf, key)
	if err != nil {
		return fmt.Errorf("pem.FromFile failed to read from file %s, with buf len %d and err %s", f, len(buf), err)
	}
	return nil
}
