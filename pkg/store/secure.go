package store

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

const (
	secureEnvelopeVersion byte = 1
	secureSentinelNS           = "meta"
	secureSentinelKey          = "__secure_store_check__"
	secureSentinelValue        = "sprout-secure-store-v1"
)

type SecureStore struct {
	base Store
	aead cipher.AEAD
}

func LoadOrCreateSalt(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) < 16 {
			return nil, fmt.Errorf("sal inválida en %s", path)
		}
		return data, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("no se ha podido generar la sal: %w", err)
	}
	if err := os.WriteFile(path, salt, 0600); err != nil {
		return nil, fmt.Errorf("no se ha podido guardar la sal: %w", err)
	}
	return salt, nil
}

func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

func NewSecureStore(base Store, key []byte) (*SecureStore, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("no se ha podido crear el cifrador: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("no se ha podido crear GCM: %w", err)
	}
	return &SecureStore{base: base, aead: aead}, nil
}

func (s *SecureStore) VerifyOrInit() error {
	value, err := s.Get(secureSentinelNS, []byte(secureSentinelKey))
	if err == nil {
		if subtle.ConstantTimeCompare(value, []byte(secureSentinelValue)) != 1 {
			return ErrInvalidMasterKey
		}
		return nil
	}
	if err != nil && !errors.Is(err, ErrNamespaceNotFound) && !errors.Is(err, ErrKeyNotFound) {
		return err
	}
	return s.Put(secureSentinelNS, []byte(secureSentinelKey), []byte(secureSentinelValue))
}

func (s *SecureStore) Put(namespace string, key, value []byte) error {
	compressed, err := compress(value)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("no se ha podido generar el nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nil, nonce, compressed, nil)

	var payload bytes.Buffer
	payload.WriteByte(secureEnvelopeVersion)
	if err := binary.Write(&payload, binary.BigEndian, uint16(len(nonce))); err != nil {
		return fmt.Errorf("no se ha podido serializar el nonce: %w", err)
	}
	payload.Write(nonce)
	payload.Write(ciphertext)
	return s.base.Put(namespace, key, payload.Bytes())
}

func (s *SecureStore) Get(namespace string, key []byte) ([]byte, error) {
	raw, err := s.base.Get(namespace, key)
	if err != nil {
		return nil, err
	}
	if len(raw) < 3 || raw[0] != secureEnvelopeVersion {
		return nil, ErrInvalidMasterKey
	}
	nonceSize := int(binary.BigEndian.Uint16(raw[1:3]))
	if len(raw) < 3+nonceSize {
		return nil, ErrInvalidMasterKey
	}
	nonce := raw[3 : 3+nonceSize]
	ciphertext := raw[3+nonceSize:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidMasterKey
	}
	return decompress(plaintext)
}

func (s *SecureStore) Delete(namespace string, key []byte) error {
	return s.base.Delete(namespace, key)
}

func (s *SecureStore) ListKeys(namespace string) ([][]byte, error) {
	return s.base.ListKeys(namespace)
}

func (s *SecureStore) KeysByPrefix(namespace string, prefix []byte) ([][]byte, error) {
	return s.base.KeysByPrefix(namespace, prefix)
}

func (s *SecureStore) Close() error {
	return s.base.Close()
}

func (s *SecureStore) Dump() error {
	keys, err := s.base.ListKeys(secureSentinelNS)
	if err != nil && !errors.Is(err, ErrNamespaceNotFound) {
		return err
	}
	_ = keys
	return s.base.Dump()
}

func compress(value []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(value); err != nil {
		return nil, fmt.Errorf("no se ha podido comprimir: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("no se ha podido cerrar gzip: %w", err)
	}
	return buf.Bytes(), nil
}

func decompress(value []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(value))
	if err != nil {
		return nil, fmt.Errorf("no se ha podido abrir gzip: %w", err)
	}
	defer zr.Close()
	plain, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("no se ha podido descomprimir: %w", err)
	}
	return plain, nil
}
