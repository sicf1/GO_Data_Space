package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newTestSecureStore(t *testing.T, path string, passphrase string) *SecureStore {
	t.Helper()

	base, err := NewBboltStore(path)
	if err != nil {
		t.Fatalf("no se ha podido crear la store bbolt: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	saltPath := filepath.Join(filepath.Dir(path), "salt.bin")
	salt, err := LoadOrCreateSalt(saltPath)
	if err != nil {
		t.Fatalf("no se ha podido preparar la sal: %v", err)
	}
	key := DeriveKey(passphrase, salt)
	secure, err := NewSecureStore(base, key)
	if err != nil {
		t.Fatalf("no se ha podido crear la store segura: %v", err)
	}
	if err := secure.VerifyOrInit(); err != nil {
		t.Fatalf("VerifyOrInit falló: %v", err)
	}
	return secure
}

func TestSecureStore_RoundTripEncryptsContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure.db")
	s := newTestSecureStore(t, path, "clave-principal")

	plaintext := []byte("dato-muy-sensible")
	if err := s.Put("records", []byte("k1"), plaintext); err != nil {
		t.Fatalf("Put falló: %v", err)
	}
	got, err := s.Get("records", []byte("k1"))
	if err != nil {
		t.Fatalf("Get falló: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("valor inesperado: %q", string(got))
	}

	_ = s.Close()
	rawDB, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no se ha podido leer la DB: %v", err)
	}
	if bytes.Contains(rawDB, plaintext) {
		t.Fatalf("el texto sensible aparece en claro dentro de la DB")
	}
}

func TestSecureStore_WrongKeyFailsVerification(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure.db")
	saltPath := filepath.Join(dir, "salt.bin")

	{
		base, err := NewBboltStore(path)
		if err != nil {
			t.Fatalf("open falló: %v", err)
		}
		salt, err := LoadOrCreateSalt(saltPath)
		if err != nil {
			t.Fatalf("salt falló: %v", err)
		}
		key := DeriveKey("correcta", salt)
		secure, err := NewSecureStore(base, key)
		if err != nil {
			t.Fatalf("NewSecureStore falló: %v", err)
		}
		if err := secure.VerifyOrInit(); err != nil {
			t.Fatalf("VerifyOrInit falló: %v", err)
		}
		_ = secure.Close()
	}

	{
		base, err := NewBboltStore(path)
		if err != nil {
			t.Fatalf("re-open falló: %v", err)
		}
		defer base.Close()

		salt, err := LoadOrCreateSalt(saltPath)
		if err != nil {
			t.Fatalf("salt falló: %v", err)
		}
		key := DeriveKey("incorrecta", salt)
		secure, err := NewSecureStore(base, key)
		if err != nil {
			t.Fatalf("NewSecureStore falló: %v", err)
		}
		err = secure.VerifyOrInit()
		if !errors.Is(err, ErrInvalidMasterKey) {
			t.Fatalf("se esperaba ErrInvalidMasterKey, obtenido: %v", err)
		}
	}
}
