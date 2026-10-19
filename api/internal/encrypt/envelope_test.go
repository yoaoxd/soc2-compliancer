package encrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// legacyEncode reproduces the pre-envelope scheme used by the previous AESSuite:
// base64(nonce || ciphertext) with AES-256-GCM keyed by sha256(masterKey).
func legacyEncode(masterKey string, plaintext []byte) (string, error) {
	sum := sha256.Sum256([]byte(masterKey))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func TestEnvelopeRoundTrip(t *testing.T) {
	c, err := New("master-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	payloads := [][]byte{
		[]byte(`{"type":"service_account","client_email":"x@y.iam.gserviceaccount.com"}`),
		[]byte("short"),
		[]byte(strings.Repeat("a", 4096)),
	}
	for _, p := range payloads {
		enc, err := c.Encrypt(ctx, p)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if !strings.HasPrefix(enc, "AQ") { // version byte 1 base64 prefix
			t.Fatalf("unexpected envelope header: %q", enc[:4])
		}
		dec, err := c.Decrypt(ctx, enc)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if string(dec) != string(p) {
			t.Fatalf("round trip mismatch: %q != %q", dec, p)
		}
	}
}

// Two envelopes encrypting the same payload must differ (random DEK).
func TestEnvelopeRandomization(t *testing.T) {
	c, _ := New("master-key", nil)
	a, _ := c.Encrypt(context.Background(), []byte("same payload"))
	b, _ := c.Encrypt(context.Background(), []byte("same payload"))
	if a == b {
		t.Fatal("expected different ciphertexts for the same plaintext")
	}
}

// Legacy ciphertext (direct AES-GCM with sha256(masterKey)) must still decrypt.
func TestLegacyDecrypt(t *testing.T) {
	c, err := New("legacy-master", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Build a legacy-format payload: base64(nonce || AES-GCM ct) keyed directly
	// by sha256(masterKey), with no envelope version byte.
	legacy, err := legacyEncode("legacy-master", []byte("legacy secret"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.Decrypt(ctx, legacy)
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if string(dec) != "legacy secret" {
		t.Fatalf("got %q", dec)
	}
}

// Wrong master key must fail to decrypt.
func TestEnvelopeWrongKey(t *testing.T) {
	c, _ := New("right-key", nil)
	enc, _ := c.Encrypt(context.Background(), []byte("secret"))
	other, _ := New("wrong-key", nil)
	if _, err := other.Decrypt(context.Background(), enc); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}
