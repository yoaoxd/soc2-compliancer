package encrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Crypter encrypts secrets at rest. Credentials are encrypted with a randomly
// generated data encryption key (DEK), and the DEK is itself wrapped ("sealed")
// by a key-encryption key (KEK). The KEK can live in an external KMS (AWS KMS,
// GCP KMS) or locally. This is envelope encryption: losing the KEK makes the
// ciphertext unrecoverable, and rotating the KEK never requires re-encrypting
// stored payloads.
type Crypter interface {
	// Encrypt returns a portable, self-describing envelope: key version +
	// wrapped DEK + nonce + ciphertext, base64-encoded.
	Encrypt(ctx context.Context, plaintext []byte) (string, error)
	// Decrypt reverses Encrypt. It also transparently decrypts payloads written
	// by earlier versions (see decryptLegacy).
	Decrypt(ctx context.Context, encoded string) ([]byte, error)
}

// KEK wraps/unwraps data encryption keys.
type KEK interface {
	Kind() string
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

type envelopeCrypter struct {
	kek KEK
}

// New builds a Crypter. If masterKey is non-empty it uses a local KEK derived
// from it (AES-256-GCM with key encryption key = sha256(masterKey)); ext (e.g.
// an AWS KMS KEK) wins when provided.
func New(masterKey string, ext KEK) (*envelopeCrypter, error) {
	if ext != nil {
		return &envelopeCrypter{kek: ext}, nil
	}
	if masterKey == "" {
		return nil, errors.New("encryption requires an explicit master key or external KEK")
	}
	return &envelopeCrypter{kek: &localKEK{key: hashedKey(masterKey)}}, nil
}

// envelope wire format (base64 of the whole struct):
//
//	[0]    version byte  (1)
//	[1:5)  uint32 BE wrapped-DEK length
//	[5:    wrapped DEK bytes
//	[..    nonce (12 bytes) + AES-GCM ciphertext
const envVersion = 1
const prefixLen = 5

func (e *envelopeCrypter) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", fmt.Errorf("generate dek: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)

	wrapped, err := e.kek.Wrap(ctx, dek)
	if err != nil {
		return "", fmt.Errorf("wrap dek: %w", err)
	}

	out := make([]byte, 0, prefixLen+len(wrapped)+len(ct))
	out = append(out, envVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (e *envelopeCrypter) Decrypt(ctx context.Context, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(raw) >= prefixLen && raw[0] == envVersion {
		return e.decryptEnvelope(ctx, raw)
	}
	// Payload written by the pre-envelope implementation (no version byte).
	return e.decryptLegacy(raw)
}

func (e *envelopeCrypter) decryptEnvelope(ctx context.Context, raw []byte) ([]byte, error) {
	wrappedLen := binary.BigEndian.Uint32(raw[1:prefixLen])
	if int(wrappedLen) > len(raw)-prefixLen {
		return nil, errors.New("wrapped dek length exceeds ciphertext")
	}
	wrapped := raw[prefixLen : prefixLen+int(wrappedLen)]
	body := raw[prefixLen+int(wrappedLen):]

	dek, err := e.kek.Unwrap(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(body) < ns+16 {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := body[:ns], body[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// decryptLegacy handles the old scheme (AES-GCM keyed directly by
// sha256(masterKey), base64(nonce || ciphertext)) so deployed ciphertext keeps
// decrypting after upgrade.
func (e *envelopeCrypter) decryptLegacy(raw []byte) ([]byte, error) {
	lk, ok := e.kek.(*localKEK)
	if !ok {
		return nil, errors.New("ciphertext uses legacy scheme but no local keystore configured")
	}
	block, err := aes.NewCipher(lk.key)
	if err != nil {
		return nil, fmt.Errorf("legacy cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("legacy gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("legacy decrypt: %w", err)
	}
	return plain, nil
}

type localKEK struct {
	key []byte // already sha256-hashed, 32 bytes
}

func (k *localKEK) Kind() string { return "local" }

func (k *localKEK) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, nil), nil
}

func (k *localKEK) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns+16 {
		return nil, errors.New("wrapped dek too short")
	}
	nonce, ct := wrapped[:ns], wrapped[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

func hashedKey(master string) []byte {
	sum := sha256.Sum256([]byte(master))
	return sum[:]
}
