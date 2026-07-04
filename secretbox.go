// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import "golang.org/x/crypto/nacl/secretbox"

// Byte-length constants for the secret-key box, matching libsodium's
// crypto_secretbox_*BYTES and RbNaCl::SecretBox::{KEYBYTES,NONCEBYTES,MACBYTES}.
const (
	// SecretBoxKeyBytes is the shared-secret key length (32).
	SecretBoxKeyBytes = 32
	// SecretBoxNonceBytes is the nonce length (24).
	SecretBoxNonceBytes = 24
	// SecretBoxMACBytes is the Poly1305 authentication tag length (16).
	SecretBoxMACBytes = 16
)

// SecretBox is symmetric authenticated encryption with the XSalsa20 stream
// cipher and a Poly1305 MAC (RbNaCl::SecretBox). A single 32-byte key both
// encrypts and authenticates; a fresh 24-byte nonce is required for every
// message.
type SecretBox struct {
	key [SecretBoxKeyBytes]byte
}

// NewSecretBox constructs a SecretBox from a 32-byte key, mirroring
// RbNaCl::SecretBox.new(key). A key of any other length yields a *LengthError.
func NewSecretBox(key []byte) (*SecretBox, error) {
	if err := checkLen("key", len(key), SecretBoxKeyBytes); err != nil {
		return nil, err
	}
	sb := &SecretBox{}
	copy(sb.key[:], key)
	return sb, nil
}

// Encrypt seals message under nonce and returns the combined ciphertext (the
// 16-byte Poly1305 tag followed by the encrypted bytes), mirroring
// RbNaCl::SecretBox#encrypt. A nonce of the wrong length yields a *LengthError.
func (sb *SecretBox) Encrypt(nonce, message []byte) ([]byte, error) {
	if err := checkLen("nonce", len(nonce), SecretBoxNonceBytes); err != nil {
		return nil, err
	}
	var n [SecretBoxNonceBytes]byte
	copy(n[:], nonce)
	return secretbox.Seal(nil, message, &n, &sb.key), nil
}

// Decrypt opens a combined ciphertext produced by Encrypt and returns the
// plaintext, mirroring RbNaCl::SecretBox#decrypt. A wrong-length nonce yields a
// *LengthError; a ciphertext that is too short or fails its Poly1305 check
// yields a *BadAuthenticatorError.
func (sb *SecretBox) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if err := checkLen("nonce", len(nonce), SecretBoxNonceBytes); err != nil {
		return nil, err
	}
	var n [SecretBoxNonceBytes]byte
	copy(n[:], nonce)
	out, ok := secretbox.Open(nil, ciphertext, &n, &sb.key)
	if !ok {
		return nil, &BadAuthenticatorError{Op: "secretbox open"}
	}
	return out, nil
}
