// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// Byte-length constants for the AEAD constructions, matching libsodium's
// crypto_aead_*.
const (
	// AEADKeyBytes is the ChaCha20-Poly1305 key length (32).
	AEADKeyBytes = 32
	// AEADTagBytes is the Poly1305 tag length appended to every ciphertext
	// (16).
	AEADTagBytes = 16
	// ChaCha20Poly1305IETFNonceBytes is the IETF ChaCha20-Poly1305 nonce length
	// (12).
	ChaCha20Poly1305IETFNonceBytes = 12
	// XChaCha20Poly1305IETFNonceBytes is the XChaCha20-Poly1305 nonce length
	// (24).
	XChaCha20Poly1305IETFNonceBytes = 24
)

// AEAD is authenticated encryption with associated data using ChaCha20-Poly1305
// (RbNaCl::AEAD). Construct it with NewChaCha20Poly1305IETF (12-byte nonce) or
// NewXChaCha20Poly1305IETF (24-byte nonce); the associated data is
// authenticated but not encrypted.
type AEAD struct {
	aead      cipher.AEAD
	nonceSize int
}

// NewChaCha20Poly1305IETF builds an IETF ChaCha20-Poly1305 AEAD from a 32-byte
// key (RbNaCl::AEAD::ChaCha20Poly1305IETF.new). Any other key length yields a
// *LengthError.
func NewChaCha20Poly1305IETF(key []byte) (*AEAD, error) {
	if err := checkLen("key", len(key), AEADKeyBytes); err != nil {
		return nil, err
	}
	// key length is validated, so New cannot fail.
	a, _ := chacha20poly1305.New(key)
	return &AEAD{aead: a, nonceSize: ChaCha20Poly1305IETFNonceBytes}, nil
}

// NewXChaCha20Poly1305IETF builds an XChaCha20-Poly1305 AEAD from a 32-byte key
// (RbNaCl::AEAD::XChaCha20Poly1305IETF.new). Any other key length yields a
// *LengthError.
func NewXChaCha20Poly1305IETF(key []byte) (*AEAD, error) {
	if err := checkLen("key", len(key), AEADKeyBytes); err != nil {
		return nil, err
	}
	// key length is validated, so NewX cannot fail.
	a, _ := chacha20poly1305.NewX(key)
	return &AEAD{aead: a, nonceSize: XChaCha20Poly1305IETFNonceBytes}, nil
}

// Encrypt seals message under nonce with the given associated data and returns
// the ciphertext with its 16-byte tag appended, mirroring RbNaCl::AEAD#encrypt.
// A wrong-length nonce yields a *LengthError.
func (a *AEAD) Encrypt(nonce, message, additionalData []byte) ([]byte, error) {
	if err := checkLen("nonce", len(nonce), a.nonceSize); err != nil {
		return nil, err
	}
	return a.aead.Seal(nil, nonce, message, additionalData), nil
}

// Decrypt opens a ciphertext produced by Encrypt with the same nonce and
// associated data, mirroring RbNaCl::AEAD#decrypt. A wrong-length nonce yields a
// *LengthError; a forged or corrupt ciphertext (or mismatched associated data)
// yields a *BadAuthenticatorError.
func (a *AEAD) Decrypt(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if err := checkLen("nonce", len(nonce), a.nonceSize); err != nil {
		return nil, err
	}
	out, err := a.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, &BadAuthenticatorError{Op: "aead open"}
	}
	return out, nil
}

// NonceBytes returns the nonce length this AEAD requires (12 for the IETF
// variant, 24 for XChaCha20).
func (a *AEAD) NonceBytes() int { return a.nonceSize }
