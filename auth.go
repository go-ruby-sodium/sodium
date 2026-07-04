// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// Byte-length constants for the HMAC authenticators, matching libsodium's
// crypto_auth_hmacsha*_{KEYBYTES,BYTES}.
const (
	// HMACKeyBytes is libsodium's recommended HMAC key length (32). Standard
	// HMAC accepts a key of any length, and so does this package; the constant
	// documents the default rbnacl uses.
	HMACKeyBytes = 32
	// HMACSHA256Bytes is the HMAC-SHA-256 tag length (32).
	HMACSHA256Bytes = 32
	// HMACSHA512Bytes is the HMAC-SHA-512 tag length (64).
	HMACSHA512Bytes = 64
	// HMACSHA512256Bytes is the HMAC-SHA-512-256 tag length (32); it is
	// HMAC-SHA-512 truncated to its leading 32 bytes, i.e. libsodium's
	// crypto_auth (crypto_auth_hmacsha512256).
	HMACSHA512256Bytes = 32
)

// Authenticator is a keyed HMAC message-authentication code
// (RbNaCl::Auth::HMAC). It computes and verifies a fixed-length tag over a
// message with a secret key.
type Authenticator struct {
	newHash  func() hash.Hash
	key      []byte
	tagBytes int
}

// NewHMACSHA256 builds an HMAC-SHA-256 authenticator
// (RbNaCl::Auth::HMAC::SHA256.new(key)).
func NewHMACSHA256(key []byte) *Authenticator {
	return &Authenticator{newHash: sha256.New, key: clone(key), tagBytes: HMACSHA256Bytes}
}

// NewHMACSHA512 builds an HMAC-SHA-512 authenticator
// (RbNaCl::Auth::HMAC::SHA512.new(key)).
func NewHMACSHA512(key []byte) *Authenticator {
	return &Authenticator{newHash: sha512.New, key: clone(key), tagBytes: HMACSHA512Bytes}
}

// NewHMACSHA512256 builds an HMAC-SHA-512-256 authenticator
// (RbNaCl::Auth::HMAC::SHA512256.new(key)), the truncated form libsodium
// exposes as crypto_auth.
func NewHMACSHA512256(key []byte) *Authenticator {
	return &Authenticator{newHash: sha512.New, key: clone(key), tagBytes: HMACSHA512256Bytes}
}

// Auth computes the authentication tag over message, mirroring
// RbNaCl::Auth::HMAC#auth. The tag is truncated to the code's tag length (a
// no-op for SHA-256/512, a 32-byte truncation for SHA-512-256).
func (a *Authenticator) Auth(message []byte) []byte {
	m := hmac.New(a.newHash, a.key)
	m.Write(message)
	return m.Sum(nil)[:a.tagBytes]
}

// Verify checks tag against message in constant time, mirroring
// RbNaCl::Auth::HMAC#verify. It returns nil when the tag matches and a
// *BadAuthenticatorError otherwise.
func (a *Authenticator) Verify(tag, message []byte) error {
	if !hmac.Equal(tag, a.Auth(message)) {
		return &BadAuthenticatorError{Op: "hmac verify"}
	}
	return nil
}

// clone copies a key so the Authenticator does not alias the caller's slice.
func clone(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
