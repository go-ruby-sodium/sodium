// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import (
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Byte-length constants for public-key authenticated encryption, matching
// libsodium's crypto_box_*BYTES.
const (
	// PublicKeyBytes is the Curve25519 public-key length (32).
	PublicKeyBytes = 32
	// PrivateKeyBytes is the Curve25519 secret-key length (32).
	PrivateKeyBytes = 32
	// BoxNonceBytes is the nonce length (24).
	BoxNonceBytes = 24
	// BoxMACBytes is the Poly1305 tag length (16).
	BoxMACBytes = 16
	// BeforeNMBytes is the precomputed shared-key length (32).
	BeforeNMBytes = 32
)

// PrivateKey is a Curve25519 secret key (RbNaCl::PrivateKey). Its matching
// PublicKey is derived by scalar multiplication of the Curve25519 base point.
type PrivateKey struct {
	key [PrivateKeyBytes]byte
}

// PublicKey is a Curve25519 public key (RbNaCl::PublicKey).
type PublicKey struct {
	key [PublicKeyBytes]byte
}

// NewPrivateKey wraps a 32-byte secret key, mirroring RbNaCl::PrivateKey.new.
// Any other length yields a *LengthError.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if err := checkLen("private key", len(key), PrivateKeyBytes); err != nil {
		return nil, err
	}
	pk := &PrivateKey{}
	copy(pk.key[:], key)
	return pk, nil
}

// GeneratePrivateKey draws a fresh secret key from the system CSPRNG, mirroring
// RbNaCl::PrivateKey.generate.
func GeneratePrivateKey() *PrivateKey {
	pk := &PrivateKey{}
	copy(pk.key[:], RandomBytes(PrivateKeyBytes))
	return pk
}

// Bytes returns a copy of the raw secret key (RbNaCl::PrivateKey#to_bytes).
func (pk *PrivateKey) Bytes() []byte {
	b := make([]byte, PrivateKeyBytes)
	copy(b, pk.key[:])
	return b
}

// PublicKey derives the matching public key (RbNaCl::PrivateKey#public_key).
func (pk *PrivateKey) PublicKey() *PublicKey {
	pub := &PublicKey{}
	// X25519 of the secret scalar with the base point is the public key; the
	// error path is unreachable for a full-length scalar.
	out, _ := curve25519.X25519(pk.key[:], curve25519.Basepoint)
	copy(pub.key[:], out)
	return pub
}

// NewPublicKey wraps a 32-byte public key, mirroring RbNaCl::PublicKey.new. Any
// other length yields a *LengthError.
func NewPublicKey(key []byte) (*PublicKey, error) {
	if err := checkLen("public key", len(key), PublicKeyBytes); err != nil {
		return nil, err
	}
	pub := &PublicKey{}
	copy(pub.key[:], key)
	return pub, nil
}

// Bytes returns a copy of the raw public key (RbNaCl::PublicKey#to_bytes).
func (pub *PublicKey) Bytes() []byte {
	b := make([]byte, PublicKeyBytes)
	copy(b, pub.key[:])
	return b
}

// Box is Curve25519-XSalsa20-Poly1305 public-key authenticated encryption
// (RbNaCl::Box). It binds the recipient's public key to the sender's private
// key; the shared secret is computed once and cached, matching libsodium's
// crypto_box_beforenm.
type Box struct {
	shared [BeforeNMBytes]byte
}

// NewBox constructs a Box between their public key and my private key, mirroring
// RbNaCl::Box.new(their_public_key, my_private_key).
func NewBox(their *PublicKey, mine *PrivateKey) *Box {
	b := &Box{}
	box.Precompute(&b.shared, &their.key, &mine.key)
	return b
}

// Encrypt seals message under nonce for the recipient and returns the combined
// ciphertext (16-byte tag followed by the encrypted bytes), mirroring
// RbNaCl::Box#encrypt. A wrong-length nonce yields a *LengthError.
func (b *Box) Encrypt(nonce, message []byte) ([]byte, error) {
	if err := checkLen("nonce", len(nonce), BoxNonceBytes); err != nil {
		return nil, err
	}
	var n [BoxNonceBytes]byte
	copy(n[:], nonce)
	return box.SealAfterPrecomputation(nil, message, &n, &b.shared), nil
}

// Decrypt opens a combined ciphertext produced by Encrypt, mirroring
// RbNaCl::Box#decrypt. A wrong-length nonce yields a *LengthError; a forged or
// corrupt ciphertext yields a *BadAuthenticatorError.
func (b *Box) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if err := checkLen("nonce", len(nonce), BoxNonceBytes); err != nil {
		return nil, err
	}
	var n [BoxNonceBytes]byte
	copy(n[:], nonce)
	out, ok := box.OpenAfterPrecomputation(nil, ciphertext, &n, &b.shared)
	if !ok {
		return nil, &BadAuthenticatorError{Op: "box open"}
	}
	return out, nil
}

// SharedKey returns a copy of the precomputed 32-byte shared secret
// (RbNaCl::Box's crypto_box_beforenm output).
func (b *Box) SharedKey() []byte {
	s := make([]byte, BeforeNMBytes)
	copy(s, b.shared[:])
	return s
}
