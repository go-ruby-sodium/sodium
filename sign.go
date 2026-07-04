// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import "crypto/ed25519"

// Byte-length constants for Ed25519 signing, matching libsodium's
// crypto_sign_*BYTES.
const (
	// SignSeedBytes is the 32-byte seed a SigningKey wraps
	// (crypto_sign_SEEDBYTES).
	SignSeedBytes = 32
	// VerifyKeyBytes is the 32-byte Ed25519 public key length
	// (crypto_sign_PUBLICKEYBYTES).
	VerifyKeyBytes = 32
	// SignatureBytes is the 64-byte detached signature length
	// (crypto_sign_BYTES).
	SignatureBytes = 64
)

// SigningKey is an Ed25519 secret signing key (RbNaCl::SigningKey). It is
// carried as its 32-byte seed, exactly as rbnacl stores it; the full expanded
// private key is derived on demand.
type SigningKey struct {
	seed [SignSeedBytes]byte
}

// VerifyKey is an Ed25519 public verification key (RbNaCl::VerifyKey).
type VerifyKey struct {
	pub [VerifyKeyBytes]byte
}

// NewSigningKey wraps a 32-byte seed, mirroring RbNaCl::SigningKey.new(seed).
// Any other length yields a *LengthError.
func NewSigningKey(seed []byte) (*SigningKey, error) {
	if err := checkLen("seed", len(seed), SignSeedBytes); err != nil {
		return nil, err
	}
	sk := &SigningKey{}
	copy(sk.seed[:], seed)
	return sk, nil
}

// GenerateSigningKey draws a fresh signing key from the system CSPRNG, mirroring
// RbNaCl::SigningKey.generate.
func GenerateSigningKey() *SigningKey {
	sk := &SigningKey{}
	copy(sk.seed[:], RandomBytes(SignSeedBytes))
	return sk
}

// Seed returns a copy of the 32-byte seed (RbNaCl::SigningKey#to_bytes).
func (sk *SigningKey) Seed() []byte {
	b := make([]byte, SignSeedBytes)
	copy(b, sk.seed[:])
	return b
}

// Sign returns the 64-byte detached Ed25519 signature over message, mirroring
// RbNaCl::SigningKey#sign.
func (sk *SigningKey) Sign(message []byte) []byte {
	priv := ed25519.NewKeyFromSeed(sk.seed[:])
	return ed25519.Sign(priv, message)
}

// VerifyKey derives the matching public key (RbNaCl::SigningKey#verify_key).
func (sk *SigningKey) VerifyKey() *VerifyKey {
	priv := ed25519.NewKeyFromSeed(sk.seed[:])
	vk := &VerifyKey{}
	copy(vk.pub[:], priv.Public().(ed25519.PublicKey))
	return vk
}

// NewVerifyKey wraps a 32-byte public key, mirroring RbNaCl::VerifyKey.new. Any
// other length yields a *LengthError.
func NewVerifyKey(pub []byte) (*VerifyKey, error) {
	if err := checkLen("public key", len(pub), VerifyKeyBytes); err != nil {
		return nil, err
	}
	vk := &VerifyKey{}
	copy(vk.pub[:], pub)
	return vk, nil
}

// Bytes returns a copy of the raw public key (RbNaCl::VerifyKey#to_bytes).
func (vk *VerifyKey) Bytes() []byte {
	b := make([]byte, VerifyKeyBytes)
	copy(b, vk.pub[:])
	return b
}

// Verify checks the 64-byte signature over message, mirroring
// RbNaCl::VerifyKey#verify. It returns nil on success; a wrong-length signature
// yields a *LengthError and a signature that does not verify yields a
// *BadAuthenticatorError (RbNaCl::BadSignatureError).
func (vk *VerifyKey) Verify(signature, message []byte) error {
	if err := checkLen("signature", len(signature), SignatureBytes); err != nil {
		return err
	}
	if !ed25519.Verify(vk.pub[:], message, signature) {
		return &BadAuthenticatorError{Op: "signature verify"}
	}
	return nil
}
