// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package sodium is a pure-Go (no cgo) reimplementation of Ruby's rbnacl gem,
// the libsodium/NaCl binding.
//
// The rbnacl gem is a thin C extension over libsodium. This package mirrors its
// public surface — RbNaCl::SecretBox, RbNaCl::Box, RbNaCl::SigningKey /
// VerifyKey, RbNaCl::Hash, RbNaCl::Auth, RbNaCl::PasswordHash, RbNaCl::PWHash,
// RbNaCl::GroupElement, RbNaCl::AEAD and RbNaCl::Random — on top of the pure-Go
// crypto in golang.org/x/crypto (nacl/secretbox, nacl/box, nacl/sign, ed25519,
// curve25519, blake2b, argon2, scrypt, chacha20poly1305) and the standard
// library (crypto/sha256, crypto/sha512, crypto/hmac). No cgo, no libsodium, no
// C. The byte outputs are identical to libsodium's, so ciphertexts, signatures
// and digests produced here are accepted by libsodium/rbnacl and vice versa.
//
// The Go names deliberately track the Ruby ones: a Ruby RbNaCl::SecretBox.new
// maps to sodium.NewSecretBox, #encrypt / #decrypt map to Encrypt / Decrypt,
// the key/nonce byte-length constants (SecretBoxKeyBytes = 32,
// SecretBoxNonceBytes = 24, ...) match libsodium's crypto_secretbox_*BYTES, and
// the error hierarchy (CryptoError, LengthError, BadAuthenticatorError, ...)
// mirrors RbNaCl's exception tree so callers port over one-to-one.
//
// Every wrong-length key, nonce or tag raises a *LengthError; every failed
// authentication (a tampered ciphertext, a bad signature) raises a
// *BadAuthenticatorError wrapped in CryptoError, exactly where libsodium
// returns -1.
package sodium
