// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import (
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Byte-length constants for the password-hashing primitives, matching
// libsodium.
const (
	// PWHashSaltBytes is libsodium's Argon2 salt length (crypto_pwhash_SALTBYTES,
	// 16).
	PWHashSaltBytes = 16
	// ScryptSaltBytes is libsodium's scrypt salt length
	// (crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 32).
	ScryptSaltBytes = 32
)

// Argon2i derives a key from password and salt with the Argon2i function,
// mirroring RbNaCl::PasswordHash.argon2. time is the number of passes
// (opslimit), memoryKiB is the memory cost in kibibytes (libsodium's memlimit
// divided by 1024), threads the degree of parallelism and digestSize the output
// length. The bytes equal libsodium's crypto_pwhash Argon2i (version 0x13).
func Argon2i(password, salt []byte, time, memoryKiB uint32, threads uint8, digestSize uint32) []byte {
	return argon2.Key(password, salt, time, memoryKiB, threads, digestSize)
}

// Argon2id derives a key with the Argon2id function, mirroring
// RbNaCl::PasswordHash.argon2id. The parameters are as for Argon2i; the bytes
// equal libsodium's crypto_pwhash Argon2id (version 0x13).
func Argon2id(password, salt []byte, time, memoryKiB uint32, threads uint8, digestSize uint32) []byte {
	return argon2.IDKey(password, salt, time, memoryKiB, threads, digestSize)
}

// Scrypt derives a key with scrypt, mirroring RbNaCl::PasswordHash.scrypt. n is
// the CPU/memory cost (a power of two), r the block size, p the parallelism and
// digestSize the output length. It returns an error only when the parameters
// are invalid (n not a power of two > 1, or r*p >= 2^30), matching scrypt's
// domain. The bytes equal libsodium's crypto_pwhash_scryptsalsa208sha256.
func Scrypt(password, salt []byte, n, r, p, digestSize int) ([]byte, error) {
	out, err := scrypt.Key(password, salt, n, r, p, digestSize)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scrypt parameters: %v", ErrCrypto, err)
	}
	return out, nil
}
