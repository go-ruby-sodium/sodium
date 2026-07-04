// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Byte-length constants for the hash functions, matching libsodium.
const (
	// SHA256Bytes is the SHA-256 digest length (32).
	SHA256Bytes = 32
	// SHA512Bytes is the SHA-512 digest length (64).
	SHA512Bytes = 64
	// Blake2bBytes is the default BLAKE2b digest length
	// (crypto_generichash_BYTES, 32).
	Blake2bBytes = 32
	// Blake2bBytesMin is the smallest BLAKE2b digest length (1).
	Blake2bBytesMin = 1
	// Blake2bBytesMax is the largest BLAKE2b digest length (64).
	Blake2bBytesMax = 64
	// Blake2bKeyBytesMax is the largest BLAKE2b key length (64).
	Blake2bKeyBytesMax = 64
	// Blake2bSaltBytes is the BLAKE2b salt length when supplied (16).
	Blake2bSaltBytes = 16
	// Blake2bPersonalBytes is the BLAKE2b personalization length when supplied
	// (16).
	Blake2bPersonalBytes = 16
)

// SHA256 returns the SHA-256 digest of message, mirroring RbNaCl::Hash.sha256.
func SHA256(message []byte) []byte {
	sum := sha256.Sum256(message)
	return sum[:]
}

// SHA512 returns the SHA-512 digest of message, mirroring RbNaCl::Hash.sha512.
func SHA512(message []byte) []byte {
	sum := sha512.Sum512(message)
	return sum[:]
}

// Blake2bOptions carries the keyword arguments RbNaCl::Hash.blake2b accepts:
// digest_size:, key:, salt: and personal:. The zero value asks for the default
// 32-byte unkeyed digest.
type Blake2bOptions struct {
	// DigestSize is the output length in bytes (1..64). Zero means the default
	// 32 (crypto_generichash_BYTES).
	DigestSize int
	// Key is an optional up-to-64-byte key turning BLAKE2b into a keyed MAC.
	Key []byte
	// Salt is an optional 16-byte salt (crypto_generichash_blake2b_salt).
	Salt []byte
	// Personal is an optional 16-byte personalization string.
	Personal []byte
}

// errBlake2bParams is returned when salt or personalization is requested. The
// pure-Go backend (golang.org/x/crypto/blake2b) implements the keyed, sized
// generichash but not the salt/personalized parameter-block variant; rather
// than silently ignore the value, blake2b refuses it.
var errBlake2bParams = fmt.Errorf("%w: blake2b salt/personal not supported by the pure-Go backend", ErrCrypto)

// Blake2b returns the BLAKE2b digest of message under opts, mirroring
// RbNaCl::Hash.blake2b. An out-of-range digest size or over-long key yields a
// *LengthError; a non-empty salt or personalization yields errBlake2bParams
// (see errBlake2bParams). With the default options it equals
// libsodium's crypto_generichash.
func Blake2b(message []byte, opts Blake2bOptions) ([]byte, error) {
	size := opts.DigestSize
	if size == 0 {
		size = Blake2bBytes
	}
	if size < Blake2bBytesMin || size > Blake2bBytesMax {
		return nil, &LengthError{What: "digest size", Got: size, Want: Blake2bBytes}
	}
	if len(opts.Key) > Blake2bKeyBytesMax {
		return nil, &LengthError{What: "key", Got: len(opts.Key), Want: Blake2bKeyBytesMax}
	}
	if len(opts.Salt) != 0 || len(opts.Personal) != 0 {
		return nil, errBlake2bParams
	}
	// size and key length are validated above, so blake2b.New cannot fail here.
	h, _ := blake2b.New(size, opts.Key)
	h.Write(message)
	return h.Sum(nil), nil
}
