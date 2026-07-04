// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import "crypto/rand"

// randRead is the source of randomness. It is a package variable so tests can
// substitute a deterministic or failing reader; in production it is
// crypto/rand.Read, the same CSPRNG libsodium's randombytes draws from.
var randRead = rand.Read

// RandomBytes returns n cryptographically secure random bytes, mirroring
// RbNaCl::Random.random_bytes(n). It panics only if the system CSPRNG fails,
// matching RbNaCl, which raises rather than returning a short read.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		panic("sodium: RandomBytes: " + err.Error())
	}
	return b
}
