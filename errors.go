// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import (
	"errors"
	"fmt"
)

// The error tree mirrors RbNaCl's exception hierarchy. In Ruby every error is a
// subclass of RbNaCl::CryptoError; the notable leaves are LengthError (a key,
// nonce, tag or message of the wrong size) and BadAuthenticatorError (a
// ciphertext or signature that fails verification). Go callers match them with
// errors.Is / errors.As.
//
// The sentinels below are the roots a caller reaches for with errors.Is; the
// *LengthError and *BadAuthenticatorError concrete types carry the offending
// detail and unwrap to those sentinels.
var (
	// ErrCrypto is the root of the tree (RbNaCl::CryptoError). Every error this
	// package returns satisfies errors.Is(err, ErrCrypto).
	ErrCrypto = errors.New("sodium: crypto error")

	// ErrLength is the RbNaCl::LengthError root: a key, nonce, tag or message
	// did not have the exact byte length libsodium requires.
	ErrLength = fmt.Errorf("%w: incorrect length", ErrCrypto)

	// ErrBadAuthenticator is the RbNaCl::BadAuthenticatorError /
	// RbNaCl::BadSignatureError root: authentication or signature verification
	// failed. It is what libsodium signals by returning -1.
	ErrBadAuthenticator = fmt.Errorf("%w: authentication failed", ErrCrypto)
)

// LengthError is raised when a value handed to the library is not the exact
// size libsodium mandates (RbNaCl::LengthError). It names the value, the length
// it received and the length it wanted.
type LengthError struct {
	// What names the offending value, e.g. "key", "nonce", "public key".
	What string
	// Got is the byte length that was supplied.
	Got int
	// Want is the byte length libsodium requires.
	Want int
}

func (e *LengthError) Error() string {
	return fmt.Sprintf("sodium: %s must be %d bytes, got %d", e.What, e.Want, e.Got)
}

// Unwrap ties every *LengthError to the ErrLength (and thereby ErrCrypto) root
// so errors.Is(err, ErrLength) and errors.Is(err, ErrCrypto) both hold.
func (e *LengthError) Unwrap() error { return ErrLength }

// BadAuthenticatorError is raised when a ciphertext fails its Poly1305 check or
// a signature fails Ed25519 verification (RbNaCl::BadAuthenticatorError /
// RbNaCl::BadSignatureError). libsodium returns -1 in exactly these cases.
type BadAuthenticatorError struct {
	// Op names the operation that failed, e.g. "secretbox open".
	Op string
}

func (e *BadAuthenticatorError) Error() string {
	return fmt.Sprintf("sodium: %s: forged or corrupt ciphertext", e.Op)
}

// Unwrap ties every *BadAuthenticatorError to ErrBadAuthenticator (and thereby
// ErrCrypto).
func (e *BadAuthenticatorError) Unwrap() error { return ErrBadAuthenticator }

// checkLen returns a *LengthError when got != want, and nil otherwise. It is
// the single guard every primitive uses to reject mis-sized keys and nonces,
// matching libsodium's up-front length assertions.
func checkLen(what string, got, want int) error {
	if got != want {
		return &LengthError{What: what, Got: got, Want: want}
	}
	return nil
}
