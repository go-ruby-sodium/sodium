// Copyright (c) the go-ruby-sodium/sodium authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sodium

import "golang.org/x/crypto/curve25519"

// Byte-length constants for Curve25519 scalar multiplication, matching
// libsodium's crypto_scalarmult_*BYTES.
const (
	// GroupElementBytes is the length of a Curve25519 group element / point
	// (32).
	GroupElementBytes = 32
	// ScalarBytes is the length of a Curve25519 scalar (32).
	ScalarBytes = 32
)

// GroupElement is a point on Curve25519 (RbNaCl::GroupElement). Multiplying it
// by a scalar is the X25519 Diffie-Hellman operation.
type GroupElement struct {
	point [GroupElementBytes]byte
}

// NewGroupElement wraps a 32-byte point, mirroring RbNaCl::GroupElement.new.
// Any other length yields a *LengthError.
func NewGroupElement(point []byte) (*GroupElement, error) {
	if err := checkLen("group element", len(point), GroupElementBytes); err != nil {
		return nil, err
	}
	ge := &GroupElement{}
	copy(ge.point[:], point)
	return ge, nil
}

// Bytes returns a copy of the raw point (RbNaCl::GroupElement#to_bytes).
func (ge *GroupElement) Bytes() []byte {
	b := make([]byte, GroupElementBytes)
	copy(b, ge.point[:])
	return b
}

// Mult multiplies the point by scalar and returns the resulting group element,
// mirroring RbNaCl::GroupElement#mult. A wrong-length scalar yields a
// *LengthError; a result of all zeroes (a small-order input point) yields a
// *BadAuthenticatorError, exactly where libsodium's crypto_scalarmult returns
// -1.
func (ge *GroupElement) Mult(scalar []byte) (*GroupElement, error) {
	if err := checkLen("scalar", len(scalar), ScalarBytes); err != nil {
		return nil, err
	}
	out, err := curve25519.X25519(scalar, ge.point[:])
	if err != nil {
		return nil, &BadAuthenticatorError{Op: "scalarmult"}
	}
	res := &GroupElement{}
	copy(res.point[:], out)
	return res, nil
}

// ScalarMultBase multiplies the Curve25519 base point by scalar, mirroring
// RbNaCl::GroupElement.base.mult(scalar) — the public-key derivation
// crypto_scalarmult_base. A wrong-length scalar yields a *LengthError.
func ScalarMultBase(scalar []byte) ([]byte, error) {
	if err := checkLen("scalar", len(scalar), ScalarBytes); err != nil {
		return nil, err
	}
	// The base point is not small-order, so X25519 never returns the all-zero
	// error here.
	out, _ := curve25519.X25519(scalar, curve25519.Basepoint)
	return out, nil
}
