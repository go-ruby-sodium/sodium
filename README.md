<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-sodium/brand/main/social/go-ruby-sodium-sodium.png" alt="go-ruby-sodium/sodium" width="720"></p>

# sodium — go-ruby-sodium

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-sodium.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's [`rbnacl`](https://github.com/RubyCrypto/rbnacl)
gem** — the libsodium/NaCl binding. It mirrors RbNaCl's public surface
(`RbNaCl::SecretBox`, `RbNaCl::Box`, `RbNaCl::SigningKey` / `VerifyKey`,
`RbNaCl::Hash`, `RbNaCl::Auth`, `RbNaCl::PasswordHash`, `RbNaCl::GroupElement`,
`RbNaCl::AEAD`, `RbNaCl::Random`) and produces **byte-identical** ciphertexts,
signatures and digests to libsodium — **without any C, cgo or libsodium**.

Where the `rbnacl` gem is a thin C extension over libsodium, this port stands on
the pure-Go crypto in [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto)
and the standard library: it consumes rather than reinvents the primitives.

It is the NaCl/libsodium backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-bcrypt](https://github.com/go-ruby-bcrypt/bcrypt) (the OpenBSD bcrypt
port), [go-ruby-jwt](https://github.com/go-ruby-jwt/jwt) and
[go-ruby-regexp](https://github.com/go-ruby-regexp/regexp).

## What it consumes

Every primitive is delegated to audited pure-Go code — no hand-rolled crypto:

| RbNaCl surface | Primitive | Backend |
| --- | --- | --- |
| `SecretBox` | XSalsa20-Poly1305 | `golang.org/x/crypto/nacl/secretbox` |
| `Box` / `PrivateKey` / `PublicKey` | Curve25519-XSalsa20-Poly1305 | `golang.org/x/crypto/nacl/box` |
| `SigningKey` / `VerifyKey` | Ed25519 | `crypto/ed25519` |
| `Hash.sha256` / `.sha512` | SHA-2 | `crypto/sha256`, `crypto/sha512` |
| `Hash.blake2b` | BLAKE2b (sized + keyed) | `golang.org/x/crypto/blake2b` |
| `Auth::HMAC` | HMAC-SHA-256/512/512256 | `crypto/hmac` |
| `PasswordHash.argon2` / `.argon2id` | Argon2i / Argon2id | `golang.org/x/crypto/argon2` |
| `PasswordHash.scrypt` | scrypt | `golang.org/x/crypto/scrypt` |
| `GroupElement` | Curve25519 scalar mult (X25519) | `golang.org/x/crypto/curve25519` |
| `AEAD` | ChaCha20-Poly1305 IETF / XChaCha20 | `golang.org/x/crypto/chacha20poly1305` |
| `Random` | CSPRNG | `crypto/rand` |

## Features

- **Symmetric auth-enc** — `SecretBox` (XSalsa20-Poly1305): `Encrypt` / `Decrypt`,
  32-byte key, 24-byte nonce, 16-byte Poly1305 tag.
- **Public-key auth-enc** — `Box` (Curve25519-XSalsa20-Poly1305) with
  `PrivateKey` / `PublicKey`, precomputed shared key (`crypto_box_beforenm`).
- **Signatures** — `SigningKey` / `VerifyKey` (Ed25519), `Sign` / `Verify`,
  `GenerateSigningKey`.
- **Hashing** — `SHA256`, `SHA512`, `Blake2b` with `DigestSize` and `Key`.
- **MACs** — `NewHMACSHA256` / `SHA512` / `SHA512256` (`Auth` / `Verify`).
- **Password hashing** — `Argon2i`, `Argon2id`, `Scrypt`.
- **Scalar multiplication** — `GroupElement.Mult`, `ScalarMultBase` (X25519).
- **AEAD** — `NewChaCha20Poly1305IETF` (12-byte nonce),
  `NewXChaCha20Poly1305IETF` (24-byte nonce), with associated data.
- **Error tree** — `ErrCrypto` → `ErrLength` (`*LengthError`) and
  `ErrBadAuthenticator` (`*BadAuthenticatorError`), mirroring RbNaCl's
  `CryptoError` / `LengthError` / `BadAuthenticatorError` and matchable with
  `errors.Is` / `errors.As`. Exact libsodium key/nonce/tag byte lengths.

CGO-free, **100% test coverage**, `gofmt` + `go vet` clean, `-race` clean, and
green across the six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le,
**s390x** — big-endian).

> **Note.** `golang.org/x/crypto/blake2b` implements the sized, keyed
> generichash but not the salt/personalization parameter-block variant, so
> `Blake2b` supports `DigestSize` and `Key` and rejects a non-empty `Salt` or
> `Personal` rather than silently ignoring it.

## Install

```sh
go get github.com/go-ruby-sodium/sodium
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/go-ruby-sodium/sodium"
)

func main() {
	// SecretBox: symmetric authenticated encryption.
	key := sodium.RandomBytes(sodium.SecretBoxKeyBytes)
	nonce := sodium.RandomBytes(sodium.SecretBoxNonceBytes)
	sb, _ := sodium.NewSecretBox(key)
	ct, _ := sb.Encrypt(nonce, []byte("attack at dawn"))
	pt, _ := sb.Decrypt(nonce, ct)
	fmt.Printf("%s\n", pt) // attack at dawn

	// Box: public-key authenticated encryption.
	alice := sodium.GeneratePrivateKey()
	bob := sodium.GeneratePrivateKey()
	box := sodium.NewBox(bob.PublicKey(), alice)
	sealed, _ := box.Encrypt(nonce, []byte("hi bob"))
	_ = sealed

	// Ed25519 signatures.
	sk := sodium.GenerateSigningKey()
	sig := sk.Sign([]byte("sign me"))
	fmt.Println(sk.VerifyKey().Verify(sig, []byte("sign me"))) // <nil>
}
```

## Tests & coverage

The suite is deterministic and network-free — it drives every primitive with
**published test vectors**: the NaCl reference ciphertexts (generated by the C
implementation of NaCl) for SecretBox and Box, RFC 8032 for Ed25519, RFC 8439
for ChaCha20-Poly1305, RFC 7748 for X25519, RFC 7693 for BLAKE2b, RFC 4231 for
HMAC, RFC 7914 for scrypt, and Argon2 reference-validated goldens. Encrypt /
decrypt / sign / verify / hash reproduce the exact expected bytes; a tampered
ciphertext or signature raises `*BadAuthenticatorError`; a wrong-length key,
nonce or tag raises `*LengthError`. These alone hold coverage at 100%, so the
qemu cross-arch and Windows lanes pass the gate with no Ruby or libsodium
present.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-sodium/sodium authors.

## WebAssembly

Being pure Go (CGO=0), this library also compiles to **WebAssembly** — both
`GOOS=js GOARCH=wasm` (browser / Node.js) and `GOOS=wasip1 GOARCH=wasm` (WASI).
CI builds both targets on every push, alongside the six 64-bit native/qemu arches.

```sh
GOOS=js     GOARCH=wasm go build ./...   # browser / Node
GOOS=wasip1 GOARCH=wasm go build ./...   # WASI (wasmtime, wasmer, wasmedge, …)
```
