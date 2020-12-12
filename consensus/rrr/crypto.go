package rrr

// The ambition is to have much of rrr implemented in its own package.
// However, some of go-ethereums crypto primitives are far to useful to re-work
// at this stage. This file exists to keep the dependencies on go-ethereum in
// one place. Its not clear how this will all turn out.  Possibly a rrr go
// package is useful in order to support both quorum and go-ethereum upstream,
// possibly that isn't realistic. This small accomodation keeps to door open a
// crack

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type Hash [32]byte

// Address is the ethereum style right most 20 bytes of Keccak256 (pub.X || pub.Y )
type Address [20]byte

func RlpEncodeToBytes(v interface{}) ([]byte, error) {
	return rlp.EncodeToBytes(v)
}

func RlpDecodeBytes(b []byte, v interface{}) error {
	return rlp.DecodeBytes(b, v)
}

func Keccak256(b ...[]byte) []byte {
	return crypto.Keccak256(b...)
}

func Keccak256Hash(b ...[]byte) Hash {
	h := Hash{}
	copy(h[:], Keccak256(b...))
	return h
}

func Sign(h []byte, k *ecdsa.PrivateKey) ([]byte, error) {
	return crypto.Sign(h, k)
}

func Ecrecover(hash, sig []byte) ([]byte, error) {
	return crypto.Ecrecover(hash, sig)
}

func VerifySignature(pub, digest, sig []byte) bool {
	return crypto.VerifySignature(pub, digest, sig)
}

func RecoverPublic(h []byte, sig []byte) (*ecdsa.PublicKey, error) {

	// Recover the public signing key bytes in uncompressed encoded form
	p, err := Ecrecover(h, sig)
	if err != nil {
		return nil, err
	}

	// re-build the public key for the private key used to sign the userdata
	// hash
	//
	// per 2.3.4 sec1-v2 for uncompresed representation "otherwise the leftmost
	// octet of the octetstring is removed"

	pub := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	pub.X.SetBytes(p[1 : 1+32])
	pub.Y.SetBytes(p[1+32 : 1+64])
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return pub, nil
}
