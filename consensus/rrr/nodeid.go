package rrr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// Pub2NodeIDBytes NodeID is Keccak256 (Pub.X || Pub.Y )
// In contexts where we have the id and a signature, we can recover the pub key
// of the signer using Ecrecover
func Pub2NodeIDBytes(pub *ecdsa.PublicKey) []byte {
	buf := make([]byte, 64)
	math.ReadBits(pub.X, buf[:32])
	math.ReadBits(pub.Y, buf[32:])
	return crypto.Keccak256(buf)
}

// PubBytes2NodeID gets a node id from the bytes of an ecdsa public key
func PubBytes2NodeID(pub []byte) (Hash, error) {
	if len(pub) != 65 {
		return Hash{}, fmt.Errorf("raw pubkey must be 64 bytes long")
	}
	h := Hash{}
	copy(h[:], Keccak256(pub[1:]))
	return h, nil
}

// Pub2NodeID gets a node id from an ecdsa pub key
func Pub2NodeID(pub *ecdsa.PublicKey) Hash {
	h := Hash{}
	copy(h[:], Pub2NodeIDBytes(pub))
	return h
}

// Address gets an address from a hash
func (h Hash) Address() Address {
	a := Address{}
	copy(a[:], h[12:])
	return a
}

// Hex gets the hex string of the Hash
func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

// Hex gets the hex string for the Address
func (a Address) Hex() string {
	return hex.EncodeToString(a[:])
}

// SignerPub recovers the public key that signed h
func (h Hash) SignerPub(sig []byte) (*ecdsa.PublicKey, error) {
	return RecoverPublic(h[:], sig)
}

// SignerNodeID gets the recovers the signers node id  from the signature
func (h Hash) SignerNodeID(sig []byte) (Hash, error) {
	pub, err := h.SignerPub(sig)
	if err != nil {
		return Hash{}, err
	}
	return Pub2NodeID(pub), nil
}

// SignerEnodeID recovers the enode id for the signer of the hash
func (h Hash) SignerEnodeID(sig []byte) ([]byte, error) {
	pub, err := RecoverPublic(h[:], sig)
	if err != nil {
		return nil, err
	}
	return elliptic.Marshal(crypto.S256(), pub.X, pub.Y)[1:], nil
}
