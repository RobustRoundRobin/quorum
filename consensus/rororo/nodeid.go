package rororo

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// NodeID is Keccak256 (Pub.X || Pub.Y )
// In contexts where we have the id and a signature, we can recover the pub key
// of the signer using Ecrecover

func Pub2NodeIDBytes(pub *ecdsa.PublicKey) []byte {
	buf := make([]byte, 64)
	math.ReadBits(pub.X, buf[:32])
	math.ReadBits(pub.Y, buf[32:])
	return crypto.Keccak256(buf)
}

func Pub2NodeID(pub *ecdsa.PublicKey) Hash {
	h := Hash{}
	copy(h[:], Pub2NodeIDBytes(pub))
	return h
}

// SignerPub recovers the public key that signed h
func SignerPub(h Hash, sig []byte) (*ecdsa.PublicKey, error) {
	return RecoverPublic(h[:], sig)
}

func SignerNodeID(h Hash, sig []byte) (Hash, error) {
	pub, err := RecoverPublic(h[:], sig)
	if err != nil {
		return Hash{}, err
	}
	return Pub2NodeID(pub), nil
}

// Recover the enode id for the signer of the hash
func SignerEnodeID(h Hash, sig []byte) ([]byte, error) {
	pub, err := RecoverPublic(h[:], sig)
	if err != nil {
		return nil, err
	}
	return elliptic.Marshal(crypto.S256(), pub.X, pub.Y)[1:], nil
}
