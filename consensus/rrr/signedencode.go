package rrr

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
)

var (
	errSignedDecodeSignedFailed = errors.New("decoding signed rlp struct failed")
)

// verifyNodeSig verifies that sig was produced by the public key for the node
// identified by nodeID. The nodeID is the hash of the nodes public key. So
// rather that a typical verify where the r co-ords are compared, we recover
// the full public key and hash it to get the node id of the signer.
func verifyNodeSig(nodeID Hash, sig []byte, v interface{}) (bool, error) {

	var err error
	var b []byte
	var pub []byte

	// Recover the public key which produced sig over hash(rlp(v)) and derive
	// the corresponding node id.
	if b, err = rlp.EncodeToBytes(v); err != nil {
		return false, err
	}
	h := Keccak256(b)
	pub, err = Ecrecover(h, sig)
	if err != nil {
		return false, err
	}
	signedByID, err := PubBytes2NodeID(pub)
	if err != nil {
		return false, err
	}

	if signedByID != nodeID {
		return false, fmt.Errorf("signature mismatch: signer=`%s', wanted=`%s'",
			hex.EncodeToString(signedByID[:]), hex.EncodeToString(nodeID[:]))
	}

	return true, nil
}

func signedEncode(k *ecdsa.PrivateKey, v interface{}) ([65]byte, rlp.RawValue, error) {
	var err error
	var b []byte
	var sig [65]byte

	list := make([]interface{}, 2)

	if b, err = rlp.EncodeToBytes(v); err != nil {
		return [65]byte{}, nil, err
	}
	list[0] = rlp.RawValue(b)

	h := Keccak256(b)

	if b, err = Sign(h, k); err != nil {
		return [65]byte{}, nil, err
	}

	copy(sig[:], b)

	list[1] = b

	if b, err = rlp.EncodeToBytes(list); err != nil {
		return [65]byte{}, nil, err
	}
	return sig, rlp.RawValue(b), nil
}

// decodeSigned decodes a hash and its 65 byte ecdsa signture and recovers the
// puplic key. In this implementation, the recovered public key is the RRR long
// term identity and we pretty much always want that to hand.
func decodeSigned(s *rlp.Stream) ([65]byte, []byte, []byte, error) {

	var err error
	var sig [65]byte
	var pub []byte

	if _, err = s.List(); err != nil {
		return [65]byte{}, nil, nil, err
	}

	// First item is the full encoding of the signed item, get the bytes and
	// recover the pub key using the hash of the encoded bytes
	var body []byte
	if body, err = s.Raw(); err != nil {
		return [65]byte{}, nil, nil, err
	}
	h := Keccak256(body)

	// read the signature
	var b []byte
	if b, err = s.Bytes(); err != nil {
		return [65]byte{}, nil, nil, err
	}
	copy(sig[:], b)

	// recover the public key
	pub, err = Ecrecover(h, b)
	if err != nil {
		return [65]byte{}, nil, nil, err
	}

	if err = s.ListEnd(); err != nil {
		return [65]byte{}, nil, nil, err
	}
	return sig, pub, body, nil
}
