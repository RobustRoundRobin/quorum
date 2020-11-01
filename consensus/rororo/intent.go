package rororo

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/rlp"
)

var (
	ErrIntentVerifyFailed = errors.New("decoding intent, verify failed")
)

type Intent struct {
	// ChainID is established in the extradata of the genesis block
	ChainID Hash
	// NodeID is Keccak256 ( PublicKey X || Y )
	NodeID      Hash
	RoundNumber *big.Int
	// ParentHash parent block hash
	ParentHash Hash
	// TxHash is the hash of the transactions (merkle root for block)
	TxHash Hash
}

type Confirmation struct {
	ChainID    Hash
	EndorserID Hash // NodeID of endorser
	IntentHash Hash
}

type SignedIntent struct {
	Intent
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

type SignedConfirmation struct {
	Confirmation
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

// EncodeSigned rlp encodes the intent body, signs the result and returns the
// RLP encoding of the result. c will typically be a leader candidate private
// key.
func (i *SignedIntent) EncodeSigned(c *ecdsa.PrivateKey) (rlp.RawValue, error) {

	var err error
	var b []byte

	list := make([]interface{}, 2)

	if b, err = rlp.EncodeToBytes(i.Intent); err != nil {
		return nil, err
	}
	list[0] = rlp.RawValue(b)

	h := Keccak256(b)

	if b, err = Sign(h, c); err != nil {
		return nil, err
	}

	copy(i.Sig[:], b) // So the caller can retrieve it if they want

	list[1] = b

	if b, err = rlp.EncodeToBytes(list); err != nil {
		return nil, err
	}
	return rlp.RawValue(b), nil
}

func (i *SignedIntent) DecodeVerify(s *rlp.Stream) ([]byte, error) {
	var err error
	if _, err = s.List(); err != nil {
		return nil, err
	}

	// First item is the full encoding of the IntentBody, get the bytes and
	// verify the sig using the hash of the encoded bytes
	var body []byte
	if body, err = s.Raw(); err != nil {
		return nil, err
	}
	h := Keccak256(body)

	var b []byte
	if b, err = s.Bytes(); err != nil {
		return nil, err
	}
	copy(i.Sig[:], b)

	pub, err := Ecrecover(h, b)
	if err != nil {
		return nil, err
	}

	// note: b is sig as R || S || V, we need to drop the V
	if !VerifySignature(pub, h, b[:64]) {
		return nil, ErrIntentVerifyFailed
	}

	// Do the defered decoding of the IntentBody now we have verified the sig
	if err = rlp.DecodeBytes(body, &i.Intent); err != nil {
		return nil, err
	}

	if err = s.ListEnd(); err != nil {
		return nil, err
	}
	return pub, nil
}
