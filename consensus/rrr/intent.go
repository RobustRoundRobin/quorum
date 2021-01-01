package rrr

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/rlp"
)

type Intent struct {
	// ChainID is established in the extradata of the genesis block
	ChainID Hash
	// NodeID is Keccak256 ( PublicKey X || Y )
	NodeID Hash
	// RoundNumber is the block number proposed.
	RoundNumber *big.Int
	// FailedAttempts is the number of times the intent/confirm cycle completed
	// on the node without a new block being produced. The validity of the
	// proposer as a leader is depedent on both the RoundNumber and the
	// FailedAttempts
	FailedAttempts uint
	// ParentHash parent block hash
	ParentHash Hash
	// TxHash is the hash of the transactions (merkle root for block)
	TxHash Hash
}

func (i *Intent) Hash() (Hash, error) {
	var err error
	var b []byte
	if b, err = rlp.EncodeToBytes(i); err != nil {
		return Hash{}, err
	}

	h := Hash{}
	copy(h[:], Keccak256(b))
	return h, nil
}

type SignedIntent struct {
	Intent
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

// SignedEncode rlp encodes the intent body, signs the result and returns the
// RLP encoding of the result. c will typically be a leader candidate private
// key.
func (i *SignedIntent) SignedEncode(k *ecdsa.PrivateKey) (rlp.RawValue, error) {

	var err error
	var r rlp.RawValue
	i.Sig, r, err = signedEncode(k, &i.Intent)
	return r, err
}

func (i *SignedIntent) DecodeSigned(s *rlp.Stream) ([]byte, error) {

	sig, pub, body, err := decodeSigned(s)
	if err != nil {
		return nil, err
	}
	i.Sig = sig

	// Do the defered decoding of the Intent now we have verified the sig
	if err = rlp.DecodeBytes(body, &i.Intent); err != nil {
		return nil, err
	}

	return pub, nil
}
