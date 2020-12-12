package rrr

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/rlp"
)

type Endorsement struct {
	ChainID    Hash
	IntentHash Hash
	EndorserID Hash // NodeID of endorser
}

type SignedEndorsement struct {
	Endorsement
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

func (c *SignedEndorsement) SignedEncode(k *ecdsa.PrivateKey) (rlp.RawValue, error) {

	var err error
	var r rlp.RawValue
	c.Sig, r, err = signedEncode(k, &c.Endorsement)

	return r, err
}

func (c *SignedEndorsement) VerifyNodeSig(nodeID Hash) (bool, error) {
	return verifyNodeSig(nodeID, c.Sig[:], &c.Endorsement)
}

// DecodeSigned decodes the endorsment and returns the signers ecrecovered public key
func (c *SignedEndorsement) DecodeSigned(s *rlp.Stream) ([]byte, error) {

	sig, pub, body, err := decodeSigned(s)
	if err != nil {
		return nil, err
	}
	c.Sig = sig

	if err = rlp.DecodeBytes(body, &c.Endorsement); err != nil {
		return nil, err
	}
	return pub, nil
}
