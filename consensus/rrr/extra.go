package rrr

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/rlp"
)

type ExtraData struct {
	// SealTime is not part of the protocol. It is used for reporting
	// disemination latencey. It is the unix time on the sealers system.
	SealTime uint64
	Intent   Intent
	Confirm  []Endorsement
	Enrol    []Enrolment
	Seed     []byte // generated using crypto/rand for now
	Proof    []byte // Not meaningful until we add VRF support
}

type SignedExtraData struct {
	ExtraData
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

func (e *SignedExtraData) SignedEncode(k *ecdsa.PrivateKey) (rlp.RawValue, error) {
	var err error
	var r rlp.RawValue
	e.Sig, r, err = signedEncode(k, e.ExtraData)
	return r, err
}

func (e *SignedExtraData) DecodeSigned(s *rlp.Stream) ([]byte, error) {

	sig, pub, body, err := decodeSigned(s)
	if err != nil {
		return nil, err
	}
	e.Sig = sig

	// Do the defered decoding of the Endorsement now we have verified the sig
	if err = rlp.DecodeBytes(body, &e.ExtraData); err != nil {
		return nil, err
	}
	return pub, nil
}
