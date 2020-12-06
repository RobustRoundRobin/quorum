package rororo

// All hashes are keccak 256 unless otherwise stated

import (
	"crypto/ecdsa"
	"math/big"
)

// Quote is the 'pseudo' attestation of identity performed using node private
// keys rather than SGX. See RRR-spec 'extraData of Block0' and 'Enrolment
// data'. It is only the "Quote" refrenced in the original paper in so far as
// it will be the Qi that gets included in Block0 or in Enroln messages.  It's
// an ecdsa signature the [R || S || V] format
type Quote [65]byte

type Enrolment struct {
	Q Quote
	U Hash // nodeid for genesis, EnrolmentBinding.U() otherwise

	// ID can be verified by reconstructing an EnrolmentBinding, getting its
	// hash, comparing that hash with U (above) and then checking that the
	// public key for the node that sealed the block with the Enrolment can
	// verify the quote.
	ID Hash // must be verified by re-creating an Enrol
}

// Fill intitialises a Quote for an identity to be enroled on the chain.
// a is the attestor. For genesis enrolment, this should be the chain creators
// private key.
// u is the 'userdata' hash to attest. For genesis identity
// enrolment it is just the enode identity directly (they are already 32 byte
// hashes). For operational enrolment it the hash of the rlp encoded
// EnrolmentBinding struct
func (q *Quote) Fill(a *ecdsa.PrivateKey, u Hash) error {

	var err error
	var b []byte

	if b, err = Sign(u[:], a); err != nil {
		return err
	}
	copy(q[:], b[:])

	return nil
}

// EnrolIdentity fills in a quote for operational enrolment of the supplied
// nodeid. This binds the enrolment to the chain identified by chainID. Round
// is the current round of consensus. blockHash identifies the current head of
// the chain (selected branch)
func (q *Quote) EnrolIdentity(
	a *ecdsa.PrivateKey, chainID Hash, nodeid Hash, round *big.Int, blockHash Hash, reEnrol bool) error {
	e := EnrolmentBinding{
		ChainID: chainID, NodeID: nodeid, Round: round, BlockHash: blockHash, ReEnrol: reEnrol}
	u, err := e.U()
	if err != nil {
		return err
	}
	return q.Fill(a, u)
}

// EnrolmentBinding is rlp encoded, hashed and signed to introduce NodeID as a
// member.
type EnrolmentBinding struct {
	ChainID   Hash     // ChainID is EIP-rororo/extraData of Block0
	NodeID    Hash     // NodeID is defined by ethereum as keccak 256 ( PublicKey X || Y )
	Round     *big.Int // Round is the consensus round
	BlockHash Hash     // BlockHash is the block hash for the head of the selected chain branch
	ReEnrol   bool     // true if the identity has been enroled before.
}

// U encodes the userdata hash to sign for the enrolment.
func (e *EnrolmentBinding) U() (Hash, error) {

	u := Hash{}
	b, err := RlpEncodeToBytes(e)
	if err != nil {
		return u, err
	}
	copy(u[:], Keccak256(b))
	return u, nil
}

// RecoverPublic recovers the attestors public key from the signature and the
// attested userdata hash. For a genesis enrolment, that is just the nodeid
// directly. For operational enrolments, obtain u by filling in the
// EnrolementBinding type and calling U()
func (q *Quote) RecoverPublic(u Hash) (*ecdsa.PublicKey, error) {
	return RecoverPublic(u[:], q[:])
}

// RecoverID recovers the attestors identity from the signature and the
// identity (public key) of the quoted node
func (q *Quote) RecoverID(u Hash) (Hash, error) {
	p, err := Ecrecover(u[:], q[:])
	if err != nil {
		return Hash{}, err
	}
	id := Hash{}
	copy(id[:], Keccak256(p[1:65]))
	return id, nil
}
