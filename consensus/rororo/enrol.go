package rororo

// All hashes are keccak 256 unless otherwise stated

import (
	"crypto/ecdsa"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/rlp"
)

// Quote is the 'pseudo' attestation of identity performed using node private
// keys rather than SGX. See EIP-rororo 'extraData of Block0' and 'Enrolment
// data'. It is only the "Quote" refrenced in the original paper in so far as
// it will be the Qi that gets included in Block0 or in Enroln messages.  It's
// an ecdsa signature the [R || S || V] format
type Quote [65]byte

type Enrolment struct {
	Q Quote
	U Hash // nodeid for genesis, EnrolmentBinding.U() otherwise
}

// IdentInit creates, or extends, the identity initialisation vector for the extraData in
// the genesis block. init is nil or the currently included identities. One or
// more nodeids are passes as the trailing parameters. The updated init vector
// is returned. See EIP-rororo/extraData of Block0
func IdentInit(ck *ecdsa.PrivateKey, init []Enrolment, nodeids ...Hash) ([]Enrolment, error) {

	start := len(init)
	init = append(init, make([]Enrolment, len(nodeids))...)

	for i, id := range nodeids {
		err := init[start+i].Q.Fill(ck, id)
		if err != nil {
			return init, err
		}
		copy(init[start+i].U[:], id[:])
	}
	return init, nil
}

type ChainInit struct {
	IdentInit []Enrolment
	He        Hash   // Always zero, as there is no enclave code to hash
	Seed      []byte // generate using crypto/rand for now
	Proof     []byte // simply Sig(CK, Seed) for now, its not really meaningful until we add VRF support
}

// Populate fills in a ChainInit ready for encoding in the genesis extraData
// See EIP-rororo/extraData of Block0/9.
func (ci *ChainInit) Populate(ck *ecdsa.PrivateKey, initIdents []Enrolment, seed []byte) error {

	ci.IdentInit = make([]Enrolment, len(initIdents))
	ci.Seed = make([]byte, len(seed))

	copy(ci.IdentInit, initIdents)

	copy(ci.Seed, seed)
	var err error
	ci.Proof, err = Sign(Keccak256(ci.Seed), ck) // TODO VRF support
	return err
}

func (ci *ChainInit) ChainID() (Hash, error) {

	id := Hash{}
	b, err := RlpEncodeToBytes(ci)
	if err != nil {
		return id, err
	}
	copy(id[:], Keccak256(b))
	return id, err
}

type GenesisExtraData struct {
	ChainInit
	ChainID Hash // EncodeRLP fills this in automatically
}

func (gd *GenesisExtraData) EncodeRLP(w io.Writer) error {

	var err error
	var b []byte

	list := make([]interface{}, 2)

	if b, err = rlp.EncodeToBytes(gd.ChainInit); err != nil {
		return err
	}
	list[0] = rlp.RawValue(b)

	if b, err = rlp.EncodeToBytes(Keccak256(b)); err != nil {
		return err
	}
	list[1] = rlp.RawValue(b)
	return rlp.Encode(w, list)
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
	a *ecdsa.PrivateKey, chainID Hash, nodeid Hash, round *big.Int, blockHash Hash) error {
	e := EnrolmentBinding{
		ChainID: chainID, NodeID: nodeid, Round: round, BlockHash: blockHash}
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
	// XXX: TODO think Keccak256 call is wrong here, we just want u[:] directly
	p, err := Ecrecover(Keccak256(u[:]), q[:])
	if err != nil {
		return Hash{}, err
	}
	id := Hash{}
	copy(id[:], Keccak256(p[1:65]))
	return id, nil
}
