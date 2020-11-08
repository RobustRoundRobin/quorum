package rororo

import (
	"crypto/ecdsa"
	"io"

	"github.com/ethereum/go-ethereum/rlp"
)

type ChainInit struct {
	IdentInit []Enrolment
	He        Hash   // Always zero, as there is no enclave code to hash
	Seed      []byte // generate using crypto/rand for now
	Proof     []byte // simply Sig(CK, Seed) for now, its not really meaningful until we add VRF support
}

type GenesisExtraData struct {
	ChainInit
	ChainID Hash // EncodeRLP fills this in automatically
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
