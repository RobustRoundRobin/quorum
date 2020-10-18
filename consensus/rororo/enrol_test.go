package rororo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/rlp"
)

func TestRoundTripChainID(t *testing.T) {

	var err error

	require := require.New(t)

	// Test that the chainid, and hence the encoding, is stable when round
	// triped through multiple encode / decode / encode operations

	extra1 := &GenesisExtraData{
		ChainInit: ChainInit{
			IdentInit: []Enrolment{
				{Q: Quote{8, 9}, U: [32]byte{10, 11}},
			},
			Seed:  []byte{0, 1, 2, 3},
			Proof: []byte{4, 5, 6, 7},
		},
	}

	var b []byte
	b, err = rlp.EncodeToBytes(extra1)
	require.Nil(err)

	extra2 := &GenesisExtraData{}
	err = rlp.DecodeBytes(b, extra2)
	require.Nil(err)

	b, err = rlp.EncodeToBytes(extra2)
	require.Nil(err)
	// decode back into the original and check both chain ids are the same
	err = rlp.DecodeBytes(b, extra1)
	require.Nil(err)

	require.Equal(extra1.ChainID, extra2.ChainID, "extra data encoding  of chainid is incorrect")
}
