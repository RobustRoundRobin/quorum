package rrr

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func TestIntentDecodeSigned(t *testing.T) {
	require := require.New(t)

	k, err := crypto.GenerateKey()
	require.Nil(err)

	i := &SignedIntent{
		Intent: Intent{
			ChainID: Hash{1, 2}, NodeID: Hash{3, 4}, ParentHash: Hash{5, 6}},
	}

	raw, err := i.SignedEncode(k)

	iv := &SignedIntent{}
	s := rlp.NewStream(bytes.NewReader([]byte(raw)), 0)
	_, err = iv.DecodeSigned(s)
	require.Nil(err)
}
