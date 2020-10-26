package rororo

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func TestIntentVerify(t *testing.T) {
	require := require.New(t)

	k, err := crypto.GenerateKey()
	require.Nil(err)

	i := &SignedIntent{
		Intent: Intent{
			ChainID: Hash{1, 2}, NodeID: Hash{3, 4}, Parent: Hash{5, 6}},
	}

	raw, err := i.EncodeSigned(k)

	iv := &SignedIntent{}
	s := rlp.NewStream(bytes.NewReader([]byte(raw)), 0)
	_, err = iv.DecodeVerify(s)
	require.Nil(err)
}
