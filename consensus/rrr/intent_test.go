package rrr

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	ecvrf "github.com/vechain/go-ecvrf"
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

// TestVRF is just an integration test to show we can build and use the dep
func TestVRF(t *testing.T) {
	require := require.New(t)

	sk, err := crypto.GenerateKey()
	require.Nil(err)

	alpha := "Hello RRR"

	vrf := ecvrf.NewSecp256k1Sha256Tai()

	beta, pi, err := vrf.Prove(sk, []byte(alpha))
	require.Nil(err)

	beta2, err := vrf.Verify(&sk.PublicKey, []byte(alpha), pi)
	require.Nil(err)
	require.Equal(beta, beta2)
}
