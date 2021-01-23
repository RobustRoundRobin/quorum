package rrr

import (
	"crypto/ecdsa"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	dummySeed = []byte{0, 1, 2, 3, 4, 5, 6, 7}
)

func TestDecodeGenesisActivity(t *testing.T) {

	assert := assert.New(t)

	var err error
	keys := requireGenerateKeys(t, 3)
	ge := requireMakeGenesisExtra(t,
		keys[0], []byte{0, 1, 2, 3, 4, 5, 6, 7}, identitiesFromKeys(keys...)...)
	assert.Nil(err, "error")

	genesis := makeBlock(withExtra(requireEncodeToBytes(t, ge)))
	a := &BlockActivity{}
	a.Decode(ge.ChainID, genesis.Header())

	assert.Len(a.Enrol, 3, "missing enrolments")
}

func TestDecodeActivity(t *testing.T) {

	assert := assert.New(t)

	keys := requireGenerateKeys(t, 3)
	ge := requireMakeGenesisExtra(t,
		keys[0], []byte{0, 1, 2, 3, 4, 5, 6, 7}, identitiesFromKeys(keys...)...)

	genesis := makeBlock(withExtra(requireEncodeToBytes(t, ge)))

	intent := fillIntent(nil, ge.ChainID, keys[0], genesis, big.NewInt(1), 0)

	se1 := requireMakeSignedEndorsement(t, ge.ChainID, keys[1], intent)
	se2 := requireMakeSignedEndorsement(t, ge.ChainID, keys[2], intent)

	_, data := requireMakeSignedExtraData(t,
		keys[0], 0, intent, []*SignedEndorsement{se1, se2}, []byte{8, 9, 10, 11, 12, 13, 14, 15})

	extra := make([]byte, RRRExtraVanity)
	extra = append(extra, data...)

	block1 := makeBlock(withNumber(1), withExtra(extra))
	a := &BlockActivity{}
	a.Decode(ge.ChainID, block1.Header())

	assert.Len(a.Confirm, 2, "missing confirmations")
}

func TestFirstAccumulate(t *testing.T) {

	logger := log.New()
	logger.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(false)))

	require := require.New(t)
	assert := assert.New(t)

	tActive := uint64(10)
	net := newNetwork(t, 3)
	ch := newChain(net.genesis)
	ch.Extend(net, 0, 1, 2)

	a := &ActiveSelection{logger: logger}
	a.Reset(tActive, net.genesis)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())

	require.NoError(err)
	assert.Len(a.aged, 3, "missing active from aged")
	assert.Equal(a.activeSelection.Len(), 3, "missing active from selection")
	assert.Len(a.idlePool, 0, "idle identities found")

	// the youngest identity should be at the front and should be the id=0
	id, ok := net.nodeID2id[a.activeSelection.Front().Value.(*idActivity).nodeID]
	require.True(ok)
	assert.Equal(id, 0)

}

// network represents a network of identities participating in RRR consensus
// for the purposes of the tests
type network struct {
	t *testing.T

	ge      *GenesisExtraData
	genesis *types.Block

	// For clarity of testing, work with integer indices as id's
	id2key    map[int]*ecdsa.PrivateKey
	id2NodeID map[int]Hash
	nodeID2id map[Hash]int
	keys      []*ecdsa.PrivateKey
}

type chain struct {
	blocks []*types.Block
	db     map[common.Hash]int
}

func newChain(genesis *types.Block) *chain {
	ch := &chain{
		blocks: []*types.Block{genesis},
		db:     make(map[common.Hash]int),
	}
	ch.db[ch.blocks[0].Header().Hash()] = 0
	return ch
}

func (ch *chain) CurrentBlock() *types.Block {
	return ch.blocks[len(ch.blocks)-1]
}

func (ch *chain) GetHeaderByHash(hash common.Hash) *types.Header {
	if i, ok := ch.db[hash]; ok {
		return ch.blocks[i].Header()
	}
	return nil
}

func (ch *chain) Extend(net *network, idSeal int, idConfirm ...int) *types.Block {
	parent := ch.CurrentBlock()

	intent := net.newIntent(idSeal, parent, 0)
	confirm := net.endorseIntent(intent, idConfirm...)
	block := net.sealBlock(idSeal, intent, confirm, dummySeed)
	ch.blocks = append(ch.blocks, block)
	ch.db[block.Header().Hash()] = len(ch.blocks) - 1
	return block
}

func newNetwork(t *testing.T, numIdents int) *network {
	net := &network{
		t:         t,
		keys:      requireGenerateKeys(t, numIdents),
		id2key:    make(map[int]*ecdsa.PrivateKey),
		id2NodeID: make(map[int]Hash),
		nodeID2id: make(map[Hash]int),
	}

	identities := identitiesFromKeys(net.keys...)
	for id, key := range net.keys {
		net.id2key[id] = key
		net.id2NodeID[id] = Pub2NodeID(&key.PublicKey)
		net.nodeID2id[net.id2NodeID[id]] = id
	}

	net.ge = requireMakeGenesisExtra(t,
		net.keys[0], []byte{0, 1, 2, 3, 4, 5, 6, 7},
		identities...)

	net.genesis = makeBlock(withExtra(requireEncodeToBytes(t, net.ge)))

	return net
}

func (net *network) newIntent(
	idFrom int, parent *types.Block, failedAttempts uint) *Intent {
	key := net.id2key[idFrom]
	require.NotZero(net.t, key)

	roundNumber := big.NewInt(0)
	roundNumber.Add(parent.Header().Number, bigOne)
	return fillIntent(
		nil, net.ge.ChainID, key, parent, roundNumber, failedAttempts)
}

func (net *network) endorseIntent(
	intent *Intent, idBy ...int) []*SignedEndorsement {

	confirm := make([]*SignedEndorsement, len(idBy))
	for i, id := range idBy {
		key := net.id2key[id]
		require.NotZero(net.t, key)
		confirm[i] = requireMakeSignedEndorsement(net.t, net.ge.ChainID, key, intent)
	}
	return confirm
}

func (net *network) sealBlock(
	idSealer int, intent *Intent, confirm []*SignedEndorsement, seed []byte,
) *types.Block {

	key := net.id2key[idSealer]
	require.NotZero(net.t, key)

	_, data := requireMakeSignedExtraData(net.t, key, 0, intent, confirm, dummySeed)

	extra := make([]byte, RRRExtraVanity)
	extra = append(extra, data...)
	return makeBlock(
		withNumber(intent.RoundNumber.Int64()),
		withParent(common.Hash(intent.ParentHash)),
		withExtra(extra))
}

func requireMakeSignedExtraData(
	t *testing.T,
	sealer *ecdsa.PrivateKey,
	sealTime uint64, intent *Intent, confirm []*SignedEndorsement,
	seed []byte,
) (*SignedExtraData, []byte) {

	data := &SignedExtraData{
		ExtraData: ExtraData{
			SealTime: sealTime,
			Intent:   *intent,
			Confirm:  make([]Endorsement, len(confirm)),
		},
	}
	data.Intent.RoundNumber = big.NewInt(0).Set(intent.RoundNumber)
	if seed != nil {
		copy(data.Seed, seed)
	}
	for i, c := range confirm {
		data.Confirm[i] = c.Endorsement
	}
	seal, err := data.SignedEncode(sealer)
	require.NoError(t, err)
	return data, seal
}

func requireMakeSignedEndorsement(
	t *testing.T,
	chainID Hash, endorser *ecdsa.PrivateKey, intent *Intent) *SignedEndorsement {

	h, err := intent.Hash()
	require.NoError(t, err)

	c := &SignedEndorsement{
		Endorsement: Endorsement{
			ChainID:    chainID,
			IntentHash: h,
			EndorserID: Pub2NodeID(&endorser.PublicKey),
		},
	}
	return c
}

func fillIntent(
	i *Intent,
	chainID Hash, proposer *ecdsa.PrivateKey,
	parent *types.Block, roundNumber *big.Int, failedAttempts uint) *Intent {

	if i == nil {
		i = &Intent{}
	}

	i.ChainID = chainID
	i.NodeID = Pub2NodeID(&proposer.PublicKey)
	i.RoundNumber = big.NewInt(0).Set(roundNumber)
	i.FailedAttempts = failedAttempts
	i.ParentHash = Hash(parent.Header().Hash())
	i.TxHash = Hash(parent.TxHash())
	return i
}

func requireMakeGenesisExtra(
	t *testing.T,
	key *ecdsa.PrivateKey,
	seed []byte, identities ...Hash) *GenesisExtraData {

	initIdents, err := IdentInit(key, nil, identities...)
	require.NoError(t, err)

	extra := &GenesisExtraData{}
	err = extra.ChainInit.Populate(key, initIdents, seed)
	require.NoError(t, err)
	return extra
}

func requireEncodeToBytes(t *testing.T, val interface{}) []byte {
	b, err := rlp.EncodeToBytes(val)
	require.NoError(t, err)
	return b
}

type headerOption func(h *types.Header)

func withNumber(n int64) headerOption {
	return func(h *types.Header) {
		h.Number = big.NewInt(n)
	}
}
func withExtra(extra []byte) headerOption {
	return func(h *types.Header) {
		h.Extra = nil
		if extra != nil {
			h.Extra = make([]byte, len(extra))
			copy(h.Extra, extra)
		}
	}
}

func withParent(parentHash common.Hash) headerOption {
	return func(h *types.Header) {
		copy(h.ParentHash[:], parentHash[:])
	}
}

func makeBlock(opts ...headerOption) *types.Block {
	header := &types.Header{
		Difficulty: big.NewInt(0),
		Number:     big.NewInt(0),
		GasLimit:   0,
		GasUsed:    0,
		Time:       0,
	}
	for _, opt := range opts {
		opt(header)
	}

	block := &types.Block{}
	return block.WithSeal(header)
}

func requireGenerateKeys(t *testing.T, count int) []*ecdsa.PrivateKey {

	var err error

	keys := make([]*ecdsa.PrivateKey, count)
	for i := 0; i < count; i++ {
		keys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
	}

	return keys
}

func identitiesFromKeys(keys ...*ecdsa.PrivateKey) []Hash {
	nodeIDs := make([]Hash, len(keys))
	for i, key := range keys {
		nodeIDs[i] = Pub2NodeID(&key.PublicKey)
	}
	return nodeIDs
}
