package rrr

import (
	"crypto/ecdsa"
	"errors"
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
	dummySeed  = []byte{0, 1, 2, 3, 4, 5, 6, 7}
	dummyProof = []byte{0, 1, 2, 3, 4, 5, 6, 7}
)

func TestDecodeGenesisActivity(t *testing.T) {

	assert := assert.New(t)

	var err error
	keys := requireGenerateKeys(t, 3)
	ge := requireMakeGenesisExtra(t,
		keys[0], dummySeed, dummyProof, identitiesFromKeys(keys...)...)
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
		keys[0], dummySeed, dummyProof, identitiesFromKeys(keys...)...)

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

// TestAccumulateGenesisActivity tests that the order of enrolments
// in the gensis block match the order produced by ActiveSelection from the
// genesis block
func TestAccumulateGenesisActivity(t *testing.T) {

	require := require.New(t)
	assert := assert.New(t)

	logger := log.New()
	logger.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(false)))

	tActive := uint64(10)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	a := &ActiveSelection{logger: logger}
	a.Reset(tActive, net.genesis)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())

	require.NoError(err)
	assert.Equal(a.activeSelection.Len(), numIdents, "missing active from selection")

	// For the genesis block, the age ordering should exactly match the
	// enrolment order. And the identity that signed the genesis block should be
	// the youngest - as it is considered more recently active than any identity
	// it enrols in the block it seals.
	order := make([]int, numIdents)
	for i := 0; i < numIdents-1; i++ {
		order[i] = i + 1
	}
	order[numIdents-1] = 0

	a.requireOrder(t, net, order)
}

// TestFirstAccumulate tests the accumulation of activity from the first
// consensus block (the block after genesis)
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

// TestAccumulateTwice tests that the order is stable (and correct) if the same
// identity is encountered twice. The first encounter of the identity in an
// accumulation determines its age. Any subsequent enconter should not change
// it.
func TestAccumulateTwice(t *testing.T) {
	require := require.New(t)

	logger := log.New()
	logger.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(false)))

	tActive := uint64(10)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	a := &ActiveSelection{logger: logger}
	a.Reset(tActive, net.genesis)

	// Establish the intial ordering from the genesis block.
	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())
	require.NoError(err)

	// Now id(0) is the youngest, and id(1) is the oldest

	// Make 3 blocks. The first and the last will be sealed by the same identity.

	ch.Extend(net, 1, 2, 3, 4) // sealer, ...endorsers
	// Imagining the rounds progress as expected, 2 should seal next
	ch.Extend(net, 2, 3, 4, 5)
	// Something very odd happened and 1 seals the next block (in reality this
	// implies a lot of failed attempts and un reachable nodes). Lets make the
	// endorsers the same too.
	ch.Extend(net, 1, 2, 3, 4)

	idYoungest := net.nodeID2id[a.activeSelection.Front().Value.(*idActivity).nodeID]

	// [ ..., 0]
	// [ ..., 0, 1]
	// [ ..., 0, 1, 2]
	// [ ..., 0, 2, 1]

	err = a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())
	require.NoError(err)
	idYoungestAfter := net.nodeID2id[a.activeSelection.Front().Value.(*idActivity).nodeID]

	order := []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 2, 1}

	a.logger.Info("youngest before", "id", idYoungest)
	a.logger.Info("youngest after", "id", idYoungestAfter)
	a.requireOrder(t, net, order)
}

// TestBranchDetection tests that AccumulateActive spots forks and returns a
// specific error for that case.
func TestBranchDetection(t *testing.T) {
	require := require.New(t)

	logger := log.New()
	logger.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(false)))

	tActive := uint64(10)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	a := &ActiveSelection{logger: logger}
	a.Reset(tActive, net.genesis)

	// build a 4 block chain
	ch.Extend(net, 1, 2, 3, 4) // sealer, ...endorsers
	ch.Extend(net, 2, 3, 4, 5)
	ch.Extend(net, 3, 4, 5, 6)
	ch.Extend(net, 4, 5, 6, 7)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())
	require.NoError(err)

	// Make a fork from block 2
	intent := net.newIntent(5, ch.blocks[2], 0)
	confirm := net.endorseIntent(intent, 6, 7, 8)
	forkFirst := net.sealBlock(5, intent, confirm, dummySeed)
	ch.Add(forkFirst)
	// Now CurrentBlock will return the forked block so we can use extend
	ch.Extend(net, 6, 7, 8, 9)

	err = a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())
	require.True(errors.Is(err, errBranchDetected))
}

// TestShortActivityHorizon tests that the age order of the active selection is
// correct in the event that the activity horizon does not move all identities.
// As is the case when one or more identities are idle - idle means "not seen
// within Ta active". Also, except for the early stages of the chain, Ta
// (active) will be smaller than the block height and this covers that scenario
// too. Note that AccumulateActive does not explicitly identify idles - it
// leaves the unvisited items in the list in their last known possition.
// selectCandidatesAndEndorsers deals with pruning and moving to the idle pool.
func TestShortActityHorizon(t *testing.T) {
	require := require.New(t)

	logger := log.New()
	logger.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(false)))

	tActive := uint64(5)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	a := &ActiveSelection{logger: logger}
	a.Reset(tActive, net.genesis)

	ch.Extend(net, 1, 2, 3, 4) // sealer, ...endorsers
	ch.Extend(net, 2, 3, 4, 5)
	ch.Extend(net, 3, 4, 5, 6)
	ch.Extend(net, 4, 5, 6, 7)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())
	require.NoError(err)

	// We have exactly 5 blocks including the genesis. The genesis has activity
	// for all 12 identities.
	order := []int{5, 6, 7, 8, 9, 10, 11, 0, 1, 2, 3, 4}
	a.requireOrder(t, net, order)

	// Add 7 more blocks
	ch.Extend(net, 5, 6, 7, 8)
	ch.Extend(net, 6, 7, 8, 9)
	ch.Extend(net, 7, 8, 9, 10)
	ch.Extend(net, 8, 9, 10, 11)
	ch.Extend(net, 9, 10, 11, 0)
	ch.Extend(net, 10, 11, 0, 1)
	ch.Extend(net, 11, 0, 1, 2)
	ch.Extend(net, 0, 1, 2, 3)

	err = a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentBlock().Header())
	require.NoError(err)

	// Now we expect the sealers of the most recent 5 to move, and everything
	// else to stay as it was. selectCandidatesAndEndorsers *skips* items that
	// are beyond the tActive horizon. When idles are fully implemented,
	// skipping will involve moving to the idle pool.

	order = []int{5, 6, 7, 1, 2, 3, 4,
		8, 9, 10, 11, 0}
	a.requireOrder(t, net, order)
}

func (a *ActiveSelection) requireOrder(t *testing.T, net *network, order []int) {

	nok := 0

	for cur, icur := a.activeSelection.Back(), 0; cur != nil; cur, icur = cur.Prev(), icur+1 {

		age := cur.Value.(*idActivity)
		ok := order[icur] == net.nodeID2id[age.nodeID]
		if ok {
			nok++
		}
		a.logger.Info(
			"activeItem", "ok", ok, "addr", age.nodeID.Address().HexShort(),
			"order", order[icur], "id", net.nodeID2id[age.nodeID], "position", a.activeSelection.Len()-icur)
	}
	require.Equal(t, nok, len(order))
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
	ch.Add(block)
	return block
}

// Add adds a block
func (ch *chain) Add(block *types.Block) {
	ch.blocks = append(ch.blocks, block)
	ch.db[block.Header().Hash()] = len(ch.blocks) - 1
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
		net.keys[0], dummySeed, dummyProof,
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
	seed, proof []byte, identities ...Hash) *GenesisExtraData {

	initIdents, err := IdentInit(key, nil, identities...)
	require.NoError(t, err)

	extra := &GenesisExtraData{}
	err = extra.ChainInit.Populate(key, initIdents, seed, proof)
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
