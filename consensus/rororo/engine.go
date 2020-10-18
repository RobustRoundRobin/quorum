package rororo

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
)

var (
	// Uncles not relevant outside of PoW
	errInvalidUncleHash = errors.New("non empty uncle hash")
)

const (
	NewBlockMsg = 0x07
	rororoMsg   = 0x11

	// TODO: probably want this to be driven by Nc, Ne configuration
	lruPeers    = 100 + 6*2
	lruMessages = 1024
)

// API is a user facing RPC API to dump Istanbul state
type API struct {
	chain  consensus.ChainReader
	rororo *engine
}

// engine implements consensus.Engine using Robust Round Robin consensus
// https://arxiv.org/abs/1804.07391
type engine struct {
	config     *Config
	privateKey *ecdsa.PrivateKey
	address    common.Address
	logger     log.Logger
	db         ethdb.Database

	broadcaster consensus.Broadcaster

	// Track which messages we have sent or received. We do not re-gossip
	// these. (IBFT calls these 'recentMessages'). We maintain a 2 level arc
	// here, for each of lruPeers we have an lru of recentley gossiped
	// messages.
	peerMessages *lru.ARCCache

	// Track which messages we have posted on our local processing queue. We do
	// not re-broadcast these. We do not re post these locally.
	selfMessages *lru.ARCCache
}

// New create rororo consensus engine
func New(config *Config, privateKey *ecdsa.PrivateKey, db ethdb.Database) consensus.RoRoRo {

	logger := log.New()
	// Only get err from NewRC if zize requested is <=0
	peerMessages, _ := lru.NewARC(lruPeers)
	selfMessages, _ := lru.NewARC(lruMessages)
	return &engine{
		config:       config,
		privateKey:   privateKey,
		address:      crypto.PubkeyToAddress(privateKey.PublicKey),
		logger:       logger,
		db:           db,
		peerMessages: peerMessages,
		selfMessages: selfMessages,
	}
}

// Gossip the message to the provided peers, skipping self.
func (e *engine) Gossip(self common.Address, peers map[common.Address]consensus.Peer, msg []byte) error {

	// XXX: todo the IBFT implementation rlp encoded msg before taking the
	// hash. Unless it was required to cannonicalise the bytes, I can't see any
	// reason for that. Lets find out ...
	hash := Keccak256(msg)

	for peerAddr, peer := range peers {

		if peerAddr == self {
			e.logger.Info("skipping self")
			continue
		}

		var msgs *lru.ARCCache
		if i, ok := e.peerMessages.Get(peerAddr); ok {
			msgs, _ = i.(*lru.ARCCache)
			if _, k := msgs.Get(hash); k {
				// have already sent the message to, or received it from, this peer
				continue
			}
		} else {
			msgs, _ = lru.NewARC(lruMessages)
		}
		msgs.Add(hash, true)
		e.peerMessages.Add(peerAddr, msgs)
		go peer.Send(rororoMsg, msg)
	}
	return nil
}

// SetBroadcaster implements consensus.Handler.SetBroadcaster
// Which, for the quorum fork, is called by eth/handler.go NewProtocolManager
func (e *engine) SetBroadcaster(broadcaster consensus.Broadcaster) {
	e.broadcaster = broadcaster
}

func (e *engine) Start(
	chain consensus.ChainReader, currentBlock func() *types.Block, hasBadBlock func(hash common.Hash) bool) error {
	e.logger.Info("RoRoRo Start")

	h := chain.CurrentHeader()
	e.logger.Info("genesis block", "extra", hex.EncodeToString(h.Extra))

	return nil
}
func (e *engine) Stop() error {
	return nil
}

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *engine) Author(header *types.Header) (common.Address, error) {
	e.logger.Info("RoRoRo Author")
	return common.Address{}, ErrNotImplemented
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *engine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	e.logger.Info("RoRoRo VerifyHeader")
	return ErrNotImplemented
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (e *engine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	e.logger.Info("RoRoRo VerifyHeaders")
	return nil, nil
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of a given engine.
func (e *engine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	e.logger.Info("RoRoRo VerifyUncles")
	if len(block.Uncles()) > 0 {
		return errInvalidUncleHash
	}
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (e *engine) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	e.logger.Info("RoRoRo VerifySeal")
	return ErrNotImplemented
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (e *engine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	e.logger.Info("RoRoRo Prepare")
	return nil
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// but does not assemble the block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *engine) Finalize(
	chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	e.logger.Info("RoRoRo Finalize")
}

// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
// rewards) and assembles the final block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *engine) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	e.logger.Info("RoRoRo FinalizeAndAssemble")
	return nil, ErrNotImplemented
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (e *engine) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	e.logger.Info("RoRoRo Seal")
	return ErrNotImplemented
}

// SealHash returns the hash of a block prior to it being sealed.
func (e *engine) SealHash(header *types.Header) common.Hash {
	e.logger.Info("RoRoRo SealHash")
	return common.Hash{}
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
func (e *engine) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	e.logger.Info("RoRoRo CalcDifficulty")
	return nil
}

// APIs returns the RPC APIs this consensus engine provides.
func (e *engine) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{}
	// return []rpc.API{{
	// 	Namespace: "rororo",
	// 	Version:   "1.0",
	// 	Service:   &API{chain: chain, rororo: e},
	// 	Public:    true,
	// }}
}

// Protocol returns the protocol for this consensus
func (e *engine) Protocol() consensus.Protocol {
	return consensus.RoRoRoProtocol
}

// Close terminates any background threads maintained by the consensus engine.
func (e *engine) Close() error {
	e.logger.Info("RoRoRo Close")
	return ErrNotImplemented
}
