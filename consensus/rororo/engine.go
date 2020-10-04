package rororo

import (
	"crypto/ecdsa"
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
)

var (
	// Uncles not relevant outside of PoW
	errInvalidUncleHash = errors.New("non empty uncle hash")
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
}

// New create rororo consensus engine
func New(config *Config, privateKey *ecdsa.PrivateKey, db ethdb.Database) consensus.RoRoRo {
	return &engine{
		config:     config,
		privateKey: privateKey,
		address:    crypto.PubkeyToAddress(privateKey.PublicKey),
		logger:     log.New(),
		db:         db,
	}
}

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *engine) Author(header *types.Header) (common.Address, error) {
	return common.Address{}, ErrNotImplemented
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *engine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return ErrNotImplemented
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (e *engine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	return nil, nil
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of a given engine.
func (e *engine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errInvalidUncleHash
	}
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (e *engine) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return ErrNotImplemented
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (e *engine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	return ErrNotImplemented
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// but does not assemble the block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *engine) Finalize(
	chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
}

// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
// rewards) and assembles the final block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *engine) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	return nil, ErrNotImplemented
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (e *engine) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return ErrNotImplemented
}

// SealHash returns the hash of a block prior to it being sealed.
func (e *engine) SealHash(header *types.Header) common.Hash {
	return common.Hash{}
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
func (e *engine) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return nil
}

// APIs returns the RPC APIs this consensus engine provides.
func (e *engine) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "rororo",
		Version:   "1.0",
		Service:   &API{chain: chain, rororo: e},
		Public:    true,
	}}
}

// Protocol returns the protocol for this consensus
func (e *engine) Protocol() consensus.Protocol {
	return consensus.RoRoRoProtocol
}

// Close terminates any background threads maintained by the consensus engine.
func (e *engine) Close() error {
	return ErrNotImplemented
}
