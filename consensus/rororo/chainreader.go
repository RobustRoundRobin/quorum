package rororo

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// ChainReader implements the go-ethereum/consensus.ChainReader interface
// Note: may not need this, current implementations are: core/blockchain.go and
// core/headerchain.go
type ChainReader struct{}

// Config retrieves the blockchain's chain configuration.
func (r *ChainReader) Config() *params.ChainConfig {
	return nil
}

// CurrentHeader retrieves the current header from the local chain.
func (r *ChainReader) CurrentHeader() *types.Header {
	return nil
}

// GetHeader retrieves a block header from the database by hash and number.
func (r *ChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	return nil
}

// GetHeaderByNumber retrieves a block header from the database by number.
func (r *ChainReader) GetHeaderByNumber(number uint64) *types.Header {
	return nil
}

// GetHeaderByHash retrieves a block header from the database by its hash.
func (r *ChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	return nil
}

// GetBlock retrieves a block from the database by hash and number.
func (r *ChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	return nil
}
