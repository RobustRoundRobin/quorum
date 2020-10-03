package rororo

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
)

// Broadcaster defines the interface to enqueue blocks to fetcher and find peer
type Broadcaster struct{}

// Enqueue add a block into fetcher queue
func (b *Broadcaster) Enqueue(id string, block *types.Block) {}

// FindPeers retrives peers by addresses
func (b *Broadcaster) FindPeers(map[common.Address]bool) map[common.Address]consensus.Peer {
	return nil
}

// Handler implements consensus.Handler interface to handle and send peer's message
type Handler struct{}

// NewChainHead handles a new head block comes
func (h *Handler) NewChainHead() error { return ErrNotImplemented }

// HandleMsg handles a message from peer
func (h *Handler) HandleMsg(address common.Address, data p2p.Msg) (bool, error) {
	return false, ErrNotImplemented
}

// SetBroadcaster sets the broadcaster to send message to peers
func (h *Handler) SetBroadcaster(consensus.Broadcaster) {}
