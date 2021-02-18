package rrr

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// Implements Robust Round Robin consensus
// https://arxiv.org/abs/1804.07391
var (
	ErrNotImplemented = errors.New("not implemented")
)

// Protocol no implementations found ?
// Broadcaster implemented only by eth/handler.go
// Peer implemented by eth/peer.go

// Config holds the RRR consensus configuration.
type Config struct {
	ConfirmPhase uint64 `toml:",omitempty"` // Duration of the confirmation phase in milliseconds (must be < round)
	RoundLength  uint64 `toml:",omitempty"` // Duration of each round in milliseconds

	Candidates        uint64 `toml:",omitempty"` // Number of leader candidates (Nc) to propose from the oldest identities on each round
	Endorsers         uint64 `toml:",omitempty"` // Number of endorsers (Ne) to select from the most recently active identities
	Quorum            uint64 `toml:",omitempty"` // Number of endorsments required to confirm an intent
	Activity          uint64 `toml:",omitempty"` // Activity threshold (Ta) (in blocks). Any identity with confirmation messages recorded within this many rounds of the head are considered active.
	StablePrefixDepth uint64 `toml:"omitempty"`  // d stable block prefix (for seed r-d)
}

// DefaultConfig provides the default rrr consensus configuration
var DefaultConfig = &Config{
	ConfirmPhase:      5000,
	RoundLength:       6000,
	Candidates:        5,
	Endorsers:         100,
	Quorum:            54,
	Activity:          200,
	StablePrefixDepth: 12,
}

// API is a user facing RPC API to dump Istanbul state
type API struct {
	chain RRRChainReader
	e     *engine
}

// APIs returns the RPC APIs this consensus engine provides.
func (e *engine) APIs(reader consensus.ChainReader) []rpc.API {

	chain, ok := reader.(RRRChainReader)
	if !ok {
		e.logger.Warn("RRR APIs incompatible chain reader", "err", errIncompatibleChainReader)
		return []rpc.API{}
	}

	return []rpc.API{{
		Namespace: "rrr",
		Version:   "1.0",
		Service:   &API{chain: chain, e: e},
		Public:    true,
	}}
}

// Seeding returns true when rrr consensus has not established the random seed
// for the first round. Until the seeding has completed, transactions will not
// be mined. After the first round, we use VRF's
func (api *API) Seeding() bool {
	return false
}

// QueueEnrolment queues up an enrolment for the supplied enrolment.
func (api *API) QueueEnrolment(nodeID common.Hash) error {

	api.e.logger.Info("RRR EnrolIdentity", "nodeID", nodeID.Hex())

	posted := api.e.postIfRunning(&engEnrolIdentity{NodeID: nodeID, ReEnrol: true})
	if !posted {
		return errEngineStopped
	}

	return nil
}

// NOTICE: To extend this api you must also update RRR_JS in go-ethereum/internal/web3ext/web3ext.go

// IsEnrolmentPending returns true if enrolment of the provided node id is
// pending.
func (api *API) IsEnrolmentPending(nodeID common.Hash) bool {
	return api.e.r.IsEnrolmentPending(nodeID)
}

// ChainID returns the identity of the chain
func (api *API) ChainID() common.Hash {
	// XXX: TODO read guards
	return common.Hash(api.e.r.genesisEx.ChainID)
}

// NodeID returns the node id
func (api *API) NodeID() common.Hash {
	// XXX: TODO read guards
	return common.Hash(api.e.r.nodeID)
}

// NodePublic returns the node public key
func (api *API) NodePublic() string {
	// XXX: TODO read guards
	return hex.EncodeToString(elliptic.Marshal(
		crypto.S256(),
		api.e.r.privateKey.PublicKey.X, api.e.r.privateKey.PublicKey.Y,
	))
}

// NodeAddress returns the nodes address
func (api *API) NodeAddress() common.Address {
	// XXX: TODO read guards
	return common.Address(api.e.r.nodeAddr)
}
