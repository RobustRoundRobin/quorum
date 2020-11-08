package rororo

import (
	"errors"
)

// Implements Robust Round Robin consensus
// https://arxiv.org/abs/1804.07391
var (
	ErrNotImplemented = errors.New("not implemented")
)

// Protocol no implementations found ?
// Broadcaster implemented only by eth/handler.go
// Peer implemented by eth/peer.go

// Config holds the RoRoRo consensus configuration.
type Config struct {
	ConfirmTimeout uint64 `toml:",omitempty"` // Duration of the confirmation phase in milliseconds (must be < round)
	RoundLength    uint64 `toml:",omitempty"` // Duration of each round in milliseconds

	Candidates      uint64 `toml:",omitempty"` // Number of leader candidates (Nc) to propose from the oldest identities on each round
	Endorsers       uint64 `toml:",omitempty"` // Number of endorsers (Ne) to select from the most recently active identities
	EndorsersQuorum uint64 `toml:",omitempty"` // Number of endorsments required to confirm an intent
	Activity        uint64 `toml:",omitempty"` // Activity threshold (Ta). Any identity with confirmation messages recorded within this many rounds of the head are considered active.
}

// DefaultConfig provides the default rororo consensus configuration
var DefaultConfig = &Config{
	ConfirmTimeout:  5000,
	RoundLength:     6000,
	Candidates:      5,
	Endorsers:       100,
	EndorsersQuorum: 54,
	Activity:        20000,
}
