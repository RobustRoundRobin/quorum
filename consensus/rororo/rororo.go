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
type Config struct {
	Candidates uint64 `toml:",omitempty"` // Number of leader candidates (Nc) to propose from the oldest identities on each round
	Endorsers  uint64 `toml:",omitempty"` // Number of endorsers (Ne) to select from the most recently active identities
	Activity   uint64 `toml:",omitempty"` // Activity threshold (Ta). Any identity with confirmation messages recorded within this many rounds of the head are considered active.
}

var DefaultConfig = &Config{
	Candidates: 5,
	Endorsers:  100,
	Activity:   20000,
}
