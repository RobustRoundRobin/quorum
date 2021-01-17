package rrr

import (
	"bytes"

	"github.com/ethereum/go-ethereum/rlp"
)

// NewBytesStream makes an rlp.Stream
func NewBytesStream(b []byte) *rlp.Stream {
	r := bytes.NewReader(b)
	s := rlp.NewStream(r, uint64(len(b)))
	return s
}
