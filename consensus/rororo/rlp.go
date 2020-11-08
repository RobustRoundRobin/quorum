package rororo

import (
	"bytes"

	"github.com/ethereum/go-ethereum/rlp"
)

func NewBytesStream(b []byte) *rlp.Stream {
	r := bytes.NewReader(b)
	s := rlp.NewStream(r, uint64(len(b)))
	return s
}
