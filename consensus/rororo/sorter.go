package rororo

import "bytes"

// The paper specifies sorting enrolment candidates by public key, the address
// is more convenient and effectively the same result.
type Addresses []Address

func (s Addresses) Len() int      { return len(s) }
func (s Addresses) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type ByAddress struct{ Addresses }

func (s ByAddress) Less(i, j int) bool {
	return bytes.Compare(s.Addresses[i][:], s.Addresses[j][:]) < 0
}
