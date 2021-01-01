package rrr

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	errDecodingGenesisExtra = errors.New("failed to decode extra field from genesis block")
)

// This will become 'Algorithm 5 VerifyBranch' and related machinery, but its
// not there yet.

func (e *engine) verifyBranchHeaders(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// If we want to filter blocks based on the assumption of "loosely
	// synchronised node time", this is where we should do it. (Before doing
	// any other more intensive validation)

	var err error

	number := header.Number.Uint64()

	// The genesis block is the always valid dead-end. However, geth calls
	// VerifyBranchHeaders as it warms up before looking at any other blocks.
	// This is the only opportunity to collect the genesis extra data on nodes
	// that have to sync before they can participate.

	if number == 0 {

		h0 := Hash{}
		if e.genesisEx.ChainID == h0 {
			e.logger.Info("RRR VerifyBranchHeaders - genesis block", "extra", hex.EncodeToString(header.Extra))
			err := rlp.DecodeBytes(header.Extra, &e.genesisEx)
			if err != nil {
				return err
			}
		}

		return nil
	}

	// XXX: TODO just verify one deep for now
	if _, err = e.verifyHeader(chain, header); err != nil {
		return err
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	return nil
}

func (e *engine) verifyHeader(chain consensus.ChainReader, header *types.Header) (*SignedExtraData, error) {

	if header.Number.Cmp(big0) == 0 {
		return nil, fmt.Errorf("RRR the genesis header cannot be verified by this method")
	}

	// Check the seal (extraData) format is correct and signed
	se, sealerID, _ /*sealerPub*/, err := e.decodeHeaderSeal(header)
	if err != nil {
		return nil, err
	}
	// Check that the intent in the seal matches the block described by the
	// header
	if se.Intent.ChainID != e.genesisEx.ChainID {
		return se, fmt.Errorf(
			"rrr sealed intent invalid chainid: %s != genesis: %s", se.Intent.ChainID.Hex(), e.genesisEx.ChainID.Hex())
	}

	// Check that the round in the intent matches the block number
	if se.Intent.RoundNumber.Cmp(header.Number) != 0 {
		return se, fmt.Errorf(
			"rrr sealed intent invalid intent round number: %s != block number: %s",
			se.Intent.RoundNumber, header.Number)
	}

	// Ensure that the coinbase is valid
	if header.Nonce != emptyNonce {
		return se, fmt.Errorf("rrr nonce must be empty")
	}

	// mix digest - we don't assert anything about that

	// sealingNodeAddr := common.Address(sealerID.Address())

	// Check that the NodeID in the intent matches the sealer
	if sealerID != se.Intent.NodeID {
		return se, fmt.Errorf("rrr sealer node id mismatch: sealer=`%s' node=`%s'",
			sealerID.Hex(), se.Intent.NodeID.Hex())
	}

	// Check that the sealed parent hash from the intent matches the parent
	// hash on the header.
	if common.Hash(se.Intent.ParentHash) != header.ParentHash {
		return se, fmt.Errorf("rrr parent mismatch: sealed=`%s' header=`%s'",
			hex.EncodeToString(se.Intent.ParentHash[:]),
			hex.EncodeToString(header.ParentHash[:]))
	}

	// Check that the sealed tx root from the intent matches the tx root in the
	// header.
	if common.Hash(se.Intent.TxHash) != header.TxHash {
		return se, fmt.Errorf("rrr txhash mismatch: sealed=`%s' header=`%s'",
			hex.EncodeToString(se.Intent.TxHash[:]),
			hex.EncodeToString(header.TxHash[:]))
	}

	// Check all the endorsements. First check the intrinsic validity

	intentHash, err := se.Intent.Hash()
	if err != nil {
		return se, err
	}

	for _, end := range se.Confirm {
		// Check the endorsers ChainID
		if end.ChainID != e.genesisEx.ChainID {
			return se, fmt.Errorf("rrr endorsment chainid invalid: `%s'", end.IntentHash.Hex())
		}

		// Check that the intent hash signed by the endorser matches the intent
		// sealed in the block header by the leader
		if end.IntentHash != intentHash {
			return se, fmt.Errorf("rrr endorsment intent hash mismatch: sealed=`%s' endorsed=`%s'",
				intentHash.Hex(), end.IntentHash.Hex())
		}
	}
	return se, nil
}

func (e *engine) decodeActivity(header *types.Header) ([]Endorsement, []Enrolment, Hash, []byte, error) {

	// Common and fast path first
	if header.Number.Cmp(big0) > 0 {
		se, sealerID, pub, err := e.decodeHeaderSeal(header)
		if err != nil {
			return nil, nil, Hash{}, nil, err
		}
		return se.ExtraData.Confirm, se.ExtraData.Enrol, sealerID, pub, nil
	}

	// Genesis block needs special handling, don't short circuit to e.genesisEx
	// incase we are called in surprising contexts.

	ge := &GenesisExtraData{}
	err := rlp.DecodeBytes(header.Extra, ge)
	if err != nil {
		return nil, nil, Hash{}, nil, fmt.Errorf("%v: %w", err, errDecodingGenesisExtra)
	}

	// But do require consistency, if it has been previously decoded
	h0 := Hash{}
	if e.genesisEx.ChainID != h0 && e.genesisEx.ChainID != ge.ChainID {
		return nil, nil, Hash{}, nil, fmt.Errorf(
			"genesis header with incorrect chainID: %w", errDecodingGenesisExtra)
	}

	// Get the genesis signer public key and node id. Do this derivation of
	// node id and public key unconditionally regardless of wheter we think we
	// have the information to hand - it is just safer that way.
	genPub, err := Ecrecover(ge.IdentInit[0].U[:], ge.IdentInit[0].Q[:])
	if err != nil {
		return nil, nil, Hash{}, nil, fmt.Errorf("%v:%w", err, errGensisIdentitiesInvalid)
	}

	genID := Hash{}
	copy(genID[:], Keccak256(genPub[1:65]))

	return []Endorsement{}, ge.IdentInit, genID, genPub, nil
}

func (e *engine) decodeHeaderSeal(header *types.Header) (*SignedExtraData, Hash, []byte, error) {

	var err error
	var pub []byte
	var sealerID Hash

	if header.Number.Cmp(big0) == 0 {
		return nil, Hash{}, nil, fmt.Errorf("the genesis block is not compatible with decodeHeaderSeal")
	}

	if len(header.Extra) < RRRExtraVanity {
		return nil, Hash{}, nil, fmt.Errorf("RRR missing extra data on block header")
	}
	seal := header.Extra[RRRExtraVanity:]

	se := &SignedExtraData{}

	if pub, err = se.DecodeSigned(NewBytesStream(seal)); err != nil {
		return nil, Hash{}, nil, err
	}
	sealerID, err = PubBytes2NodeID(pub)
	if err != nil {
		return nil, Hash{}, nil, err
	}

	return se, sealerID, pub, nil
}
