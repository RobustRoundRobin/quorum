package rororo

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

// This will become 'Algorithm 5 VerifyBranch' and related machinery, but its
// not there yet.

func (e *engine) verifyBranchHeaders(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// If we want to filter blocks based on the assumption of "loosely
	// synchronised node time", this is where we should do it. (Before doing
	// any other more intensive validation)

	var err error
	var se *SignedExtraData
	if se, err = e.verifyHeader(chain, header); err != nil {
		return err
	}

	// XXX: TODO just verify one deep for now
	number := header.Number.Uint64()
	// The genesis block is the always valid dead-end
	if number == 0 {
		return nil
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

	parentSE, _ /*sealerID*/, _ /*sealerPub*/, err := e.decodeHeaderSeal(header)
	if err != nil {
		return err
	}

	// XXX: until we sort out the round synchronisation, this can't be enabled.
	// Also, currently, we get asked to verify local mining work on endorsers,
	// so the block number for the local (never to be commited) work will be
	// equal to the block number from the leader
	if parentSE.Intent.RoundNumber.Cmp(se.Intent.RoundNumber) >= 0 {
		e.logger.Info("RoRoRo new block round number lower than current parent", "parent", parentSE.Intent.RoundNumber, "new", se.Intent.RoundNumber)
		// return fmt.Errorf("rororo round number to young: %v > %v", parentSE.Intent.RoundNumber, se.Intent.RoundNumber)
	}

	return nil
}

func (e *engine) verifyHeader(chain consensus.ChainReader, header *types.Header) (*SignedExtraData, error) {

	// Check the seal (extraData) format is correct and signed
	se, sealerID, _ /*sealerPub*/, err := e.decodeHeaderSeal(header)
	if err != nil {
		return nil, err
	}
	// Check that the intent in the seal matches the block described by the
	// header
	if se.Intent.ChainID != e.genesisEx.ChainID {
		// XXX: ARSE this is because the engine doesn't get the genesis until
		// start is called, but verifyHeader is used by block
		// synchronisation, and mining isn't started until sync is complete.
		e.logger.Error("RoRoRo temprorily disabling Chain ID check. I have messed up the genesisEx.ChainID")
		// return se, fmt.Errorf(
		//	"rororo sealed intent invalid chainid: %s != genesis: %s", se.Intent.ChainID.Hex(), e.genesisEx.ChainID.Hex())
	}

	// Ensure that the coinbase is valid
	if header.Nonce != emptyNonce {
		return se, fmt.Errorf("rororo nonce must be empty")
	}

	// mix digest - we don't assert anything about that

	// sealingNodeAddr := common.Address(sealerID.Address())

	// Check that the NodeID in the intent matches the sealer
	if sealerID != se.Intent.NodeID {
		return se, fmt.Errorf("rororo sealer node id mismatch: sealer=`%s' node=`%s'",
			hex.EncodeToString(sealerID[:]), hex.EncodeToString(se.Intent.NodeID[:]))
	}

	// Check that the sealed parent hash from the intent matches the parent
	// hash on the header.
	if common.Hash(se.Intent.ParentHash) != header.ParentHash {
		return se, fmt.Errorf("rororo parent mismatch: sealed=`%s' header=`%s'",
			hex.EncodeToString(se.Intent.ParentHash[:]),
			hex.EncodeToString(header.ParentHash[:]))
	}

	// Check that the sealed tx root from the intent matches the tx root in the
	// header.
	if common.Hash(se.Intent.TxHash) != header.TxHash {
		return se, fmt.Errorf("rororo txhash mismatch: sealed=`%s' header=`%s'",
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
			e.logger.Error("RoRoRo temprorily disabling Chain ID check. I have messed up the genesisEx.ChainID")
			// return se, fmt.Errorf("rororo endorsment chainid invalid: `%s'",
			// 	hex.EncodeToString(end.IntentHash[:]))
		}

		// Check that the intent hash signed by the endorser matches the intent
		// sealed in the block header by the leader
		if end.IntentHash != intentHash {
			return se, fmt.Errorf("rororo endorsment intent hash mismatch: sealed=`%s' endorsed=`%s'",
				intentHash.Hex(), end.IntentHash.Hex())
		}
	}
	return se, nil
}

func (e *engine) decodeHeaderSeal(header *types.Header) (*SignedExtraData, Hash, []byte, error) {

	var err error
	var pub []byte
	var sealerID Hash

	if len(header.Extra) < RoRoRoExtraVanity {
		return nil, Hash{}, nil, fmt.Errorf("RoRoRo missing extra data on block header")
	}
	seal := header.Extra[RoRoRoExtraVanity:]

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
