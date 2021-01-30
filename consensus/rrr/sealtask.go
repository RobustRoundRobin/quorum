package rrr

// This file deals with most leadership aspects of RoundState. Tracking the seal
// task from the miner, soliciting endorsements for it, and ultimately sealing
// the block.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	errSealSeedFailed = errors.New("failed to generate a seed for the next block")
)

// engSealTask is sent to the engines runningCh to request endorsment to
// create a block. This is initiated by the local miner invoking Seal interface
// method.  If the local node is a leader candidate in the current round this
// will result in an Intent being broadcast. Otherwise it will be ignored by
// the engine. The miner will clear un-answered Seal requests when it sees a
// new chain head.
type engSealTask struct {
	// RoundNumber the Seal was requested.
	RoundNumber *big.Int
	Block       *types.Block
	Results     chan<- *types.Block
	Stop        <-chan struct{}
}

func (en *engSealTask) Canceled() bool {
	select {
	case <-en.Stop:
		return true
	default:
		return false
	}
}

type pendingIntent struct {
	Candidate    bool
	SI           *SignedIntent
	SealHash     Hash
	RMsg         RMsg
	Msg          []byte
	Endorsements []*SignedEndorsement
	// Endorsers selected when the intent was issued. This map is not updated
	// after it is first created
	Endorsers map[common.Address]bool
}

// NewSealTask delivers work from the node to be mined. If we are the leader,
// and we are in the intent phase we immediately broadcast our intent. If not,
// we hang on to it until we are or we receive the next one.
func (r *RoundState) NewSealTask(e *engine, et *engSealTask) {

	e.logger.Trace("RRR engSealTask",
		"state", r.State.String(), "addr", r.nodeAddr.Hex(),
		"r", r.Number, "f", r.FailedAttempts)

	et.RoundNumber = big.NewInt(0).Set(r.Number)

	// Note: we don't reset the attempt if we get a new seal task.
	if err := r.newSealTask(r.State, et, r.Number, r.FailedAttempts); err != nil {
		e.logger.Info("RRR engSealTask - newSealTask", "err", err)
	}

	if r.State == RRRStateLeaderCandidate && r.Phase == RoundPhaseIntent {

		e.logger.Trace(
			"RRR engSealTask - broadcasting intent (new)", "addr", e.r.nodeAddr.Hex(),
			"r", r.Number, "f", r.FailedAttempts)

		r.broadcastCurrentIntent(e)
	}
}

func (r *RoundState) newSealTask(
	state RRRState, et *engSealTask, roundNumber *big.Int, failedAttempts uint,
) error {
	var err error
	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	var newIntent *pendingIntent
	if newIntent, err = r.newPendingIntent(et, roundNumber, failedAttempts); err != nil {
		return err
	}

	r.intent = newIntent
	r.sealTask = et
	return nil
}

// refreshSealTask will update the current intent to use the provided
// roundNumber and failedAttempts. The effects are imediate, if we have already
// issued an intent for this round and we are still in the intent phase, we just
// issue another. Endorsing peers will endorse the *most recent* intent from the
// *oldest* identity they have selected as leader.
func (r *RoundState) refreshSealTask(roundNumber *big.Int, failedAttempts uint) error {

	var err error
	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	// Establish which, if any, currently known task can be refreshed.

	// Reconcile whether to re-issue current seal task
	if r.sealTask == nil || r.sealTask.Canceled() {
		r.intent = nil
		r.sealTask = nil
		r.logger.Trace("RRR refreshSealTask - no task")
		return nil
	}

	// The roundNumber or failedAttempts has to change in order for the message
	// to be broadcast.
	newIntent, err := r.newPendingIntent(r.sealTask, roundNumber, failedAttempts)
	if err != nil {
		return fmt.Errorf("refreshSealTask - newPendingIntent: %v", err)
	}

	// There is no need to send nil to Results on the previous task, the geth
	// miner worker can't do anything with that information
	r.intent = newIntent

	return nil
}

func (r *RoundState) newPendingIntent(
	et *engSealTask, roundNumber *big.Int, failedAttempts uint) (*pendingIntent, error) {

	var err error

	r.logger.Trace("RRR newPendingIntent",
		"#tx", len(et.Block.Transactions()),
		"tx#", et.Block.TxHash().Hex(),
		"parent#", et.Block.ParentHash().Hex(),
	)
	pe := &pendingIntent{
		RMsg: RMsg{Code: RMsgIntent},
	}

	pe.SealHash = Hash(sealHash(et.Block.Header()))

	// The intent that will need to be confirmed by 'q' endorsers in order for
	// this node to mine this block
	pe.SI = &SignedIntent{
		Intent: Intent{
			ChainID:        r.genesisEx.ChainID,
			NodeID:         r.nodeID,
			RoundNumber:    big.NewInt(0).Set(roundNumber),
			FailedAttempts: failedAttempts,
			ParentHash:     Hash(et.Block.ParentHash()),
			TxHash:         Hash(et.Block.TxHash()), // the hash is computed by NewBlock
		},
	}
	pe.RMsg.Raw, err = pe.SI.SignedEncode(r.privateKey)
	if err != nil {
		return nil, err
	}

	if pe.Msg, err = rlp.EncodeToBytes(pe.RMsg); err != nil {
		return nil, err
	}

	pe.Endorsements = make([]*SignedEndorsement, 0, r.config.Quorum)
	pe.Endorsers = make(map[common.Address]bool)

	return pe, nil
}

// NewSignedEndorsement keeps track of endorsments received from peers. At the
// end of the confirmation phase, in PhaseTick, if we are a leader and our
// *current* intent has sufficient endorsments, we seal the block. This causes
// geth to broad cast it to the network.
func (r *RoundState) NewSignedEndorsement(et *engSignedEndorsement) {
	// leader <- endorsment from committee
	if r.State == RRRStateNodeStarting {
		r.logger.Trace("RRR engSignedEndorsement - node starting, ignoring", "end", et.EndorserID.Hex())
		return
	}

	if r.State != RRRStateLeaderCandidate {
		// This is un-expected. Likely late, or possibly from
		// broken node
		r.logger.Trace("RRR non-leader ignoring engSignedEndorsement", "round", r.Number)
		return
	}

	// XXX: divergence (3) the paper handles endorsements only in the
	// confirmation phase. It is important that all identities get an
	// opportunity to record activity. I think the key point is that a quorum of
	// fast nodes can't starve 'slow' nodes. So as long as the window is
	// consistent for all, it doesn't really matter what it is. And it is (a
	// little) easier to just accept endorsements at any time in the round.

	r.logger.Trace("RRR engSignedEndorsement",
		"round", r.Number,
		"endorser", et.EndorserID.Hex(), "intent", et.IntentHash.Hex())

	// Provided the endorsment is for our outstanding intent and from an
	// identity we have selected as an endorser in this round, then its
	// endorsment will be included in the block - whether we needed it to reach
	// the endorsment quorum or not.
	if err := r.handleEndorsement(et); err != nil {
		r.logger.Info("RRR run handleIntent", "err", err)
	}
}

func (r *RoundState) handleEndorsement(et *engSignedEndorsement) error {

	if et.Endorsement.ChainID != r.genesisEx.ChainID {
		return fmt.Errorf(
			"confirmation received for wrong chainid: %s",
			hex.EncodeToString(et.Endorsement.ChainID[:]))
	}

	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	if r.intent == nil {
		r.logger.Debug(
			"RRR confirmation stale or un-solicited, no current intent",
			"endid", et.Endorsement.EndorserID.Hex(), "hintent",
			et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	pendingIntentHash, err := r.intent.SI.Hash()
	if err != nil {
		return err
	}

	if pendingIntentHash != et.SignedEndorsement.IntentHash {
		r.logger.Debug("RRR confirmation for stale or unknown intent",
			"pending", pendingIntentHash.Hex(),
			"received", et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	// Check the confirmation came from an endorser selected by this node for
	// the current round
	endorserAddr := common.Address(et.SignedEndorsement.EndorserID.Address())
	if !r.endorsers[endorserAddr] {
		r.logger.Debug(
			"RRR confirmation from unexpected endorser", "endorser",
			et.Endorsement.EndorserID[:])
		return nil
	}

	// Check the confirmation is not from an endorser that has endorsed our
	// intent already this round.
	if r.intent.Endorsers[endorserAddr] {
		r.logger.Trace(
			"RRR redundant confirmation from endorser", "endorser",
			et.Endorsement.EndorserID[:])
		return nil
	}

	// Note: *not* copying, engine run owns everything that is passed to it on
	// the runningCh
	r.intent.Endorsements = append(r.intent.Endorsements, &et.SignedEndorsement)
	r.intent.Endorsers[endorserAddr] = true

	if uint64(len(r.intent.Endorsements)) >= r.config.Quorum {
		r.logger.Trace("RRR confirmation redundant, have quorum",
			"endid", et.Endorsement.EndorserID.Hex(),
			"end#", et.SignedEndorsement.IntentHash.Hex(),
			"hintent", et.SignedEndorsement.IntentHash.Hex())
	}

	return nil
}

// sealCurrentBlock completes the current block sealing task if the node
// has received the confirmations required to mine a block. If this function
// returns true, RRR has entered the "block disemination" phase. Which, in this
// implementation, simply means we have handed that job on to the general miner
// arrangements in geth (and its eth/devp2p machinery). Note that this is
// called on all nodes, only legitemate leader candidates will recieve enough
// endorsments for non-byzantine scenarios.
func (r *RoundState) sealCurrentBlock(chain RRRChainReader) (bool, error) {

	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	if r.intent == nil {
		r.logger.Debug("RRR no outstanding intent")
		return false, nil
	}

	if len(r.intent.Endorsements) == 0 {
		r.logger.Debug("RRR no endorsments received")
		return false, nil
	}

	if len(r.intent.Endorsements) < int(r.config.Quorum) {
		got := len(r.intent.Endorsements)
		r.logger.Info("RRR insufficient endorsers to become leader",
			"q", int(r.config.Quorum), "got", got)
		return false, nil
	}

	intentHash, err := r.intent.SI.Hash()
	if err != nil {
		return false, err
	}

	// Now check all the endorsments are for the intent
	for _, end := range r.intent.Endorsements {
		if intentHash != end.IntentHash {
			return false, fmt.Errorf(
				"endorsement intenthash mismatch. endid=%s", end.EndorserID.Hex())
		}
	}

	r.logger.Info("RRR confirmed as leader",
		"q", int(r.config.Quorum), "got", len(r.intent.Endorsements))

	if r.sealTask == nil {
		r.logger.Trace("RRR seal task canceled or discarded")
		return false, nil
	}

	if r.sealTask.Canceled() {
		r.logger.Trace("RRR seal task canceled")
		return false, nil
	}

	// Complete the seal, block will be rejected if this is wrong, no need to
	// double up on checks here.
	header := r.sealTask.Block.Header()

	// Work out the stable seed. We want to take this from a block that we are
	// probabalistically very confident is part of the canonical chain. 'd'
	// rounds before the current. Here we deal with the early blocks where d >
	// block height.
	alpha := r.genesisEx.ChainInit.Seed

	blockNumber := r.Number.Uint64()
	if r.config.StablePrefixDepth < blockNumber {

		stableHeader := chain.GetHeaderByNumber(blockNumber - r.config.StablePrefixDepth)
		se, _, _, err := decodeHeaderSeal(stableHeader)
		if err != nil {
			return false, fmt.Errorf("failed decoding stable header seal: %v", err)
		}
		alpha = se.Seed
	}

	beta, pi, err := r.vrf.Prove(r.privateKey, alpha)
	if err != nil {
		return false, fmt.Errorf("failed proving new seed: %v", err)
	}

	data := &SignedExtraData{
		ExtraData: ExtraData{
			SealTime: uint64(time.Now().Unix()),
			Intent:   r.intent.SI.Intent,
			Confirm:  make([]Endorsement, len(r.intent.Endorsements)),
			Seed:     beta,
			Proof:    pi,
		},
	}

	for i, c := range r.intent.Endorsements {
		data.Confirm[i] = c.Endorsement
	}

	seal, err := data.SignedEncode(r.privateKey)
	if err != nil {
		return false, err
	}

	header.Extra = append(header.Extra[:RRRExtraVanity], []byte(seal)...)

	block := r.sealTask.Block.WithSeal(header)
	r.sealTask.Results <- block
	r.logger.Info(
		"RRR sealCurrentBlock - sealed header",
		"now", time.Now(), "bt", header.Time,
		"bn", block.Number(), "r", r.intent.SI.Intent.RoundNumber,
		"ends", len(data.Confirm),
		"#", block.Hash(), "addr", r.nodeAddr.Hex())

	r.sealTask = nil
	r.intent = nil

	// XXX: TODO decide if legitimate leader candidate and if in correct phase

	return true, nil
}
