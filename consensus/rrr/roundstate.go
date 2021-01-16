package rrr

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

type RRRState int
type RoundPhase int

const (
	RRRStateInvalid RRRState = iota
	// If beginBlock fails we can't recover without a new block - this state suggests a bug in verifyHeader
	RRRStateNeedBlock
	RRRStateInactive          // Indicates conditions we expect to be transitor - endorsers not online etc
	RRRStateNodeStarting      // Node has just started up, wait long enough to allow for a block to be minted by live participants
	RRRStateActive            // Has endorsed or mined in some time in the last Ta rounds.
	RRRStateLeaderCandidate   // Selected as leader candidate for current round
	RRRStateEndorserCommittee // Is in the endorser committee for the current round.
)

const (
	RoundPhaseInvalid RoundPhase = iota
	// During the Intent phase, the endorser committee is allowing for intents
	// to arrive so they can, with high probability,  pick the oldest active
	// leader candidate.
	RoundPhaseIntent
	// During the confirmation phase leaders are waiting for all the
	// endorsements to come in so they fairly represent activity.
	RoundPhaseConfirm
)

type RoundState struct {
	T              *RoundTime
	Rand           *rand.Rand
	Phase          RoundPhase
	State          RRRState
	Number         *big.Int
	FailedAttempts uint
	Endorsers      map[common.Address]consensus.Peer

	logger log.Logger
}

func (p RoundPhase) String() string {
	switch p {
	case RoundPhaseIntent:
		return "RoundPhaseIntent"
	case RoundPhaseConfirm:
		return "RoundPhaseConfirm"
	default:
		return "RoundPhaseInvalid"
	}
}

func (s RRRState) String() string {
	switch s {
	case RRRStateNeedBlock:
		return "RRRStateNeedBlock"
	case RRRStateInvalid:
		return "RRRStateInvalid"
	case RRRStateInactive:
		return "RRRStateInactive"
	case RRRStateNodeStarting:
		return "RRRStateNodeStarting"
	case RRRStateActive:
		return "RRRStateActive"
	case RRRStateLeaderCandidate:
		return "RRRStateLeaderCandidate"
	case RRRStateEndorserCommittee:
		return "RRRStateEndorserCommittee"
	default:
		return "<unknown>"
	}
}

// NewRoundSate creates and initialises a RoundState
func NewRoundState(config *Config, logger log.Logger) *RoundState {
	s := &RoundState{
		T: NewRoundTime(config.RoundLength, config.ConfirmPhase, logger),
	}
	return s
}

// Start sets the round state running.  IMPORTANT: This starts the ticker.
func (r *RoundState) Start() {
	r.T.Start()
	r.Phase = RoundPhaseIntent
	r.State = RRRStateNodeStarting
	r.Number = big.NewInt(1)
}

// NewChainHead is called to handle the chainHead event from the block chain.
// For a block to make it this far, VerifyHeader and VerifySeal must have seen
// and accepted the block. A 'bad' block here is the result of a programming
// error.
func (r *RoundState) NewChainHead(e *engine, chain RRRChainReader, newHeadBlock *types.Block) {

	var err error
	// Reset the timer when a new block arrives. This should offer lose
	// synchronisation.  RRR's notion of active and age requires that honest
	// nodes give endorsers a consistent amount of time per round to record
	// their endorsement by signing an intent for the leader. Whether or not
	// the endorsement was required to reach the quorum, the presence of the
	// endorsement in the block header is how RRR determines if non leader
	// nodes are active in a particular round. Note that go timers are quite
	// tricky, see
	// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/
	r.T.Stop()

	// t.ResetForIntentPhase()
	// roundPhase = RoundPhaseIntent

	var sed *SignedExtraData
	r.Number, r.Rand, sed, err = e.nextRound(chain, newHeadBlock, r.Number)
	if err != nil {
		r.State = RRRStateNeedBlock
		e.logger.Warn("RRR newHead > RRRStateNeedBlock - corruption or bug ?", "err", err)
		return
	}

	// XXX: Make this configurable on/off
	r.Phase = r.T.PhaseAdjust(sed.SealTime)

	r.FailedAttempts = 0
	r.State, r.Endorsers, err = e.nextRoundState(chain, r.Rand, r.FailedAttempts)
	if err != nil {
		e.logger.Info("RRR newHead - nextRoundState", "err", err)
	}

	e.logger.Info(
		fmt.Sprintf("RRR new round *** %s ***", r.State.String()),
		"round", r.Number, "phase", r.Phase.String(), "addr", e.nodeAddr.Hex())

	if r.State != RRRStateLeaderCandidate {
		return
	}

	if len(r.Endorsers) < int(e.config.Quorum) {
		e.logger.Debug(
			"RRR *** insufficient endorsers online ***", "round", r.Number,
			"addr", e.nodeAddr.Hex(), "err", err)
	}

	// The intent is cleared when the round changes. Here we know we are a
	// leader candidate on the new round, establish our new intent.

	// If there is a current seal task, it will be resused, no matter
	// how long it has been since the local node was a leader
	// candidate.
	if err := e.refreshSealTask(r.Number, r.FailedAttempts); err != nil {
		e.logger.Info("RRR newHead refreshSealTask", "err", err)
		return
	}

	// Make our peers aware of our intent for this round, this may get reset by
	// the arival of a new sealing task
	e.broadcastCurrentIntent(r.Endorsers)
}

// NewSealTask delivers work from the node to be mined. If we are the leader,
// and we are in the intent phase we immediately broadcast our intent. If not,
// we hang on to it until we are or we receive the next one.
func (r *RoundState) NewSealTask(e *engine, et *engSealTask) {

	e.logger.Trace("RRR engSealTask",
		"state", r.State.String(), "addr", e.nodeAddr.Hex(),
		"r", r.Number, "f", r.FailedAttempts)

	et.RoundNumber = big.NewInt(0).Set(r.Number)

	// Note: we don't reset the attempt if we get a new seal task.
	if err := e.newSealTask(r.State, et, r.Number, r.FailedAttempts); err != nil {
		e.logger.Info("RRR engSealTask - newSealTask", "err", err)
	}

	if r.State == RRRStateLeaderCandidate && r.Phase == RoundPhaseIntent {

		e.logger.Trace(
			"RRR engSealTask - broadcasting intent (new)", "addr", e.nodeAddr.Hex(),
			"r", r.Number, "f", r.FailedAttempts)

		e.broadcastCurrentIntent(r.Endorsers)
	}
}

// NewSignedIntent keeps track of the oldest intent seen in a round. At the end
// of the intent phase (in PhaseTick), if the node is an endorser, and
// endorsment is sent to the oldest seen an endorser, and endorsment is sent to
// the oldest seen
func (r *RoundState) NewSignedIntent(e *engine, et *engSignedIntent) {
	// endorser <- intent from leader candidate
	if r.State == RRRStateNodeStarting {
		e.logger.Trace("RRR engSignedIntent - node starting, ignoring", "et.round", et.RoundNumber)
		return
	}
	if r.State == RRRStateNeedBlock {
		e.logger.Trace("RRR engSignedIntent - need block, ignoring", "et.round", et.RoundNumber)
		return
	}
	// See RRR-spec.md for a more thorough explanation, and for why we don't
	// check the round phase or whether or not we - locally - have selected
	// ourselves as an endorser. handleIntent.
	e.logger.Trace("RRR run got engSignedIntent",
		"round", r.Number, "cand-round", et.RoundNumber, "cand-attempts", et.FailedAttempts,
		"candidate", et.NodeID.Hex(), "parent", et.ParentHash.Hex())

	if err := e.handleIntent(et, r.Number); err != nil {
		e.logger.Info("RRR run handleIntent", "err", err)
	}
}

// NewSignedEndorsement keeps track of endorsments received from peers. At the
// end of the confirmation phase, in PhaseTick, if we are a leader and our
// *current* intent has sufficient endorsments, we seal the block. This causes
// geth to broad cast it to the network.
func (r *RoundState) NewSignedEndorsement(e *engine, et *engSignedEndorsement) {
	// leader <- endorsment from committee
	if r.State == RRRStateNodeStarting {
		e.logger.Trace("RRR engSignedEndorsement - node starting, ignoring", "end", et.EndorserID.Hex())
		return
	}

	if r.State != RRRStateLeaderCandidate {
		// This is un-expected. Likely late, or possibly from
		// broken node
		e.logger.Trace("RRR non-leader ignoring engSignedEndorsement", "round", r.Number)
		return
	}

	// XXX: divergence (3) the paper handles endorsements only in the
	// confirmation phase. It is important that all identities get an
	// opportunity to record activity. I think the key point is that a quorum of
	// fast nodes can't starve 'slow' nodes. So as long as the window is
	// consistent for all, it doesn't really matter what it is. And it is (a
	// little) easier to just accept endorsements at any time in the round.

	e.logger.Trace("RRR engSignedEndorsement",
		"round", r.Number,
		"endorser", et.EndorserID.Hex(), "intent", et.IntentHash.Hex())

	// Provided the endorsment is for our outstanding intent and from an
	// identity we have selected as an endorser in this round, then its
	// endorsment will be included in the block - whether we needed it to reach
	// the endorsment quorum or not.
	if err := e.handleEndorsement(et); err != nil {
		e.logger.Info("RRR run handleIntent", "err", err)
	}
}

// PhaseTick deals with the time based round state transitions. It MUST be
// called each time a tick is read from the ticker. At the end of the intent
// phase, if an endorser, the oldest seen intent is endorsed. At the end of the
// confirmation phase, if a leader candidate AND the current intent has
// sufficient endorsements, the block for the intent is sealed. Geth will then
// broadcast it. Finally, we deal with liveness here. The FailedAttempt counter
// is (almost) always incremented and the endorsers resampled. The exceptions
// are when we are starting and are in RRRStateNodeStarting (normal), and if we
// enter RRRStateNeedsBlock. NeedsBlock means the node will not progress unless
// it sees a new block from the network.
func (r *RoundState) PhaseTick(e *engine, chain RRRChainReader) {

	var confirmed bool
	var err error

	// We MUST reset, else the Stop when a new block arrives will block
	if r.Phase == RoundPhaseIntent {

		// Completed intent phase, if we have a signedIntent here, it means we
		// have not seen an intent from the oldest selected and this is the
		// oldest we have seen. So go ahead and send it. This gives us liveness
		// in the face of network issues and misbehaviour. The > Nc the stronger
		// the mitigation. Notice that we DO NOT check if we are currently
		// selected as an endorser.
		// XXX: TODO given what we are doing with intents, endorsements and
		// failedAttempts now, I'm not sure having strict intent and
		// confirmation phases makese sense - one 'attempt' phase timer should
		// work just as well.

		if r.State == RRRStateNeedBlock {
			// If we don't have a valid head, we have no buisiness
			// handing out endorsements
			e.logger.Trace(
				"RRR tick - intent phase - discarding endorsement due to round state",
				"r", r.Number, "f", r.FailedAttempts, "state", r.State.String())

			e.signedIntent = nil
		}

		if e.signedIntent != nil {
			oldestSeen := e.signedIntent.NodeID.Address()
			e.logger.Trace(
				"RRR tick - intent phase - sending endorsement to oldest seen",
				"r", r.Number, "f", r.FailedAttempts)
			e.sendSignedEndorsement(oldestSeen, e.signedIntent)
			e.signedIntent = nil
		}

		e.logger.Debug(
			"RRR tick - RoundPhaseIntent > RoundPhaseConfirm", "r", r.Number, "f", r.FailedAttempts)

		r.T.ResetForConfirmPhase()
		r.Phase = RoundPhaseConfirm
		return
	}

	// completed confirm phase
	r.Phase = RoundPhaseIntent

	// Choosing to include the potential cost of the first call to
	// nextRound in the ticker
	r.T.ResetForIntentPhase()

	// Deal with the 'old' state and any end conditions
	switch r.State {
	case RRRStateNodeStarting:
		// On startup, we wait a round to see if we get a block from a currently
		// live network. If not we assume we are the first (or among the first)
		// nodes, to start or to catch up. Remember, the miner stops and the
		// consensus engine while it is syncing. If we haven't received a block
		// from the network to pick the round from, we will use the current
		// block according to the local database.

		// it gets incremented below, which is correct as if we get here, then
		// the network has failed one attempt as far as this node is concerned.
		r.FailedAttempts = 0

		r.Number, r.Rand, _, err = e.nextRound(chain, nil, r.Number)
		if err != nil {
			r.State = RRRStateNeedBlock
			e.logger.Warn(
				"RRR tick - nextRound > RRRStateNeedBlock - corruption or bug ?", "err", err)
			return
		}

		// End of confirmation phase. If we are a leader and we have the
		// necessary endorsements, seal our intent.

		// engine RRRStateNodeStarting is now unreachable
	case RRRStateNeedBlock:
		// The current head block we have is no good to us, or we have
		// an implementation bug.
		e.logger.Warn(
			"RRR tick - nextRound > RRRStateNeedBlock - corruption or bug ?", "err", err)
		return

	case RRRStateLeaderCandidate:

		if confirmed, err = e.sealCurrentBlock(); confirmed {

			e.logger.Info("RRR tick - sealed block", "addr", e.nodeAddr.Hex(),
				"r", r.Number, "f", r.FailedAttempts)

		} else if err != nil {
			e.logger.Warn("RRR tick - sealCurrentBlock", "err", err)
		}

	case RRRStateInactive:
		e.logger.Debug("RRR tick - inactive for last attempt")
	}

	// We always increment failedAttempts if we reach here. This is the local
	// nodes perspective on how many times the network has failed to produce a
	// block. failedAttempts is reset in newHead. Until we *see* a newHead, we
	// consider the attempt failed even if we seal a block above
	r.FailedAttempts++

	r.State, r.Endorsers, err = e.nextRoundState(chain, r.Rand, r.FailedAttempts)
	if err != nil {
		e.logger.Info("RRR tick - nextRoundState", "err", err)
	}
	e.logger.Debug("RRR tick - RoundPhaseConfirm > RoundPhaseIntent",
		"state", r.State.String(), "addr", e.nodeAddr.Hex(),
		"r", r.Number, "f", r.FailedAttempts)

	// Note: If we just sealed a block (above) then there will be no
	// outstanding intent and refreshSealTask will be a NoOp.  Ultimately, if
	// the block we just sealed doesn't result in a NewChainHead event, we will
	// eventually try again when the failedAttempts counter makes it our turn
	// again. But only if a new task arives. Once we commit to a block seal, we
	// are done with the block regardless of what the network sais about it.
	if r.State == RRRStateLeaderCandidate {
		if err = e.refreshSealTask(r.Number, r.FailedAttempts); err != nil {
			e.logger.Debug("RRR - tick refreshSealTask", "err", err)
		}

		e.logger.Trace(
			"RRR tick - broadcasting intent", "addr", e.nodeAddr.Hex(),
			"r", r.Number, "f", r.FailedAttempts)

		e.broadcastCurrentIntent(r.Endorsers)
	}
}
