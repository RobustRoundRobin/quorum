package rrr

// engine methods for activities descendent to the run() method

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	errSealSeedFailed = errors.New("failed to generate a seed for the next block")
)

// eng* types can be sent at any tome the the engines main channel.

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

type engSignedIntent struct {
	SignedIntent
	Pub        []byte // Derived from signature
	ReceivedAt time.Time
	Seq        uint // from RMsg
}

type engSignedEndorsement struct {
	SignedEndorsement
	Pub        []byte // Derived from signature
	ReceivedAt time.Time
	Seq        uint // from RMsg
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

type RoundState int // todo: rename -> RoundRole
type RoundPhase int

const (
	RoundStateInvalid RoundState = iota
	// If beginBlock fails we can't recover without a new block - this state suggests a bug in verifyHeader
	RoundStateNeedBlock
	RoundStateInactive          // Indicates conditions we expect to be transitor - endorsers not online etc
	RoundStateNodeStarting      // Node has just started up, wait long enough to allow for a block to be minted by live participants
	RoundStateActive            // Has endorsed or mined in some time in the last Ta rounds.
	RoundStateLeaderCandidate   // Selected as leader candidate for current round
	RoundStateEndorserCommittee // Is in the endorser committee for the current round.
)

func (s RoundState) String() string {
	switch s {
	case RoundStateNeedBlock:
		return "RoundStateNeedBlock"
	case RoundStateInvalid:
		return "RoundStateInvalid"
	case RoundStateInactive:
		return "RoundStateInactive"
	case RoundStateNodeStarting:
		return "RoundStateNodeStarting"
	case RoundStateActive:
		return "RoundStateActive"
	case RoundStateLeaderCandidate:
		return "RoundStateLeaderCandidate"
	case RoundStateEndorserCommittee:
		return "RoundStateEndorserCommittee"
	default:
		return "<unknown>"
	}
}

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

func (e *engine) roundPhaseAdjustment(
	intentDuration, confirmDuration time.Duration,
	now, sealTime time.Time) (
	RoundPhase, time.Duration) {

	if now.After(sealTime) {
		latency := now.Sub(sealTime)

		if latency >= intentDuration+confirmDuration {
			// We don't adjust our local attempt counter, we just align best we
			// can with the phase.
			m := math.Mod(float64(latency), float64(intentDuration+confirmDuration))
			i, _ := math.Modf(m)
			latency = time.Duration(i)
		}
		if latency < intentDuration {
			// Easy case, the adjustment just shortens the intent phase.
			return RoundPhaseIntent, intentDuration - latency
		}

		if latency < intentDuration+confirmDuration {
			// Also fairly easy case. The adjustment puts us in the confirm
			// phase
			latency -= intentDuration
			return RoundPhaseIntent, confirmDuration - latency
		}
		panic("this should be impossible")
		// Now we need to consider adjusting the attempt
	}

	e.logger.Warn("seal time ahead of node now", "now", now, "seal", sealTime)

	return RoundPhaseIntent, time.Duration(0)
}

func (e *engine) run(chain RRRChainReader, ch <-chan interface{}) {

	defer e.runningWG.Done()
	e.runningWG.Add(1)

	roundDuration := time.Duration(e.config.RoundLength) * time.Millisecond
	confirmPhaseDuration := time.Duration(e.config.ConfirmPhase) * time.Millisecond
	intentPhaseDuration := time.Duration(e.config.RoundLength-e.config.ConfirmPhase) * time.Millisecond
	e.logger.Info("run starting", "roundDur", roundDuration, "conDur", confirmPhaseDuration, "intDur", intentPhaseDuration)

	roundPhase := RoundPhaseIntent
	roundTick := time.NewTimer(intentPhaseDuration)
	// Endorsed leader candidates will broadcast the new block at the end of
	// the round according to their tickers. We reset the ticker each time we
	// see a new block confirmed. This will cause all participants to loosely
	// align on the same time window for each round. In the absence of
	// sufficient endorsments to produce a block, each leader candidate will
	// simply re-broadcast their current intent.

	var roundRand *rand.Rand

	roundState := RoundStateNodeStarting
	roundNumber := big.NewInt(1) // default block is the first after genesis

	failedAttempts := uint(0)
	var endorsers map[common.Address]consensus.Peer

	var err error
	for {
		select {
		case newHead, ok := <-e.chainHeadCh:
			if !ok {
				e.logger.Info("RRR newHead - chain head channel shutdown")
				return
			}

			// To get here, VerifyHeader and VerifySeal must have seen and
			// accepted the block. We can only get a 'bad' block here if the
			// consensus interface is not being honoured.

			// Reset the timer when a new block arrives. This should offer lose
			// synchronisation.  RRR's notion of active and age requires that
			// honest nodes give endorsers a consistent amount of time per
			// round to record their endorsement by signing an intent for the
			// leader. Whether or not the endorsement was required to reach the
			// quorum, the presence of the endorsement in the block header is
			// how RRR determines if non leader nodes are active in a
			// particular round. Note that go timers are quite tricky, see
			// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/

			if !roundTick.Stop() { // Stop and drain
				<-roundTick.C
			}
			// roundTick.Reset(intentPhaseDuration)
			// roundPhase = RoundPhaseIntent

			var sed *SignedExtraData
			roundNumber, roundRand, sed, err = e.nextRound(chain, newHead.Block, roundNumber)
			if err != nil {
				roundState = RoundStateNeedBlock
				e.logger.Warn("RRR newHead > RoundStateNeedBlock - corruption or bug ?", "err", err)
				continue
			}

			// XXX: Make this configurable on/off

			var tick time.Duration
			roundPhase, tick = e.roundPhaseAdjustment(
				intentPhaseDuration, confirmPhaseDuration, time.Now(),
				time.Unix(int64(sed.SealTime), 0))
			roundTick.Reset(tick)

			failedAttempts = 0
			roundState, endorsers, err = e.nextRoundState(chain, roundRand, failedAttempts)
			if err != nil {
				e.logger.Info("RRR newHead - nextRoundState", "err", err)
			}

			switch roundState {
			case RoundStateEndorserCommittee:
				e.logger.Info(
					"RRR new round *** endorser committee ***",
					"round", roundNumber, "addr", e.nodeAddr.Hex())
				continue
			case RoundStateLeaderCandidate:
				e.logger.Info(
					"RRR new round *** leader candidate ***",
					"round", roundNumber, "addr", e.nodeAddr.Hex())
			default:
				e.logger.Info(
					"RRR new round not a candidate leader or endorser",
					"round", roundNumber, "state", roundState.String(), "addr", e.nodeAddr.Hex())

				continue
			}

			if len(endorsers) < int(e.config.Quorum) {
				e.logger.Debug(
					"RRR *** insufficient endorsers online ***", "round", roundNumber,
					"addr", e.nodeAddr.Hex(), "err", err)
			}

			// The intent is cleared when the round changes. Here we know we
			// are a leader candidate on the new round, establish our new
			// intent.

			// If there is a current seal task, it will be resused, no matter
			// how long it has been since the local node was a leader
			// candidate.
			if err := e.refreshSealTask(roundNumber, failedAttempts); err != nil {
				e.logger.Info("RRR newHead refreshSealTask", "err", err)
				continue
			}

			// Make our peers aware of our intent for this round, this may get
			// reset by the arival of a new sealing task
			e.broadcastCurrentIntent(endorsers)

		case i, ok := <-ch:
			if !ok {
				e.logger.Info("RRR run - input channel closed")
				return
			}

			switch et := i.(type) {

			case *engSealTask:

				// We always accept seal tasks, we just don't do anything with
				// them unless we become a leader while it is outstanding.
				e.logger.Debug("RRR engSealTask",
					"state", roundState.String(), "addr", e.nodeAddr.Hex(),
					"r", roundNumber, "f", failedAttempts)

				e.logger.Debug("RRR engSealTask", "round", roundNumber)
				et.RoundNumber = big.NewInt(0).Set(roundNumber)

				// Note: we don't reset the attempt if we get a new seal task.
				if err := e.newSealTask(roundState, et, roundNumber, failedAttempts); err != nil {
					e.logger.Info("RRR engSealTask - newSealTask", "err", err)
				}

				if roundState == RoundStateLeaderCandidate && roundPhase == RoundPhaseIntent {

					e.logger.Trace(
						"RRR engSealTask - broadcasting intent (new)", "addr", e.nodeAddr.Hex(),
						"r", roundNumber, "f", failedAttempts)

					e.broadcastCurrentIntent(endorsers)
				}

			case *engSignedIntent:

				// endorser <- intent from leader candidate
				if roundState == RoundStateNodeStarting {
					e.logger.Trace("RRR engSignedIntent - node starting, ignoring", "et.round", et.RoundNumber)
					continue
				}
				if roundState == RoundStateNeedBlock {
					e.logger.Trace("RRR engSignedIntent - need block, ignoring", "et.round", et.RoundNumber)
					continue
				}
				// See RRR-spec.md for a more thorough explanation, and for why
				// we don't check the round phase or whether or not we -
				// locally - have selected ourselves as an endorser.
				// handleIntent.
				e.logger.Info("RRR run got engSignedIntent",
					"round", roundNumber, "cand-round", et.RoundNumber, "cand-attempts", et.FailedAttempts,
					"candidate", et.NodeID.Hex(), "parent", et.ParentHash.Hex())

				if err := e.handleIntent(et, roundNumber); err != nil {
					e.logger.Info("RRR run handleIntent", "err", err)
				}

			case *engSignedEndorsement:

				// leader <- endorsment from committee
				if roundState == RoundStateNodeStarting {
					e.logger.Trace("RRR engSignedEndorsement - node starting, ignoring", "end", et.EndorserID.Hex())
					continue
				}

				if roundState != RoundStateLeaderCandidate {
					// This is un-expected. Likely late, or possibly from
					// broken node
					e.logger.Trace("RRR non-leader ignoring engSignedEndorsement", "round", roundNumber)
					continue
				}

				// XXX: divergence (3) the paper handles endorsements only in
				// the confirmation phase. It is important that all identities
				// get an opportunity to record activity. I think the key point
				// is that a quorum of fast nodes can't starve 'slow' nodes. So
				// as long as the window is consistent for all, it doesn't
				// really matter what it is. And it is (a little) easier to
				// just accept endorsements at any time in the round.

				e.logger.Trace("RRR engSignedEndorsement",
					"round", roundNumber,
					"endorser", et.EndorserID.Hex(), "intent", et.IntentHash.Hex())

				// Provided the endorsment is for our outstanding intent and
				// from an identity we have selected as an endorser in this
				// round, then its endorsment will be included in the block -
				// whether we needed it to reach the endorsment quorum or not.
				if err := e.handleEndorsement(et); err != nil {
					e.logger.Info("RRR run handleIntent", "err", err)
				}

			default:
				e.logger.Info("rrr engine.run received unknown type", "v", i)
			}

		case <-roundTick.C:
			var confirmed bool
			var err error

			// We MUST reset, else the Stop when a new block arrives will block
			if roundPhase == RoundPhaseIntent {

				// Completed intent phase, if we have a signedIntent here, it
				// means we have not seen an intent from the oldest selected
				// and this is the oldest we have seen. So go ahead and send
				// it. This gives us liveness in the face of network issues and
				// misbehaviour.  The > Nc the stronger the mitigation. Notice
				// that we DO NOT check if we are currently selected as an
				// endorser.
				// XXX: TODO given what we are doing with intents, endorsements
				// and failedAttempts now, I'm not sure having strict intent
				// and confirmation phases makese sense - one 'attempt' phase
				// timer should work just as well.

				if roundState == RoundStateNeedBlock {
					// If we don't have a valid head, we have no buisiness
					// handing out endorsements
					e.logger.Trace(
						"RRR tick - intent phase - discarding endorsement due to round state",
						"r", roundNumber, "f", failedAttempts, "state", roundState.String())

					e.signedIntent = nil
				}

				if e.signedIntent != nil {
					oldestSeen := e.signedIntent.NodeID.Address()
					e.logger.Trace(
						"RRR tick - intent phase - sending endorsement to oldest seen",
						"r", roundNumber, "f", failedAttempts)
					e.sendSignedEndorsement(oldestSeen, e.signedIntent)
					e.signedIntent = nil
				}

				e.logger.Debug(
					"RRR tick - RoundPhaseIntent > RoundPhaseConfirm", "r", roundNumber, "f", failedAttempts)
				roundTick.Reset(confirmPhaseDuration)
				roundPhase = RoundPhaseConfirm
				continue
			}

			// completed confirm phase
			roundPhase = RoundPhaseIntent

			// Choosing to include the potential cost of the first call to
			// nextRound in the ticker
			roundTick.Reset(intentPhaseDuration)

			// Deal with the 'old' state and any end conditions
			switch roundState {
			case RoundStateNodeStarting:
				// On startup, we wait a round to see if we get a block from a
				// currently live network. If not we assume we are the first
				// (or among the first) nodes, to start or to catch up.
				// Remember, the miner stops and the consensus engine while it
				// is syncing.  If we haven't received a block from the network
				// to pick the round from, we will use the current block
				// according to the local database.

				// it gets incremented below, which is correct as if we get
				// here, then the network has failed one attempt as far as this
				// node is concerned.
				failedAttempts = 0

				roundNumber, roundRand, _, err = e.nextRound(chain, nil, roundNumber)
				if err != nil {
					roundState = RoundStateNeedBlock
					e.logger.Warn(
						"RRR tick - nextRound > RoundStateNeedBlock - corruption or bug ?", "err", err)
					continue
				}

				// End of confirmation phase. If we are a leader and we have the
				// necessary endorsements, seal our intent.

				// engine RoundStateNodeStarting is now unreachable
			case RoundStateNeedBlock:
				// The current head block we have is no good to us, or we have
				// an implementation bug.
				e.logger.Warn(
					"RRR tick - nextRound > RoundStateNeedBlock - corruption or bug ?", "err", err)

				continue

			case RoundStateLeaderCandidate:

				if confirmed, err = e.sealCurrentBlock(); confirmed {

					e.logger.Info("RRR tick - sealed block", "addr", e.nodeAddr.Hex(),
						"r", roundNumber, "f", failedAttempts)

				} else if err != nil {
					e.logger.Warn("RRR tick - sealCurrentBlock", "err", err)
				}
			case RoundStateInactive:
				e.logger.Debug("RRR tick - inactive for last attempt")
			}

			// We always increment failedAttempts if we reach here. This is the
			// local nodes perspective on how many times the network has failed
			// to produce a block. failedAttempts is reset in newHead. Until
			// we *see* a newHead, we consider the attempt failed even if we
			// seal a block above
			failedAttempts++

			roundState, endorsers, err = e.nextRoundState(chain, roundRand, failedAttempts)
			if err != nil {
				e.logger.Info("RRR tick - nextRoundState", "err", err)
			}
			e.logger.Debug("RRR tick - RoundPhaseConfirm > RoundPhaseIntent",
				"state", roundState.String(), "addr", e.nodeAddr.Hex(),
				"r", roundNumber, "f", failedAttempts)

			// Note: If we just sealed a block (above) then there will be
			// no outstanding intent and refreshSealTask will be a NoOp.
			// Ultimately, if the block we just sealed doesn't result in a
			// NewChainHead event, we will eventually try again when the
			// failedAttempts counter makes it our turn again. But only if a
			// new task arives. Once we commit to a block seal, we are done
			// with the block regardless of what the network sais about it.
			if roundState == RoundStateLeaderCandidate {
				if err = e.refreshSealTask(roundNumber, failedAttempts); err != nil {
					e.logger.Debug("RRR - tick refreshSealTask", "err", err)
				}

				e.logger.Trace(
					"RRR tick - broadcasting intent", "addr", e.nodeAddr.Hex(),
					"r", roundNumber, "f", failedAttempts)

				e.broadcastCurrentIntent(endorsers)
			}
		}
	}
}

// handleIntent accepts the intent and queues it for endorsement if the
// intendee is a candidate for the current round given the failedAttempts
// provided on the intent. As a special case, if we see the intent from the
// oldest selected identity, we broadcast it immediately.
//  Our critical role here is to always select the *OLDEST* intent we see, and
// to allow a 'fair' amount of time for intents to arrive before choosing one
// to endorse. In a healthy network, there will be no failedAttempts, and we
// could count on being synchronised reasonably with other nodes. In that
// situation our local 'endorsing' state can be checked. In the unhealthy
// scenario, or where the current leader candidates are all off line, we can
// only progress if we re-sample. And in that scenario different nodes could
// have been un-reachable for arbitrary amounts of time. So their
// failedAttempts will be arbitrarily different. Further, we can't stop other
// nodes from lying about their failedAttempts. So even if we were willing to
// run through randome samples x failedAttempts to check, the result would be
// meaningless - and would be an obvious way to DOS attack nodes.  Ultimately,
// it is the job of VerifyHeader, on all honest nodes, to check that the
// failedAttempts recorded in the block is consistent with the minters identity
// and the endorsers the minter included.  Now we *could* do special things for
// the firstAttempt or the first N attempts. But if, in the limit, we have to
// be robust in the face of some endorsers not checking, I would like to start
// with them all not checking
func (e *engine) handleIntent(et *engSignedIntent, roundNumber *big.Int) error {

	var err error

	// Do we agree that the intendee is next in line and that their intent is
	// appropriate ?

	// Check that the public key recovered from the intent signature matches
	// the node id declared in the intent

	var recoveredNodeID Hash
	if recoveredNodeID, err = PubBytes2NodeID(et.Pub); err != nil {
		return err
	}
	intenderAddr := et.NodeID.Address()

	if recoveredNodeID != et.NodeID {
		e.logger.Info("RRR handleIntent - sender not signer",
			"from-addr", intenderAddr.Hex(), "recovered", recoveredNodeID.Hex(), "signed", et.NodeID.Hex())
		return nil
	}

	// Check that the intent round matches our current round.
	if roundNumber.Cmp(et.RoundNumber) != 0 {
		e.logger.Info("RRR handleIntent - wrong round",
			"r", roundNumber, "ir", et.RoundNumber, "from-addr", intenderAddr.Hex())
		return nil
	}

	// Check that the intent comes from a node we have selected locally as a
	// leader candidate. According to the (matching) roundNumber and their
	// provided value for FailedAttempts
	if !e.leaderForRoundAttempt(intenderAddr, roundNumber, et.Intent.FailedAttempts) {
		e.logger.Info(
			"RRR handleIntent - intent from non-candidate",
			"round", roundNumber, "cand-f", et.Intent.FailedAttempts, "cand", intenderAddr.Hex())
		return errNotLeaderCandidate
	}

	if e.signedIntent != nil {
		// It must be in the map if it was active, otherwise we have a
		// programming error.
		curAge := e.aged[e.signedIntent.NodeID.Address()].Value.(*idActivity).ageBlock
		newAge := e.aged[intenderAddr].Value.(*idActivity).ageBlock

		// Careful here, the 'older' block will have the *lower* number
		if curAge.Cmp(newAge) < 0 {
			// current is older
			e.logger.Info(
				"RRR handleIntent - ignoring intent from younger candidate",
				"cand-addr", intenderAddr.Hex(), "cand-f", et.Intent.FailedAttempts)
			return nil
		}
	}

	// Its the first one, or it is from an older candidate and yet is not the oldest
	e.signedIntent = et
	return nil
}

func (e *engine) sendSignedEndorsement(intenderAddr Address, et *engSignedIntent) error {

	c := &SignedEndorsement{
		Endorsement: Endorsement{
			ChainID:    e.genesisEx.ChainID,
			EndorserID: e.nodeID,
		},
	}

	var err error
	c.IntentHash, err = et.SignedIntent.Hash()
	if err != nil {
		return err
	}

	// Note: by including the senders sequence, and remembering that the sender
	// will be changing the round also, we can be sure we will reply even if
	// the intent is otherwise a duplicate.
	rmsg := &RMsg{Code: RMsgConfirm, Seq: et.Seq}
	rmsg.Raw, err = c.SignedEncode(e.privateKey)
	if err != nil {
		e.logger.Info("RRR encoding SignedEndorsement", "err", err.Error())
		return err
	}
	msg, err := rlp.EncodeToBytes(rmsg)
	if err != nil {
		e.logger.Info("RRR encoding RMsgConfirm", "err", err.Error())
		return err
	}

	e.logger.Info("RRR sending confirmation",
		"candidate", et.SignedIntent.NodeID.Hex(),
		"endorser", e.nodeID.Hex())

	// find the peer candidate
	return e.Send(common.Address(intenderAddr), msg)

}

func (e *engine) handleEndorsement(et *engSignedEndorsement) error {

	if et.Endorsement.ChainID != e.genesisEx.ChainID {
		return fmt.Errorf("confirmation received for wrong chainid: %s", hex.EncodeToString(et.Endorsement.ChainID[:]))
	}

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	if e.intent == nil {
		e.logger.Info("RRR confirmation stale or un-solicited, no current intent",
			"endid", et.Endorsement.EndorserID.Hex(), "hintent", et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	pendingIntentHash, err := e.intent.SI.Hash()
	if err != nil {
		return err
	}

	if pendingIntentHash != et.SignedEndorsement.IntentHash {
		e.logger.Info("RRR confirmation for stale or unknown intent",
			"pending", pendingIntentHash.Hex(),
			"received", et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	// Check the confirmation came from an endorser selected by this node for
	// the current round
	endorserAddr := common.Address(et.SignedEndorsement.EndorserID.Address())
	if !e.endorsers[endorserAddr] {
		e.logger.Info("RRR confirmation from unexpected endorser", "endorser", et.Endorsement.EndorserID[:])
		return nil
	}

	// Check the confirmation is not from an endorser that has endorsed our
	// intent already this round.
	if e.intent.Endorsers[endorserAddr] {
		e.logger.Info("RRR redundant confirmation from endorser", "endorser", et.Endorsement.EndorserID[:])
		return nil
	}

	// Note: *not* copying, engine run owns everything that is passed to it on
	// the runningCh
	e.intent.Endorsements = append(e.intent.Endorsements, &et.SignedEndorsement)
	e.intent.Endorsers[endorserAddr] = true

	if uint64(len(e.intent.Endorsements)) >= e.config.Quorum {
		e.logger.Info("RRR confirmation redundant, have quorum",
			"endid", et.Endorsement.EndorserID.Hex(), "end#", et.SignedEndorsement.IntentHash.Hex(),
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
func (e *engine) sealCurrentBlock() (bool, error) {

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	if e.intent == nil {
		e.logger.Debug("RRR no outstanding intent")
		return false, nil
	}

	if len(e.intent.Endorsements) == 0 {
		e.logger.Debug("RRR no endorsments received")
		return false, nil
	}

	if len(e.intent.Endorsements) < int(e.config.Quorum) {
		got := len(e.intent.Endorsements)
		e.logger.Info("RRR insufficient endorsers to become leader",
			"q", int(e.config.Quorum), "got", got, "ends", len(e.endorsers))
		return false, nil
	}

	intentHash, err := e.intent.SI.Hash()
	if err != nil {
		return false, err
	}

	// Now check all the endorsments are for the intent
	for _, end := range e.intent.Endorsements {
		if intentHash != end.IntentHash {
			return false, fmt.Errorf(
				"endorsement intenthash mismatch. endid=%s", end.EndorserID.Hex())
		}
	}

	e.logger.Info("RRR confirmed as leader",
		"q", int(e.config.Quorum), "got", len(e.intent.Endorsements),
		"ends", len(e.endorsers))

	if e.sealTask == nil {
		e.logger.Info("RRR seal task canceled or discarded")
		return false, nil
	}

	if e.sealTask.Canceled() {
		e.logger.Info("RRR seal task canceled")
		return false, nil
	}

	// Complete the seal, block will be rejected if this is wrong, no need to
	// double up on checks here.
	header := e.sealTask.Block.Header()

	// role a new seed for the next round, this is all a bit 'make believe' in
	// the absence of VRF's
	seed := make([]byte, 8)
	nrand, err := cryptorand.Read(seed)
	if err != nil {
		return false, fmt.Errorf("crypto/rand.Read failed - %v: %w", err, errSealSeedFailed)
	}
	if nrand != 8 {
		return false, fmt.Errorf("crypto/rand.Read insufficient entropy - %v: %w", err, errSealSeedFailed)
	}
	if err != nil || nrand != 8 {
		return false, fmt.Errorf("failed reading random seed")
	}

	data := &SignedExtraData{
		ExtraData: ExtraData{
			SealTime: uint64(time.Now().Unix()),
			Intent:   e.intent.SI.Intent,
			Confirm:  make([]Endorsement, len(e.intent.Endorsements)),
			Seed:     seed,
		},
		// XXX: TODO seed proof / VRF's
	}
	for i, c := range e.intent.Endorsements {
		data.Confirm[i] = c.Endorsement
	}
	seal, err := data.SignedEncode(e.privateKey)
	if err != nil {
		return false, err
	}

	header.Extra = append(header.Extra[:RRRExtraVanity], []byte(seal)...)

	block := e.sealTask.Block.WithSeal(header)
	e.sealTask.Results <- block
	e.logger.Info(
		"RRR sealCurrentBlock - sealed header",
		"now", time.Now(), "bt", header.Time,
		"bn", block.Number(), "r", e.intent.SI.Intent.RoundNumber,
		"ends", len(data.Confirm),
		"#", block.Hash(), "addr", e.nodeAddr.Hex())

	e.sealTask = nil
	e.intent = nil

	// XXX: TODO decide if legitimate leader candidate and if in correct phase

	return true, nil
}

// The roundNumber is always correct, even on err. If err is nil it will be the
// *next* round number, otherwise it will be the round provided by the caller.
func (e *engine) nextRound(chain RRRChainReader, head *types.Block, roundNumber *big.Int) (
	*big.Int, // newRoundNumber
	*rand.Rand, // and seeded deterministic random source
	*SignedExtraData,
	error,
) {
	newRoundNumber, roundSeed, sed, headBlock, err := e.readHead(chain, head)
	if err != nil {
		e.logger.Info("RRR nextRound - failed to readHead", "err", err)
		return roundNumber, nil, nil, err
	}
	if head != nil {
		// Its a block from the network.
		tbloc := time.Unix(int64(head.Header().Time), 0)
		tseal := time.Unix(int64(sed.SealTime), 0)
		tnow := time.Now()

		e.logger.Debug(
			"RRR nextRound - new block",
			"bn", roundNumber,
			"l1", tnow.Sub(tseal).Milliseconds(),
			"l2", tnow.Sub(tbloc).Milliseconds(),
			"f", sed.Intent.FailedAttempts,
			"hash", head.Hash().Hex())
	}

	roundRand := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(roundSeed))))

	bigDiffTmp := big.NewInt(0)

	if bigDiffTmp.Sub(newRoundNumber, roundNumber).Cmp(bigOne) > 0 {
		e.logger.Info(
			"RRR nextRound - skipping round", "cur", roundNumber, "new", newRoundNumber)
	} else if bigDiffTmp.Cmp(big0) < 0 {
		e.logger.Info(
			"RRR nextRound - round moving backwards", "cur", roundNumber, "new", newRoundNumber)
	}

	// Establish the order of identities in the round robin selection. Age is
	// determined based on the identity enrolments in the block, and of the
	// identities which enroled blocks - both of which are entirely independent
	// of the number of attempts required to produce a block in any given
	// round.
	if err := e.accumulateActive(chain, headBlock.Header()); err != nil {
		if !errors.Is(err, errBranchDetected) {
			e.logger.Info(
				"RRR nextRound - accumulateActive failed", "err", err)
			return nil, nil, nil, err
		}

		if err = e.resetActive(chain); err != nil {
			e.logger.Warn("RRR nextRound resetActive failed", "err", err)
			return nil, nil, nil, err
		}

		if err := e.accumulateActive(chain, headBlock.Header()); err != nil {
			e.logger.Warn("resetActive failed to recover from re-org", "err", err)
			return roundNumber, nil, nil, err
		}
	}
	roundNumber.Set(newRoundNumber)
	roundNumber.Add(roundNumber, bigOne)

	return roundNumber, roundRand, sed, nil
}

func (e *engine) readHead(chain RRRChainReader, head *types.Block) (
	*big.Int, []byte, *SignedExtraData, *types.Block, error) {

	if head == nil {
		head = chain.CurrentBlock()
	}

	var err error
	var se *SignedExtraData

	// This implementation of RRR defines the round number as the block number
	blockNumber := head.Number()

	// First, seed the random sequence for the round from the block seed.
	var seed []byte
	if blockNumber.Cmp(big0) > 0 {
		// There is no RRR seal on the genesis block
		se, _, _, err = e.decodeHeaderSeal(head.Header())
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("RRR readHead decodeHeaderSeal: %v", err)
		}

		if se.Intent.RoundNumber.Cmp(blockNumber) != 0 {
			// This should be rejected by VerifyHeader before it reaches the
			// chain.
			return nil, nil, nil, nil, fmt.Errorf(
				"RRR readHead - intent round number %v != block number %v",
				se.Intent.RoundNumber, blockNumber)
		}
		seed = se.Seed
	} else {
		seed = e.genesisEx.ChainInit.Seed
	}

	if len(seed) != 8 {
		return nil, nil, nil, nil, fmt.Errorf(
			"RRR readHead - seed wrong length should be 8 not %d", len(seed))
	}

	return blockNumber, seed, se, head, nil
}

// nextRoundState re-samples the active identities and returns the round state
// for the current node according to that sample. To reach the shared round
// state, on receipt of a new block, first run accumulateActive then seed the
// random source and then run nextRoundState once for each sampleCount on the
// intent which confirmed the block. It is a programming error if sampleCount < 1
func (e *engine) nextRoundState(
	chain RRRChainReader, roundRand *rand.Rand, failedAttempts uint,
) (RoundState, map[common.Address]consensus.Peer, error) {

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	e.signedIntent = nil

	// If we are a leader candidate we need to broadcast an intent.
	var err error
	e.candidates, e.endorsers, e.selection, err = e.selectCandidatesAndEndorsers(
		chain, roundRand, failedAttempts)
	if err != nil {
		return RoundStateInactive, nil, err
	}

	// How many endorsing peers are online - check this regardles of
	// leadership status.
	endorsers := e.broadcaster.FindPeers(e.endorsers)

	if len(endorsers) < int(e.config.Quorum) {
		// XXX: possibly it should be stricter and require e.config.Endorsers
		// online
		return RoundStateInactive, nil, nil
	}

	if !e.candidates[e.nodeAddr] {
		if !e.endorsers[e.nodeAddr] {
			return RoundStateActive, nil, nil // XXX: everyone is considered active for now
		}
		return RoundStateEndorserCommittee, nil, nil
	}
	e.intent = nil

	return RoundStateLeaderCandidate, endorsers, nil
}

func (e *engine) newSealTask(
	state RoundState, et *engSealTask, roundNumber *big.Int, failedAttempts uint,
) error {
	var err error
	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	var newIntent *pendingIntent
	if newIntent, err = e.newPendingIntent(et, roundNumber, failedAttempts); err != nil {
		return err
	}

	e.intent = newIntent
	e.sealTask = et
	return nil
}

// refreshSealTask will update the current intent to use the provided
// roundNumber and failedAttempts. The current intent will become the 'next'
// intent if there is one pending.
func (e *engine) refreshSealTask(roundNumber *big.Int, failedAttempts uint) error {

	var err error
	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	// Establish which, if any, currently known task can be refreshed.

	// Reconcile whether to re-issue current seal task
	if e.sealTask == nil || e.sealTask.Canceled() {
		e.intent = nil
		e.sealTask = nil
		e.logger.Trace("RRR refreshSealTask - no task")
		return nil
	}

	// The roundNumber or failedAttempts has to change in order for the message
	// to be broadcast.
	newIntent, err := e.newPendingIntent(e.sealTask, roundNumber, failedAttempts)
	if err != nil {
		return fmt.Errorf("refreshSealTask - newPendingIntent: %v", err)
	}

	// There is no need to send nil to Results on the previous task, the geth
	// miner worker can't do anything with that information
	e.intent = newIntent

	return nil
}

func (e *engine) newPendingIntent(
	et *engSealTask, roundNumber *big.Int, failedAttempts uint) (*pendingIntent, error) {

	var err error

	e.logger.Info("RRR newPendingIntent",
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
			ChainID:        e.genesisEx.ChainID,
			NodeID:         e.nodeID,
			RoundNumber:    big.NewInt(0).Set(roundNumber),
			FailedAttempts: failedAttempts,
			ParentHash:     Hash(et.Block.ParentHash()),
			TxHash:         Hash(et.Block.TxHash()), // the hash is computed by NewBlock
		},
	}
	pe.RMsg.Raw, err = pe.SI.SignedEncode(e.privateKey)
	if err != nil {
		return nil, err
	}

	if pe.Msg, err = rlp.EncodeToBytes(pe.RMsg); err != nil {
		return nil, err
	}

	pe.Endorsements = make([]*SignedEndorsement, 0, e.config.Quorum)
	pe.Endorsers = make(map[common.Address]bool)

	return pe, nil
}

// broadcastCurrentIntent gossips the signed intent for the currently pending
// seal task. It does this un-conditionally. It is the callers responsibility to
// call this from the right consensus engine state - including establishing if
// the node is a legitemate leader candidate.
func (e *engine) broadcastCurrentIntent(endorsers map[common.Address]consensus.Peer) {

	e.intentMu.Lock()
	if e.intent == nil {
		e.intentMu.Unlock()
		e.logger.Debug("RRR broadcastCurrentIntent - no intent")
		return
	}

	msg := e.intent.Msg
	e.intentMu.Unlock()

	if len(endorsers) == 0 {
		return
	}
	err := e.Broadcast(e.nodeAddr, endorsers, msg)
	if err != nil {
		e.logger.Info("RRR BroadcastCurrentIntent - Broadcast", "err", err)
	}
}
