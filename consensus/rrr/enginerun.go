package rrr

// engine methods for activities descendent to the run() method

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
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
	RoundStateInactive
	RoundStateActive            // Has endorsed or mined in some time in the last Ta rounds.
	RoundStateLeaderCandidate   // Selected as leader candidate for current round
	RoundStateEndorserCommittee // Is in the endorser committee for the current round.
)

const (
	RoundPhaseInvalid RoundPhase = iota
	// During the Intent phase, the endorser committee is allowing for intents
	// to arrive so they can, with high probability,  pick the oldest active
	// leader candidate.
	RoundPhaseIntent
	// During the confirmation phase leaders are waiting for all the
	// endorsements to comine so they fairly represent activity.
	RoundPhaseConfirm
)

func (e *engine) run(chain RRRChainReader, ch <-chan interface{}) {

	defer e.runningWG.Done()
	e.runningWG.Add(1)

	roundDuration := time.Duration(e.config.RoundLength) * time.Millisecond
	confirmPhaseDuration := time.Duration(e.config.ConfirmPhase) * time.Millisecond
	intentPhaseDuration := time.Duration(e.config.RoundLength-e.config.ConfirmPhase) * time.Millisecond
	e.logger.Info("run starting", "roundDur", roundDuration, "conDur", confirmPhaseDuration, "intDur", intentPhaseDuration)

	roundPhase := RoundPhaseIntent
	roundTick := time.NewTimer(intentPhaseDuration)
	numRoundTicks := 0 // the count of ticks that have elapsed since last block, this should ideal stay at 0 or 1.

	// Endorsed leader candidates will broadcast the new block at the end of
	// the round according to their tickers. We reset the ticker each time we
	// see a new block confirmed. This will cause all participants to loosely
	// align on the same time window for each round. In the absence of
	// sufficient endorsments to produce a block, each leader candidate will
	// simply re-broadcast their current intent.
	roundState, roundNumber := e.nextRound(chain, nil)

	for {
		select {
		case newHead, ok := <-e.chainHeadCh:
			if !ok {
				e.logger.Info("RRR newHead - chain head channel shutdown")
				return
			}
			e.logger.Debug("RRR ChainHeadEvent", "hash", newHead.Block.Hash().Hex())
			numRoundTicks = 0
			// To get here, VerifyHeader and VerifySeal must have seen and
			// accepted the block. We can only get a 'bad' block here if the
			// consensus interface is not being honoured.

			// Reset the timer when a new block arrives. This should offer lose
			// synchronisation.  RRR's notion of active and age requires that
			// honest nodes give endorsers a consistent amount of time per
			// round to record their endorsment by signing an intent for the
			// leader. Whether or not the endorsement was required to reach the
			// quorum, the presence of the endorsement in the block header is
			// how RRR determines if non leader nodes are active in a
			// particular round.  Chosing not to incorporate the block time
			// stamp as yet. Note that go timers are quite tricky, see
			// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/

			if !roundTick.Stop() { // Stop and drain
				<-roundTick.C
			}
			roundTick.Reset(intentPhaseDuration)
			roundPhase = RoundPhaseIntent

			roundState, roundNumber = e.nextRound(chain, newHead.Block)
			if roundState != RoundStateLeaderCandidate {
				continue
			}

			// The intent is cleared when the round changes. Here we know we
			// are a leader candidate on the new round, establish our new
			// intent.
			e.logger.Debug("RRR newHead - leader candidate", "round", roundNumber)

			// If there is a current seal task, it will be resused, no matter
			// how long it has been since the local node was a leader
			// candidate.
			if err := e.refreshSealTask(nil); err != nil {
				e.logger.Info("RRR newHead - refreshSealTask", "err", err)
				continue
			}

			// Make our peers aware of our intent for this round, this may get
			// reset by the arival of a new sealing task
			if err := e.broadcastCurrentIntent(); err != nil {
				e.logger.Info("RRR newHead - broadcastCurrentIntent", "err", err)
			}

		case i, ok := <-ch:
			e.logger.Trace("RRR run - handling event")
			if !ok {
				e.logger.Info("RRR run - input channel closed")
				return
			}

			switch et := i.(type) {

			case *engSealTask:

				// All nodes that are mining (started with --mine) will issue
				// seal requests. RRR decides which of those are endorsers and
				// which are leader candidates.
				if roundState != RoundStateLeaderCandidate {
					e.logger.Trace("RRR engSealTask - non-leader ignoring", "round", roundNumber)
					continue
				}

				e.logger.Info("RRR engSealTask", "round", roundNumber)

				if err := e.refreshSealTask(et); err != nil {
					e.logger.Info("RRR engSealTask - refreshSealTask", "err", err)
					continue
				}
				// intent -> leader candidates

			case *engSignedIntent:

				// endorser <- intent from leader candidate

				if roundState != RoundStateEndorserCommittee {
					// This is un-expected. Likely late, or possibly from
					// broken node
					e.logger.Trace("RRR non-endorser ignoring engSignedIntent", "round", roundNumber)
					continue
				}

				e.logger.Info("RRR run got engSignedIntent",
					"round", e.RoundNumber(), "candidate-round", et.RoundNumber,
					"candidate", et.NodeID.Hex(), "parent", et.ParentHash.Hex())

				if err := e.handleIntent(et, roundNumber); err != nil {
					e.logger.Info("RRR run handleIntent", "err", err)
				}

			case *engSignedEndorsement:

				// leader <- endorsment from committee

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

				e.logger.Trace("RRR run got engSignedEndorsement",
					"round", e.RoundNumber(),
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
				// misbehaviour.  The > Nc the stronger the mitigation.
				if e.signedIntent != nil {
					oldestSeen := e.signedIntent.NodeID.Address()
					e.logger.Info("RRR intent phase - sending endorsment to oldest seen", "addr", oldestSeen.Hex())
					e.sendSignedEndorsement(oldestSeen, e.signedIntent)
					e.signedIntent = nil
				}
				e.sentEndorsement = false

				e.logger.Debug("RRR start confirm phase", "addr", e.nodeAddr.Hex(), "ticks", numRoundTicks)
				roundTick.Reset(confirmPhaseDuration)
				roundPhase = RoundPhaseConfirm
				continue
			}

			// completed confirm phase
			roundTick.Reset(intentPhaseDuration)
			roundPhase = RoundPhaseIntent
			numRoundTicks += 1

			if roundState != RoundStateLeaderCandidate {
				e.logger.Debug("RRR start intent phase - endorsing", "addr", e.nodeAddr.Hex(), "ticks", numRoundTicks)
				continue
			}

			if confirmed, err = e.sealCurrentBlock(); err != nil {
				e.logger.Info("RRR sealCurrentBlock", "err", err)
				continue
			}

			e.logger.Debug("RRR start intent phase - leader candidate", "addr", e.nodeAddr.Hex(), "ticks", numRoundTicks)
			if !confirmed {
				if err = e.refreshSealTask(nil); err != nil {
					e.logger.Info("RRR refresing seal task", "err", err)
				}
				e.logger.Info("RRR broadcasting intent", "addr", e.nodeAddr.Hex(), "ticks", numRoundTicks)
				if err = e.broadcastCurrentIntent(); err != nil {
					e.logger.Info("RRR broadcasting intent", "err", err)
				}
			}
			if confirmed {
				e.logger.Info("RRR sealed block", "addr", e.nodeAddr.Hex(), "round", roundNumber)
			}
		}
	}
}

func (e *engine) handleIntent(et *engSignedIntent, roundNumber *big.Int) error {

	var err error
	// Don't call handleIntent unless selected for the endorser committee
	if !e.endorsers[e.nodeAddr] {
		return errNotEndorser
	}

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
	// leader candidate.
	if !e.candidates[common.Address(intenderAddr)] {
		e.logger.Info("RRR handleIntent - intent from non-candidate", "addr", intenderAddr.Hex())
		return nil
	}

	if e.sentEndorsement {
		// We could do this check earlier, but it is useful, at least for now,
		// to get logs for any malformed  or late intents on all nodes that see
		// them.
		e.logger.Info("RRR handleIntent - endorsed oldest already, ignoring intent from", "addr", intenderAddr.Hex())
		return nil
	}

	// If we see an intent from the oldest candidate, send the endorsment
	// immediately.
	if intenderAddr == Address(e.selection[0]) { // its a programming error if this slice is empty

		e.logger.Info("RRR handleIntent - sending endorsment, have intent from oldest", "addr", intenderAddr.Hex())
		err = e.sendSignedEndorsement(intenderAddr, et)
		if err != nil {
			return err
		}
		e.sentEndorsement = true
		// If we have seen a younger candidate first, forget it.
		e.signedIntent = nil
	}

	if e.signedIntent != nil {
		// It must be in the map if it was in the candidates map, otherwise we
		// have a programming error.
		curAge := e.aged[e.signedIntent.NodeID.Address()].Value.(*idActivity).ageBlock
		newAge := e.aged[intenderAddr].Value.(*idActivity).ageBlock

		// Careful here, the 'older' block will have the *lower* number
		if curAge.Cmp(newAge) < 0 {
			// current is older
			e.logger.Info("RRR handleIntent - have intent for older candidate, ignoring from", "addr", intenderAddr.Hex())
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

	// Endorsements is a slice whose backing array is pre allocated to the
	// quorum size
	if uint64(len(e.intent.Endorsements)) >= e.config.Quorum {
		e.logger.Info("RRR confirmation redundant, have quorum",
			"endid", et.Endorsement.EndorserID.Hex(), "end#", et.SignedEndorsement.IntentHash.Hex(),
			"hintent", et.SignedEndorsement.IntentHash.Hex())
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
			Intent:  e.intent.SI.Intent,
			Confirm: make([]Endorsement, len(e.intent.Endorsements)),
			Seed:    seed,
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
	e.sealTask = nil
	e.intent = nil
	e.logger.Info("RRR sealCurrentBlock - sealed header", "addr", e.nodeAddr.Hex(), "#", block.Hash())

	// XXX: TODO decide if legitimate leader candidate and if in correct phase

	return true, nil
}

func (e *engine) nextRound(chain RRRChainReader, head *types.Block) (RoundState, *big.Int) {

	e.roundNumberC.L.Lock()

	if head == nil {
		head = chain.CurrentBlock()
	}

	e.roundNumber = big.NewInt(0).Set(head.Number())
	e.roundNumber.Add(e.roundNumber, big.NewInt(1))
	roundNumber := big.NewInt(0).Set(e.roundNumber)

	e.roundNumberC.L.Unlock() // don't defer this
	e.roundNumberC.Broadcast()

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	e.signedIntent = nil
	e.sentEndorsement = false

	// First, seed the random sequence for the round from the block seed.
	var seed []byte
	if head.Number().Cmp(big0) > 0 {
		// There is no RRR seal on the genesis block
		se, _, _, err := e.decodeHeaderSeal(head.Header())
		if err != nil {
			e.logger.Info("RRR nextRound - failed to decode header seal, will be inactive this round", "err", err, "addr", e.nodeAddr.Hex(), "round", roundNumber)
			return RoundStateInactive, roundNumber
		}
		seed = se.Seed
	} else {
		seed = e.genesisEx.ChainInit.Seed
	}

	if len(seed) != 8 {
		// e.logger.Info("RRR nextRound - seed wrong length, will be inactive this round", "len", len(seed), "addr", e.nodeAddr.Hex(), "round", roundNumber)
		e.logger.Crit("RRR nextRound - seed wrong length, will be inactive this round", "len", len(seed), "addr", e.nodeAddr.Hex(), "round", roundNumber)
		return RoundStateInactive, roundNumber
	}

	// We record it in e only for telemetry, this is the only place it gets set.
	e.roundSeed = int64(binary.LittleEndian.Uint64(seed))
	e.roundRand = rand.New(rand.NewSource(e.roundSeed))

	// If we are a leader candidate we need to broadcast an intent.
	var err error
	e.candidates, e.endorsers, e.selection, err = e.selectCandidatesAndEndorsers(chain, head)
	if err != nil {
		e.logger.Info("RRR nextRound - select failed, skipping round", "addr", e.nodeAddr.Hex(), "round", roundNumber, "err", err)
		return RoundStateInactive, roundNumber
	}

	if !e.candidates[e.nodeAddr] {
		if !e.endorsers[e.nodeAddr] {
			e.logger.Info("RRR not a candidate leader or endorser", "addr", e.nodeAddr.Hex(), "round", roundNumber)
			return RoundStateActive, roundNumber // XXX: everyone is considered active for now
		}
		e.logger.Info("RRR endorser committee", "addr", e.nodeAddr.Hex(), "round", roundNumber)
		return RoundStateEndorserCommittee, roundNumber
	}
	e.intent = nil

	e.logger.Info("RRR **** leader candidate ****", "addr", e.nodeAddr.Hex(), "round", roundNumber)

	return RoundStateLeaderCandidate, roundNumber
}

// refreshSealTask will issue the provided seal task if et is not nil.
// Otherwise it will re-issue the existing seal task. If the round hasn't
// changed since the seal task was originally issued this will have no effect.
func (e *engine) refreshSealTask(et *engSealTask) error {

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	// these are just for telemetry
	hseal, hmsg := "nil", e.intentMsgHash.Hex()
	if e.intent != nil {
		hseal = e.intent.SealHash.Hex()
	}

	// Reconcile whether to re-issue current seal task
	if et == nil {
		if e.sealTask == nil {
			e.logger.Info("RRR refreshSealTask", "hseal", "none")
			return nil
		}
		et = e.sealTask
		e.logger.Info("RRR refreshSealTask", "hseal", hseal, "hmsg", hmsg)
	}

	if et.Canceled() {
		e.logger.Info("RRR refreshSealTask - cancelled", "hseal", hseal, "hmsg", hmsg)
		return nil
	}

	// The sequence ensures we re-broadcast the intent even if the seal task
	// hasn't changed.
	e.intentSeq += 1
	newIntent, err := e.newPendingIntent(et, e.intentSeq)
	if err != nil {
		return err
	}

	// There is no need to send nil to Results on the previous task, the geth
	// miner worker can't do anything with that information
	e.sealTask = et
	newIntentHash := Keccak256Hash(newIntent.Msg)

	// The intent may be nil, but we always remember the most recent intent msg hash
	if e.intentMsgHash == newIntentHash {

		// If we are re-issuing *and* we have endorsments, copy them forward.
		// Note the intent hash will not match if the round has changed.
		if e.intent != nil {

			newIntent.Endorsements = append(newIntent.Endorsements, e.intent.Endorsements...)

			if len(e.intent.Endorsements) > 0 {
				e.logger.Debug("RRR refreshSealTask - re-issue preserving endorsements")
			}
			for _, end := range newIntent.Endorsements {
				newIntent.Endorsers[common.Address(end.EndorserID.Address())] = true
			}
		}
		e.logger.Info("RRR refreshSealTask - no change", "hseal", hseal, "hmsg", hmsg)
	} else {
		e.logger.Info("RRR refreshSealTask - new intent")
	}
	e.intent = newIntent
	e.intentMsgHash = newIntentHash

	e.logger.Info("RRR refreshSealTask - current intent",
		"ends", len(newIntent.Endorsers), "cons", len(newIntent.Endorsements),
		"hseal", newIntent.SealHash.Hex(), "hmsg", e.intentMsgHash.Hex(),
	)

	return nil
}

func (e *engine) newPendingIntent(et *engSealTask, seq uint) (*pendingIntent, error) {

	var err error

	e.logger.Info("RRR newPendingIntent",
		"#tx", len(et.Block.Transactions()),
		"tx#", et.Block.TxHash().Hex(),
		"parent#", et.Block.ParentHash().Hex(),
	)
	pe := &pendingIntent{
		RMsg: RMsg{Code: RMsgIntent, Seq: seq},
	}

	pe.SealHash = Hash(sealHash(et.Block.Header()))

	// The intent that will need to be confirmed by 'q' endorsers in order for
	// this node to mine this block
	pe.SI = &SignedIntent{
		Intent: Intent{
			ChainID:     e.genesisEx.ChainID,
			NodeID:      e.nodeID,
			RoundNumber: e.RoundNumber(),
			ParentHash:  Hash(et.Block.ParentHash()),
			TxHash:      Hash(et.Block.TxHash()), // the hash is computed by NewBlock
		},
	}
	pe.RMsg.Raw, err = pe.SI.SignedEncode(e.privateKey)
	if err != nil {
		return nil, err
	}

	if pe.Msg, err = rlp.EncodeToBytes(pe.RMsg); err != nil {
		e.logger.Info("RRR encoding RMsgIntent", "err", err.Error())
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
func (e *engine) broadcastCurrentIntent() error {

	e.intentMu.Lock()
	if e.intent == nil {
		e.intentMu.Unlock()
		e.logger.Debug("RRR broadcastCurrentIntent - no intent")
		return nil
	}

	msg := e.intent.Msg
	endorsers := e.broadcaster.FindPeers(e.endorsers)
	e.logger.Info("RRR BroadcastCurrentIntent", "endorsers", len(e.endorsers), "online", len(endorsers))
	e.intentMu.Unlock()

	if len(endorsers) == 0 {
		return nil
	}
	return e.Broadcast(e.nodeAddr, endorsers, msg)
}
