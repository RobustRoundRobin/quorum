package rororo

// engine methods for activities descendent to the run() method

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// eng* types can be sent at any tome the the engines main channel.
// engStop

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
	// EndorserPeers map[common.Address]consensus.Peer
}

type RoundState int

const (
	RoundStateInvalid RoundState = iota
	RoundStateInactive
	RoundStateActive            // Has endorsed or mined in some time in the last Ta rounds.
	RoundStateLeaderCandidate   // Selected as leader candidate for current round
	RoundStateEndorserCommittee // Is in the endorser committee for the current round.
)

func (e *engine) run(chain RoRoRoChainReader, ch <-chan interface{}) {

	defer e.runningWG.Done()
	e.runningWG.Add(1)

	roundDuration := time.Duration(e.config.RoundLength) * time.Millisecond
	roundTick := time.NewTicker(roundDuration)
	// Idealy we want no ticks while we are an endorser, as endorsement is
	// reactive, and regular ticks when we are a leader candidate. HOWEVER:
	// time.Timer is *very* anoying.  In short: Stop is not idempotent. Stop is
	// only safe after New or Reset. Stop followed by Stop will block forever.
	// And Reset is only safe after Stop (or event). go 1.15 adds Reset to
	// Ticker which would be ideal.  See
	// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/

	// Endorsed leader candidates will broadcast the new block at the end of
	// the round according to their tickers. We reset the ticker each time we
	// see a new block confirmed. This will cause all participants to loosely
	// align on the same time window for each round. In the absence of
	// sufficient endorsments to produce a block, each leader candidate will
	// simply re-broadcast their current intent.
	roundState, roundNumber := e.nextRound(chain.CurrentBlock())
	if roundState == RoundStateLeaderCandidate {
		e.logger.Debug("RoRoRo leader candidate", "round", roundNumber)
	}

	for {
		select {
		case newHead, ok := <-e.chainHeadCh:
			if !ok {
				e.logger.Info("RoRoRo newHead - chain head channel shutdown")
				return
			}
			e.logger.Info("RoRoRo ChainHeadEvent", "hash", newHead.Block.Hash().Hex())

			// To get here, VerifyHeader and VerifySeal must have seen and
			// accepted the block. We can only get a 'bad' block here if the
			// consensus interface is not being honoured.

			// RRR's notion of active and age requires that honest nodes give
			// endorsers a consistent amount of time per round to record their
			// endorsment by signing an intent for the leader. Whether or not
			// the endorsement was required to reach the quorum, the presence
			// of the endorsement in the block header is how RRR determines
			// wether non leader nodes are active in a particular round or not.

			roundState, roundNumber = e.nextRound(newHead.Block)
			if roundState != RoundStateLeaderCandidate {
				continue
			}

			// The intent is cleared when the round changes. Now we now we are
			// a leader candidate on the new round, establish our new intent.

			e.logger.Debug("RoRoRo newHead - leader candidate", "round", roundNumber)

			// If there is a current seal task, it will be resused, no matter
			// how long it has been since the local node was a leader
			// candidate.
			if err := e.refreshSealTask(nil); err != nil {
				e.logger.Info("RoRoRo newHead - refreshSealTask", "err", err)
				continue
			}

			// Make our peers aware of our intent for this round, this may get
			// reset by the arival of a new sealing task
			if err := e.broadcastCurrentIntent(); err != nil {
				e.logger.Info("RoRoRo newHead - broadcastCurrentIntent", "err", err)
			}

		case i, ok := <-ch:
			e.logger.Info("RoRoRo run - handling event")
			if !ok {
				e.logger.Info("RoRoRo run - input channel closed")
				return
			}
			switch et := i.(type) {

			case *engSealTask:

				// All nodes that are mining (started with --mine) will issue
				// seal requests. RRR decides which of those are endorsers and
				// which are leader candidates.
				if roundState != RoundStateLeaderCandidate {
					e.logger.Debug("RoRoRo engSealTask - non-leader ignoring", "round", roundNumber)
					continue
				}

				e.logger.Info("RoRoRo engSealTask", "round", roundNumber)

				if err := e.refreshSealTask(et); err != nil {
					e.logger.Info("RoRoRo engSealTask - refreshSealTask", "err", err)
					continue
				}
				if err := e.broadcastCurrentIntent(); err != nil {
					e.logger.Info("RoRoRo engSealTask - broadcastCurrentIntent", "err", err)
				}
				// intent -> leader candidates

			case *engSignedIntent:

				// endorser <- intent from leader candidate

				if roundState != RoundStateEndorserCommittee {
					// This is un-expected. Likely late, or possibly from
					// broken node
					e.logger.Debug("RoRoRo non-endorser ignoring engSignedIntent", "round", roundNumber)
					continue
				}

				e.logger.Info("RoRoRo run got engSignedIntent",
					"round", e.RoundNumber(),
					"candidate-round", et.RoundNumber,
					"candidate", et.NodeID.Hex(), "parent", et.ParentHash.Hex())
				if err := e.handleIntent(et); err != nil {
					e.logger.Info("RoRoRo run handleIntent", "err", err)
				}

			case *engSignedEndorsement:

				// leader <- endorsment from committee

				if roundState != RoundStateLeaderCandidate {
					// This is un-expected. Likely late, or possibly from
					// broken node
					e.logger.Debug("RoRoRo non-leader ignoring engSignedEndorsement", "round", roundNumber)
					continue
				}

				e.logger.Info("RoRoRo run got engSignedEndorsement",
					"round", e.RoundNumber(),
					"endorser", hex.EncodeToString(et.EndorserID[:]),
					"intent", hex.EncodeToString(et.IntentHash[:]))
				if err := e.handleEndorsement(et); err != nil {
					e.logger.Info("rororo run handleIntent", "err", err)
				}

			default:
				e.logger.Info("rororo engine.run received unknown type", "v", i)
			}

		case <-roundTick.C:
			var confirmed bool
			var err error

			if roundState != RoundStateLeaderCandidate {
				e.logger.Debug("RoRoRo run is awake - endorsing")
				continue
			}
			e.logger.Debug("RoRoRo run is awake - leader candidate")

			if confirmed, err = e.sealCurrentBlock(); err != nil {
				e.logger.Info("RoRoRo sealCurrentBlock", "err", err)
				continue
			}
			if !confirmed {
				if err = e.refreshSealTask(nil); err != nil {
					e.logger.Info("RoRoRo refresing seal task", "err", err)
				}
				if err = e.broadcastCurrentIntent(); err != nil {
					e.logger.Info("RoRoRo broadcasting intent", "err", err)
				}
			}
			if confirmed {
				e.logger.Info("RoRoRo sealed block", "round", roundNumber)
			}
		}
	}
}

func (e *engine) handleIntent(et *engSignedIntent) error {

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
	if recoveredNodeID != et.NodeID {
		return errIntentSigInconsistent
	}

	// Check that the intent comes from a node we have selected locally as a
	// leader candidate.
	intenderAddr := et.NodeID.Address()
	if !e.candidates[common.Address(intenderAddr)] {
		e.logger.Info("RoRoRo endorser leader selection excludes intent", "intent-nodeid", intenderAddr.Hex())
		return errIntentNotFromLeader
	}

	c := &SignedEndorsement{
		Endorsement: Endorsement{
			ChainID:    e.genesisEx.ChainID,
			EndorserID: e.nodeID,
		},
	}
	c.IntentHash, err = et.SignedIntent.Hash()

	// Note: by including the senders sequence, and remembering that the sender
	// will be changing the round also, we can be sure we will reply even if
	// the intent is otherwise a duplicate.
	rmsg := &RMsg{Code: RMsgConfirm, Seq: et.Seq}
	rmsg.Raw, err = c.SignedEncode(e.privateKey)
	if err != nil {
		e.logger.Info("RoRoRo encoding SignedEndorsement", "err", err.Error())
		return err
	}
	msg, err := rlp.EncodeToBytes(rmsg)
	if err != nil {
		e.logger.Info("RoRoRo encoding RMsgConfirm", "err", err.Error())
		return err
	}

	e.logger.Info("RoRoRo sending confirmation",
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
		e.logger.Info("RoRoRo confirmation stale or un-solicited, no current intent",
			"endid", et.Endorsement.EndorserID.Hex(), "hintent", et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	pendingIntentHash, err := e.intent.SI.Hash()
	if err != nil {
		return err
	}

	if pendingIntentHash != et.SignedEndorsement.IntentHash {
		e.logger.Info("RoRoRo confirmation for stale or unknown intent",
			"pending", pendingIntentHash.Hex(),
			"received", et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	// Endorsements is a slice whose backing array is pre allocated to the
	// quorum size
	if uint64(len(e.intent.Endorsements)) >= e.config.EndorsersQuorum {
		e.logger.Info("RoRoRo confirmation redundant, have quorum",
			"endid", et.Endorsement.EndorserID.Hex(), et.SignedEndorsement.IntentHash.Hex(),
			"hintent", et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	// Check the confirmation came from an endorser selected by this node for
	// the current round
	endorserAddr := common.Address(et.SignedEndorsement.EndorserID.Address())
	if !e.endorsers[endorserAddr] {
		e.logger.Info("RoRoRo confirmation from unexpected endorser", "endorser", et.Endorsement.EndorserID[:])
		return nil
	}

	// Check the confirmation is not from an endorser that has endorsed our
	// intent already this round.
	if e.intent.Endorsers[endorserAddr] {
		e.logger.Info("RoRoRo redundant confirmation from endorser", "endorser", et.Endorsement.EndorserID[:])
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
		e.logger.Debug("RoRoRo no outstanding intent")
		return false, nil
	}

	if len(e.intent.Endorsements) == 0 {
		e.logger.Debug("RoRoRo no endorsments received")
		return false, nil
	}

	if len(e.intent.Endorsements) != int(e.config.EndorsersQuorum) {
		got := len(e.intent.Endorsements)
		e.logger.Info("RoRoRo insuffcient endorsers to become leader",
			"q", int(e.config.EndorsersQuorum), "got", got, "ends", len(e.endorsers))
		return false, nil
	}
	e.logger.Info("RoRoRo confirmed as leader",
		"q", int(e.config.EndorsersQuorum), "got", len(e.intent.Endorsements),
		"ends", len(e.endorsers))

	if e.sealTask == nil {
		e.logger.Info("RoRoRo seal task canceled or discarded")
		return false, nil
	}

	if e.sealTask.Canceled() {
		e.logger.Info("RoRoRo seal task canceled")
		return false, nil
	}

	// Complete the seal, block will be rejected if this is wrong, no need to
	// double up on checks here.
	header := e.sealTask.Block.Header()

	data := &SignedExtraData{
		ExtraData: ExtraData{
			Intent:  e.intent.SI.Intent,
			Confirm: make([]Endorsement, len(e.intent.Endorsements)),
		},
		// XXX: TODO enrolments,
		// XXX: TODO seed
		// XXX: TODO seed proof
	}
	for i, c := range e.intent.Endorsements {
		data.Confirm[i] = c.Endorsement
	}
	seal, err := data.SignedEncode(e.privateKey)
	if err != nil {
		return false, err
	}

	header.Extra = append(header.Extra[:RoRoRoExtraVanity], []byte(seal)...)

	e.sealTask.Results <- e.sealTask.Block.WithSeal(header)
	e.sealTask = nil
	e.intent = nil

	// XXX: TODO decide if legitimate leader candidate and if in correct phase

	return true, nil
}

func (e *engine) nextRound(head *types.Block) (RoundState, *big.Int) {

	e.roundNumberC.L.Lock()

	e.roundNumber = big.NewInt(0).Set(head.Number())
	e.roundNumber.Add(e.roundNumber, big.NewInt(1))
	roundNumber := big.NewInt(0).Set(e.roundNumber)

	e.roundNumberC.L.Unlock()
	e.roundNumberC.Broadcast()

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	// If we are a leader candidate we need to broadcast an intent.
	e.candidates, e.endorsers = e.selectCandidatesAndEndorsers()
	e.logger.Info("RoRoRo selection updated", "cans", len(e.candidates), "ends", len(e.endorsers))
	if !e.candidates[e.nodeAddr] {
		if !e.endorsers[e.nodeAddr] {
			e.logger.Info("RoRoRo not a candidate leader or endorser")
			return RoundStateActive, roundNumber // XXX: everyone is considered active for now
		}
		e.logger.Info("RoRoRo endorser committee")
		return RoundStateEndorserCommittee, roundNumber
	}
	e.intent = nil

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
			e.logger.Info("RoRoRo refreshSealTask", "hseal", "none")
			return nil
		}
		et = e.sealTask
		e.logger.Info("RoRoRo refreshSealTask", "hseal", hseal, "hmsg", hmsg)
	}

	if et.Canceled() {
		e.logger.Info("RoRoRo refreshSealTask - cancelled", "hseal", hseal, "hmsg", hmsg)
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
				e.logger.Debug("RoRoRo refreshSealTask - re-issue preserving endorsements")
			}
			for _, end := range newIntent.Endorsements {
				newIntent.Endorsers[common.Address(end.EndorserID.Address())] = true
			}
		}
		e.logger.Info("RoRoRo refreshSealTask - no change", "hseal", hseal, "hmsg", hmsg)
	} else {
		e.logger.Info("RoRoRo refreshSealTask - new intent")
	}
	e.intent = newIntent
	e.intentMsgHash = newIntentHash

	e.logger.Info("RoRoRo refreshSealTask - current intent",
		"ends", len(newIntent.Endorsers), "cons", len(newIntent.Endorsements),
		"hseal", newIntent.SealHash.Hex(), "hmsg", e.intentMsgHash.Hex(),
	)

	return nil
}

func (e *engine) newPendingIntent(et *engSealTask, seq uint) (*pendingIntent, error) {

	var err error

	e.logger.Info("RoRoRo newPendingIntent",
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
		e.logger.Info("RoRoRo encoding RMsgIntent", "err", err.Error())
		return nil, err
	}

	pe.Endorsements = make([]*SignedEndorsement, 0, e.config.EndorsersQuorum)
	pe.Endorsers = make(map[common.Address]bool)

	return pe, nil
}

// selectCandidatesAndEndorsers determines if the current node is a leader
// candidate and what the current endorsers are
func (e *engine) selectCandidatesAndEndorsers() (map[common.Address]bool, map[common.Address]bool) {

	// XXX: This must ultimately to SelectCandiates AND SelectEndorsers then
	// decide if the current node is in the results of SelectCandatates

	// XXX: TODO active endorsers/leaders. To get going, return everyone in
	// the genesis extradata  except the local node

	// XXX: fixed leader until we get the endorsments working

	endorsers := map[common.Address]bool{}
	for i, en := range e.genesisEx.IdentInit {
		addr := common.Address(en.U.Address())
		if i == 0 {
			continue
		}
		endorsers[addr] = true
	}

	// XXX: leader is first genesis node for now
	candidates := map[common.Address]bool{}
	candidates[common.Address(e.genesisEx.IdentInit[0].U.Address())] = true

	return candidates, endorsers
}

// broadcastCurrentIntent gossips the signed intent for the currently pending
// seal task. It does this un-conditionally. It is the callers responsibility to
// call this from the right consensus engine state - including establishing if
// the node is a legitemate leader candidate.
func (e *engine) broadcastCurrentIntent() error {

	e.intentMu.Lock()
	if e.intent == nil {
		e.intentMu.Unlock()
		e.logger.Debug("RoRoRo broadcastCurrentIntent - no intent")
		return nil
	}

	msg := e.intent.Msg
	endorsers := e.broadcaster.FindPeers(e.endorsers)
	e.logger.Info("RoRoRo BroadcastCurrentIntent", "endorsers", len(e.endorsers), "online", len(endorsers))
	e.intentMu.Unlock()

	if len(endorsers) == 0 {
		return nil
	}
	return e.Broadcast(e.nodeAddr, endorsers, msg)
}
