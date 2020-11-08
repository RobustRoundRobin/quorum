package rororo

// engine methods for activities descendent to the run() method

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	lru "github.com/hashicorp/golang-lru"
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
}

type engSignedEndorsement struct {
	SignedEndorsement
	Pub        []byte // Derived from signature
	ReceivedAt time.Time
}

type pendingIntent struct {
	Candidate    bool
	SI           *SignedIntent
	SealHash     Hash
	MsgHash      Hash
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
	RoundStateIntentPhase
	// The endorsers must pick the oldest candidate *seen* in the intent phase.
	RoundStateEndorsePhase
	RoundStateBroadcastBlockPhase
)

func (e *engine) run(
	currentBlock func() *types.Block,
	hasBadBlock func(hash common.Hash) bool, ch <-chan interface{}) {

	defer e.runningWG.Done()
	e.runningWG.Add(1)

	roundTick := time.NewTicker(time.Duration(e.config.RoundLength) * time.Millisecond)
	// Endorsed leader candidates will broadcast the new block at the end of
	// the round according to their tickers. We reset the ticker each time we
	// see a new block confirmed. This will cause all participants to loosely
	// align on the same time window for each round. In the absence of
	// communication, each node will simply initiate a new round.

	for {
		select {
		case i, ok := <-ch:
			if !ok {
				e.logger.Info("rororo engine.run input channel closed")
				return
			}
			switch et := i.(type) {
			case *engSealTask:
				e.logger.Info("RoRoRo run got engSealTask", "round", e.RoundNumber())
				// XXX: TODO decide if legitimate leader candidate and if in correct phase
				if err := e.handleSealTask(et); err != nil {
					// There is no value I can see in posting nil back to the
					// et.Results channel, it just gets ignored by the
					// miner/worker resultLoop.
					e.logger.Info("rororo run handleSealTask", "err", err)
				}
			case *engSignedIntent:

				e.logger.Info("RoRoRo run got engSignedIntent",
					"round", e.RoundNumber(),
					"candidate-round", et.RoundNumber,
					"candidate", hex.EncodeToString(et.NodeID[:]),
					"parent", hex.EncodeToString(et.ParentHash[:]))
				if err := e.handleIntent(et); err != nil {
					e.logger.Info("rororo run handleIntent", "err", err)
				}

			case *engSignedEndorsement:
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
			e.completeRound()
			e.nextRound()
			e.refreshSealTask(nil)
			e.broadcastCurrentIntent()
		}
	}
}

func (e *engine) handleSealTask(et *engSealTask) error {

	if err := e.refreshSealTask(et); err != nil {
		return err
	}
	// XXX: TODO decide if legitimate leader candiate and if in correct phase
	return e.broadcastCurrentIntent()
}

func (e *engine) handleIntent(et *engSignedIntent) error {

	var err error

	// XXX: we could track the highest round we have seen and the number of
	// intents issued for it. This would allow us a consensus based approach to
	// synchronising the rounds without having to wait for a block to be mined.

	// If this node is not selected as an endorser this round, there is nothing
	// to do here
	if !e.endorsers[e.nodeAddr] {
		e.logger.Debug("RoRoRo ignoring intent as not a selected endorser")
		return nil
	}

	// XXX: TODO Do we agree that the intendee is next in line and that their
	// intent is appropriate ?

	// Endorse everything for now
	c := &SignedEndorsement{
		Endorsement: Endorsement{
			ChainID:    e.genesisEx.ChainID,
			EndorserID: e.nodeID,
		},
	}
	c.IntentHash, err = et.SignedIntent.Hash()

	rmsg := &RMsg{Code: RMsgConfirm}
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
		"candidate", hex.EncodeToString(et.SignedIntent.NodeID[:]),
		"endorser", hex.EncodeToString(e.nodeID[:]))

	// find the peer candidate
	return e.Send(common.Address(et.SignedIntent.NodeID.Address()), msg)
}

func (e *engine) handleEndorsement(et *engSignedEndorsement) error {

	if et.Endorsement.ChainID != e.genesisEx.ChainID {
		return fmt.Errorf("confirmation received for wrong chainid: %s", hex.EncodeToString(et.Endorsement.ChainID[:]))
	}

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	pendingIntentHash, err := e.intent.SI.Hash()
	if err != nil {
		return err
	}

	if et.SignedEndorsement.IntentHash != et.SignedEndorsement.IntentHash {
		e.logger.Info("RoRoRo confirmation for unknown intent",
			"pending", hex.EncodeToString(pendingIntentHash[:]),
			"received", hex.EncodeToString(et.SignedEndorsement.IntentHash[:]))
		return nil
	}

	// Endorsements is a slice whose backing array is pre allocated to the
	// quorum size
	if uint64(len(e.intent.Endorsements)) >= e.config.EndorsersQuorum {
		e.logger.Info("RoRoRo confirmation redundant, have quorum", "endorser", et.Endorsement.EndorserID[:])
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

// completeRound
func (e *engine) completeRound() error {

	e.intentMu.Lock()
	defer e.intentMu.Unlock()
	if e.intent == nil || len(e.intent.Endorsements) == 0 || len(e.intent.Endorsements) != int(e.config.EndorsersQuorum) {
		if e.candidates[e.nodeAddr] {
			e.logger.Debug("RoRoRo not a leader candidate, nothing to do")
		}
		got := 0
		if e.intent != nil {
			got = len(e.intent.Endorsements)
		}
		e.logger.Info("RoRoRo insuffcient endorsers to become leader", "q", int(e.config.EndorsersQuorum), "got", got, "ends", len(e.endorsers))
		return nil
	}
	e.logger.Info("RoRoRo confirmed as leader", "q", int(e.config.EndorsersQuorum), "got", len(e.intent.Endorsements), "ends", len(e.endorsers))

	if e.sealTask == nil {
		e.logger.Info("RoRoRo seal task canceled or discarded")
		return nil
	}

	if e.sealTask.Canceled() {
		e.logger.Info("RoRoRo seal task canceled")
		return nil
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
		return err
	}

	header.Extra = append(header.Extra[:RoRoRoExtraVanity], []byte(seal)...)

	e.sealTask.Results <- e.sealTask.Block.WithSeal(header)
	e.sealTask = nil

	// XXX: TODO decide if legitimate leader candidate and if in correct phase

	return nil
}

func (e *engine) nextRound() error {

	e.roundNumberC.L.Lock()
	e.roundNumber.Add(e.roundNumber, big.NewInt(1))
	e.logger.Debug("RoRoRo new round", "round", e.roundNumber)
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
			return nil
		}
		e.logger.Info("RoRoRo candidate endorser")
		return nil
	}

	return nil
}

// refreshSealTask will issue the provided seal task if et is not nil.
// Otherwise it will re-issue the existing seal task. If the round hasn't
// changed since the seal task was originally issued this will have no effect.
func (e *engine) refreshSealTask(et *engSealTask) error {

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	// Reconcile whether to re-issue current seal task
	if et == nil {
		if e.sealTask == nil {
			e.logger.Info("RoRoRo reissueSealTask", "hseal", "none")
			return nil
		}
		et = e.sealTask
		// note it is a bug in this function if intent is nil at this point
		e.logger.Info(
			"RoRoRo reissueSealTask", "hseal", hex.EncodeToString(e.intent.SealHash[:]),
			"hmsg", hex.EncodeToString(e.intent.MsgHash[:]))
	}

	// these are just for telemetry
	hseal, hmsg := "nil", "nil"
	if e.intent != nil {
		hseal = hex.EncodeToString(e.intent.SealHash[:])
		hmsg = hex.EncodeToString(e.intent.MsgHash[:])
	}

	if et.Canceled() {
		e.logger.Info("RoRoRo handleSealTask cancelled", "hseal", hseal, "hmsg", hmsg)
		return nil
	}

	// IF THIS NODE IS A CANDIDATE Drop the current intent if there is one and
	// its different. It is not clear yet whether we need this accommodation
	// for re-issuing duplicate intents

	newIntent, err := e.newPendingIntent(et)
	if err != nil {
		return err
	}

	// There is no need to send nil to Results on the previous task, the geth
	// miner worker can't do anything with that information
	e.sealTask = et

	if e.intent != nil && e.candidates[e.nodeAddr] {

		if e.intent.MsgHash == newIntent.MsgHash {
			e.logger.Info("RoRoRo reissueSealTask no change", "hseal", hseal, "hmsg", hmsg)
			return nil
		}
		e.logger.Info("RoRoRo droping pending intent",
			"ends", len(e.intent.Endorsers), "cons", len(e.intent.Endorsements),
			"hseal", hseal,
			"hmsg", hex.EncodeToString(e.intent.MsgHash[:]),
		)
	}

	e.intent = newIntent

	e.logger.Info("RoRoRo new pending intent",
		"ends", len(e.intent.Endorsers), "cons", len(e.intent.Endorsements),
		"hseal", hex.EncodeToString(e.intent.SealHash[:]),
		"hmsg", hex.EncodeToString(e.intent.MsgHash[:]),
	)

	return nil
}

func (e *engine) newPendingIntent(et *engSealTask) (*pendingIntent, error) {

	var err error

	pe := &pendingIntent{}

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
	rmsg := &RMsg{Code: RMsgIntent}
	rmsg.Raw, err = pe.SI.SignedEncode(e.privateKey)
	if err != nil {
		return nil, err
	}

	if pe.Msg, err = rlp.EncodeToBytes(rmsg); err != nil {
		e.logger.Info("RoRoRo encoding RMsgIntent", "err", err.Error())
		return nil, err
	}
	pe.MsgHash = Keccak256Hash(pe.Msg)

	// XXX: temporary while we are evolving the implementation, its clearly a
	// violation of the security model.
	pe.Endorsements = make([]*SignedEndorsement, 0, e.config.EndorsersQuorum)
	pe.Endorsers = make(map[common.Address]bool)

	// pe.EndorserPeers = make(map[common.Address]consensus.Peer)

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

// recalCandidatesAndEndorsers returns the candidates and endorsers for the
// requested round.
func (e *engine) recalCandidatesAndEndorsers(round *big.Int) (map[common.Address]bool, map[common.Address]bool) {
	// XXX: we are not round anything yet, so cheat
	return e.selectCandidatesAndEndorsers()
}

// broadcastCurrentIntent gossips the signed intent for the currently pending
// seal task. It does this un-conditionally. It is the callers responsibility to
// call this from the right consensus engine state - including establishing if
// the node is a legitemate leader candidate.
func (e *engine) broadcastCurrentIntent() error {

	e.intentMu.Lock()
	if e.intent == nil {
		e.intentMu.Unlock()
		return nil
	}

	// If we are not a current candiate, then we have no intent
	if !e.candidates[e.nodeAddr] {
		e.intentMu.Unlock()
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

func (e *engine) Send(peerAddr common.Address, msg []byte) error {

	msgHash := Keccak256Hash(msg)

	peers := e.broadcaster.FindPeers(map[common.Address]bool{peerAddr: true})
	if len(peers) != 1 {
		return fmt.Errorf("RoRoRo no peer connection for received Intent")
	}
	peer := peers[peerAddr]
	if peer == nil {
		return fmt.Errorf("internal error, FindPeers returning unasked for peer")
	}
	return e.peerSend(peer, peerAddr, msg, msgHash)
}

// Broadcast the message to the provided peers, skipping self.
func (e *engine) Broadcast(self common.Address, peers map[common.Address]consensus.Peer, msg []byte) error {

	msgHash := Keccak256Hash(msg)
	// e.logger.Debug("RoRoRo messaging broadcasting msg", "hash", hex.EncodeToString(msgHash[:]))

	for peerAddr, peer := range peers {

		if peerAddr == self {
			e.logger.Info("skipping self")
			continue
		}

		if err := e.peerSend(peer, peerAddr, msg, msgHash); err != nil {
			e.logger.Info("RoRoRo error sending msg", "err", err, "peer", peerAddr)
		}
	}
	return nil
}

func (e *engine) peerSend(peer consensus.Peer, peerAddr common.Address, msg []byte, msgHash Hash) error {

	e.messagingMu.Lock()
	defer e.messagingMu.Unlock()

	var msgs *lru.ARCCache
	if i, ok := e.peerMessages.Get(peerAddr); ok {
		msgs = i.(*lru.ARCCache) // panic if we have put the wrong type in the cache
		if _, k := msgs.Get(msgHash); k {
			// have already sent the message to, or received it from, this peer
			return nil
		}
	} else {
		msgs, _ = lru.NewARC(lruMessages)
	}
	msgs.Add(msgHash, true)
	e.peerMessages.Add(peerAddr, msgs)

	// Send will error imediately on encoding problems. But otherwise it
	// will block until the receiver consumes the message or the send times
	// out. So we can not sensibly collect errors.
	go peer.Send(rororoMsg, msg)
	return nil
}

// BroadcastStale returns true if the hash matches a message knowing to have been
// sent to or received from peer. The 'knowning' is based on an ARC cache, so
// over time we will forget.
func (e *engine) BroadcastStale(peerAddr common.Address, hash Hash) bool {
	e.messagingMu.RLock()
	defer e.messagingMu.RUnlock()

	i, ok := e.peerMessages.Get(peerAddr)
	if !ok {
		return false
	}

	msgs, _ := i.(*lru.ARCCache)
	if _, ok := msgs.Get(hash); ok {
		return true
	}
	return false
}
