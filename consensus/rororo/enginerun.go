package rororo

// engine methods for activities descendent to the run() method

import (
	"encoding/hex"
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

type pendingIntent struct {
	SI            *SignedIntent
	SealHash      Hash
	MsgHash       Hash
	Msg           []byte
	Confirmations []*SignedConfirmation
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
	chain consensus.ChainReader,
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
				e.logger.Info("rororo run got seal task")
				// XXX: TODO decide if legitimate leader candidate and if in correct phase
				if err := e.handleSealTask(et); err != nil {
					// There is no value I can see in posting nil back to the
					// et.Results channel, it just gets ignored by the
					// miner/worker resultLoop.
					e.logger.Info("rororo run handleSealTask", "err", err)
				}
			default:
				e.logger.Info("rororo engine.run received unknown type", "v", i)
			}

		case <-roundTick.C:
			e.roundNumberC.L.Lock()
			e.roundNumber.Add(e.roundNumber, big.NewInt(1))
			e.logger.Debug("RoRoRo new round", "round", e.roundNumber)
			e.roundNumberC.L.Unlock()
			e.roundNumberC.Broadcast()
			// XXX: TODO decide if legitimate leader candidate and if in correct phase
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

	newIntent, err := e.newPendingIntent(et)
	if err != nil {
		return err
	}

	// There is no need to send nil to Results on the previous task, the geth
	// miner worker can't do anything with that information
	e.sealTask = et

	// Drop the current intent if there is one and its different. It is not
	// clear yet whether we need this accommodation for re-issuing duplicate
	// intents
	if e.intent != nil {
		if e.intent.MsgHash == newIntent.MsgHash {
			e.logger.Info("RoRoRo reissueSealTask no change", "hseal", hseal, "hmsg", hmsg)
			return nil
		}
		e.logger.Info("RoRoRo droping pending intent",
			"hseal", hseal,
			"hmsg", hex.EncodeToString(e.intent.MsgHash[:]),
			"ends", len(e.intent.Endorsers),
			"cons", len(e.intent.Confirmations),
		)
	}

	e.intent = newIntent

	e.logger.Info("RoRoRo new pending intent",
		"hseal", hex.EncodeToString(e.intent.SealHash[:]),
		"hmsg", hex.EncodeToString(e.intent.MsgHash[:]),
		"ends", len(e.intent.Endorsers),
		"cons", len(e.intent.Confirmations),
	)

	return nil
}

func (e *engine) newPendingIntent(et *engSealTask) (*pendingIntent, error) {

	var err error
	pe := &pendingIntent{
		SealHash: Hash(sealHash(et.Block.Header())),
	}

	// The intent that would need to be confirmed by 'q' endorsers in order for
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
	rmsg.Raw, err = pe.SI.EncodeSigned(e.privateKey)
	if err != nil {
		return nil, err
	}

	if pe.Msg, err = rlp.EncodeToBytes(rmsg); err != nil {
		e.logger.Info("RoRoRo encoding RMsgIntent", "err", err.Error())
		return nil, err
	}
	pe.MsgHash = Keccak256Hash(pe.Msg)

	pe.Endorsers = e.currentEndorsers()

	// XXX: temporary while we are evolving the implementation, its clearly a
	// violation of the security model.
	q := e.config.EndorserQuorum
	if uint64(len(pe.Endorsers)) < q {
		q = uint64(len(pe.Endorsers))
	}

	pe.Confirmations = make([]*SignedConfirmation, 0, q)

	// pe.EndorserPeers = make(map[common.Address]consensus.Peer)

	return pe, nil
}

// GossipStale returns true if the hash matches a message knowing to have been
// sent to or received from peer. The 'knowning' is based on an ARC cache, so
// over time we will forget.
func (e *engine) GossipStale(peerAddr common.Address, hash Hash) bool {
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

// currentEndorsers returns the most recently evaluated endorser list. No
// effort is made to check whether it is valid for the current round.
func (e *engine) currentEndorsers() map[common.Address]bool {

	// XXX: TODO active endorsers/leaders. To get going, return everyone in
	// the genesis extradata  except the local node

	selfAddr := common.Address(e.nodeID.Address())
	addresses := map[common.Address]bool{}
	for _, en := range e.genesisEx.IdentInit {
		addr := common.Address(en.U.Address())
		if addr == selfAddr {
			continue
		}
		addresses[addr] = true
	}
	return addresses
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

	// The Endorsers map is not changed after the intent is created so
	// borrowing the reference is safe.
	addresses := e.intent.Endorsers
	msg := e.intent.Msg
	e.intentMu.Unlock()

	endorsers := e.broadcaster.FindPeers(addresses)
	e.logger.Info("RoRoRo BroadcastCurrentIntent", "endorsers", len(addresses), "online", len(endorsers))
	if len(endorsers) == 0 {
		return nil
	}
	return e.Gossip(common.Address(e.nodeID.Address()), endorsers, msg)
}

// Gossip the message to the provided peers, skipping self.
func (e *engine) Gossip(self common.Address, peers map[common.Address]consensus.Peer, msg []byte) error {

	e.messagingMu.Lock()
	defer e.messagingMu.Unlock()

	// XXX: todo the IBFT implementation rlp encoded msg before taking the
	// hash. Unless it was required to cannonicalise the bytes, I can't see any
	// reason for that. Lets find out ...
	hash := Keccak256(msg)
	e.logger.Debug("RoRoRo messaging broadcasting msg", "hash", hex.EncodeToString(hash[:]))

	for peerAddr, peer := range peers {

		if peerAddr == self {
			e.logger.Info("skipping self")
			continue
		}

		var msgs *lru.ARCCache
		if i, ok := e.peerMessages.Get(peerAddr); ok {
			msgs, _ = i.(*lru.ARCCache)
			if _, k := msgs.Get(hash); k {
				// have already sent the message to, or received it from, this peer
				continue
			}
		} else {
			msgs, _ = lru.NewARC(lruMessages)
		}
		msgs.Add(hash, true)
		e.peerMessages.Add(peerAddr, msgs)

		// Send will error imediately on encoding problems. But otherwise it
		// will block until the receiver consumes the message or the send times
		// out. So we can not sensibly collect errors.
		go peer.Send(rororoMsg, msg)
	}
	return nil
}
