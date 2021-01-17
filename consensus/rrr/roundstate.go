package rrr

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// RRRState type for the round state
type RRRState int

// RoundPhase is the type for the round phase
type RoundPhase int

const (
	// RRRStateInvalid is the invalid and never set state
	RRRStateInvalid RRRState = iota
	// RRRStateNeedBlock is entered if the current block doesn't 'make sense'.
	// We should not ever receive invalid blocks if VerifyHeaders is working,
	// but this is our backstop. The node will not progress until it sees a new
	// node from the network.
	RRRStateNeedBlock
	// RRRStateInactive is set if the node is not in the active selection for the round.
	RRRStateInactive // Indicates conditions we expect to be transitor - endorsers not online etc

	// RRRStateNodeStarting is used to defer the processing of the head block until
	// there has been a chance for one to arrive from the network
	RRRStateNodeStarting

	// RRRStateActive is entered if the node is active but is not selected as
	// either a leader or an endorser
	RRRStateActive // Has endorsed or mined in some time in the last Ta rounds.

	// RRRStateLeaderCandidate selected as leader candidate for current round
	RRRStateLeaderCandidate
	// RRRStateEndorserCommittee Is in the endorser committee for the current round.
	RRRStateEndorserCommittee
)

const (
	// RoundPhaseInvalid is the invalid state for RoundPhase
	RoundPhaseInvalid RoundPhase = iota
	// RoundPhaseIntent During the Intent phase, the endorser committee is
	// allowing for intents to arrive so they can, with high probability, pick
	// the oldest active leader candidate.
	RoundPhaseIntent
	// RoundPhaseConfirm During the confirmation phase leaders are waiting for
	// all the endorsements to come in so they fairly represent activity.
	RoundPhaseConfirm
)

// The engine supplies these so that the roundstate can call out to the network at the right points.
type broadcaster interface {
	// FindPeers peers
	FindPeers(map[common.Address]bool) map[common.Address]consensus.Peer
	// Broadcast self, peers, msg
	Broadcast(common.Address, map[common.Address]consensus.Peer, []byte) error

	// SendSignedEndorsement ...
	SendSignedEndorsement(intenderAddr Address, et *engSignedIntent) error
}

// RoundState is used to mange the round state for the RRR consensus engine.
type RoundState struct {
	logger log.Logger

	config     *Config
	genesisEx  GenesisExtraData
	ChainID    Hash
	privateKey *ecdsa.PrivateKey
	nodeID     Hash // derived from privateKey
	nodeAddr   common.Address

	T              *RoundTime
	Rand           *rand.Rand
	Phase          RoundPhase
	State          RRRState
	Number         *big.Int
	FailedAttempts uint

	OnlineEndorsers map[common.Address]consensus.Peer

	// These get updated each round on all nodes without regard to which are
	// leaders/endorsers or participants.
	selection  []common.Address
	endorsers  map[common.Address]bool
	candidates map[common.Address]bool

	intentMu sync.Mutex
	sealTask *engSealTask
	intent   *pendingIntent

	// On endorsing nodes, keep the oldest signed intent we have seen during
	// the intent phase, until the end of the phase or until we see an intent
	// from the oldest candidate.
	signedIntent *engSignedIntent

	a *ActiveSelection
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

// NewRoundState creates and initialises a RoundState
func NewRoundState(key *ecdsa.PrivateKey, config *Config, logger log.Logger) *RoundState {

	s := &RoundState{
		logger:     logger,
		privateKey: key,
		nodeID:     Pub2NodeID(&key.PublicKey),
		nodeAddr:   crypto.PubkeyToAddress(key.PublicKey),
		config:     config,
		T:          NewRoundTime(config.RoundLength, config.ConfirmPhase, logger),
	}
	return s
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have. For rrr this is just the round number
func (r *RoundState) CalcDifficulty(nodeAddr common.Address) *big.Int {
	r.logger.Debug("RRR CalcDifficulty")

	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	if r.candidates[nodeAddr] {
		return difficultyForCandidate
	}
	return difficultyForEndorser
}

// CheckGenesis checks that the RRR consensus configuration in the genesis block
// is correct.
func (r *RoundState) CheckGenesis(chain RRRChainReader) error {

	hg := chain.GetHeaderByNumber(0)
	if hg == nil {
		return errNoGenesisHeader
	}

	if r.genesisEx.ChainID == zeroHash {
		// geth warmup will call VerifyBranchHeaders on the genesis block
		// before doing anything else. This guard simply avoids an anoying and
		// redundant log message, whilst also guarding against changes in the
		// geth implementation outside of our control.
		r.logger.Info("RRR CheckGenesis", "extra", hex.EncodeToString(hg.Extra))
		err := rlp.DecodeBytes(hg.Extra, &r.genesisEx)
		if err != nil {
			return err
		}
	}

	// All of the enrolments in the genesis block are signed by the long term
	// identity key (node key) of the genesis node.

	genPub, err := Ecrecover(r.genesisEx.IdentInit[0].U[:], r.genesisEx.IdentInit[0].Q[:])
	if err != nil {
		return fmt.Errorf("%v:%w", err, errGensisIdentitiesInvalid)
	}
	genID := Hash{}
	copy(genID[:], Keccak256(genPub[1:65]))

	r.logger.Debug("RRR CheckGenesis", "genid", genID.Hex(), "genpub", hex.EncodeToString(genPub))

	// We require the identity that signed the gensis block to also be enrolled
	// in the block.
	var foundGenesisSigner bool
	for _, en := range r.genesisEx.IdentInit {
		if en.ID == genID {
			foundGenesisSigner = true
			break
		}
	}
	if !foundGenesisSigner {
		return fmt.Errorf("genid=`%s':%w", genID.Hex(), errGensisIdentityNotEnroled)
	}
	return nil
}

// PrimeActiveSelection should be called for engine Start
func (r *RoundState) PrimeActiveSelection(chain RRRChainReader) error {

	if err := r.CheckGenesis(chain); err != nil {
		return err
	}

	if r.a != nil {
		r.a.Prime(r.config.Activity, chain.CurrentBlock())
		return nil
	}

	r.a = &ActiveSelection{logger: r.logger}
	r.a.Reset(r.config.Activity, chain.CurrentBlock())

	return nil
}

// NewSignedIntent keeps track of the oldest intent seen in a round. At the end
// of the intent phase (in PhaseTick), if the node is an endorser, an endorsment
// is sent to the oldest seen. Only the most recent intent from any identity
// counts.
func (r *RoundState) NewSignedIntent(et *engSignedIntent) {
	// endorser <- intent from leader candidate
	if r.State == RRRStateNodeStarting {
		r.logger.Trace("RRR engSignedIntent - node starting, ignoring", "et.round", et.RoundNumber)
		return
	}
	if r.State == RRRStateNeedBlock {
		r.logger.Trace("RRR engSignedIntent - need block, ignoring", "et.round", et.RoundNumber)
		return
	}
	// See RRR-spec.md for a more thorough explanation, and for why we don't
	// check the round phase or whether or not we - locally - have selected
	// ourselves as an endorser. handleIntent.
	r.logger.Trace("RRR run got engSignedIntent",
		"round", r.Number, "cand-round", et.RoundNumber, "cand-attempts", et.FailedAttempts,
		"candidate", et.NodeID.Hex(), "parent", et.ParentHash.Hex())

	if err := r.handleIntent(et); err != nil {
		r.logger.Info("RRR run handleIntent", "err", err)
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
func (r *RoundState) handleIntent(et *engSignedIntent) error {

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
		r.logger.Info("RRR handleIntent - sender not signer",
			"from-addr", intenderAddr.Hex(), "recovered", recoveredNodeID.Hex(),
			"signed", et.NodeID.Hex())
		return nil
	}

	// Check that the intent round matches our current round.
	if r.Number.Cmp(et.RoundNumber) != 0 {
		r.logger.Info("RRR handleIntent - wrong round",
			"r", r.Number, "ir", et.RoundNumber, "from-addr", intenderAddr.Hex())
		return nil
	}

	// Check that the intent comes from a node we have selected locally as a
	// leader candidate. According to the (matching) roundNumber and their
	// provided value for FailedAttempts
	if !r.a.LeaderForRoundAttempt(
		uint(r.config.Candidates), uint(r.config.Endorsers),
		intenderAddr, et.Intent.FailedAttempts) {
		r.logger.Info(
			"RRR handleIntent - intent from non-candidate",
			"round", r.Number, "cand-f", et.Intent.FailedAttempts, "cand", intenderAddr.Hex())
		return errNotLeaderCandidate
	}

	if r.signedIntent != nil {
		// It must be in the map if it was active, otherwise we have a
		// programming error.
		curAge := r.a.aged[r.signedIntent.NodeID.Address()].Value.(*idActivity).ageBlock
		newAge := r.a.aged[intenderAddr].Value.(*idActivity).ageBlock

		// Careful here, the 'older' block will have the *lower* number
		if curAge.Cmp(newAge) < 0 {
			// current is older
			r.logger.Trace(
				"RRR handleIntent - ignoring intent from younger candidate",
				"cand-addr", intenderAddr.Hex(), "cand-f", et.Intent.FailedAttempts)
			return nil
		}
	}

	// Its the first one, or it is from an older candidate and yet is not the oldest
	r.signedIntent = et
	return nil
}

// broadcastCurrentIntent sends the current intent to all known *online* peers
// selected as endorsers. It does this un-conditionally. It is the callers
// responsibility to call this from the right consensus engine state - including
// establishing if the local node is a legitemate leader candidate.
func (r *RoundState) broadcastCurrentIntent(b broadcaster) {

	r.intentMu.Lock()
	if r.intent == nil {
		r.intentMu.Unlock()
		r.logger.Debug("RRR broadcastCurrentIntent - no intent")
		return
	}

	msg := r.intent.Msg
	r.intentMu.Unlock()

	if len(r.OnlineEndorsers) == 0 {
		return
	}
	err := b.Broadcast(r.nodeAddr, r.OnlineEndorsers, msg)
	if err != nil {
		r.logger.Info("RRR BroadcastCurrentIntent - Broadcast", "err", err)
	}
}
