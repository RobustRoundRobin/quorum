package rororo

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

var (
	// Uncles not relevant outside of PoW
	errInvalidUncleHash        = errors.New("non empty uncle hash")
	errNoGenesisHeader         = errors.New("failed to get genesis header")
	errEndorsersNotQuorate     = errors.New("insufficient endorsers online")
	errP2PMsgInvalidCode       = errors.New("recieved p2p.Msg with unsported code")
	errRMsgInvalidCode         = errors.New("recevived RMsg with invalid code")
	errIncompatibleChainReader = errors.New("chainreader missing required interfaces for RoRoRo")
	errEngineStopped           = errors.New("consensus not running")
	errNotEndorser             = errors.New("expected to be endorser")
	errNotLeaderCandidate      = errors.New("expected to be leader candidate")
	errIntentNotFromLeader     = errors.New("endorser disagrees with intents leadership")
	errIntentSigInconsistent   = errors.New("The node id derived from the intent signature doesn't match the intent nodeid")
	nilUncleHash               = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	emptyNonce = types.BlockNonce{}
	bigOne     = big.NewInt(1)

	// Difficulty is the measure of 'how hard' it is to extend the chain. For
	// PoA, and RRR in particular, this is just an indicator of whose turn it
	// is. Essentially it is always 'harder' for the peers that are currently
	// leader candidates - as they must wait for endorsements. The peers whose
	// turn it is to endorse don't actually publish blocks at all, but we have
	// an endorser difficulty to make sure any transitory local data makes
	// sense.
	difficultyForCandidate = big.NewInt(2)
	difficultyForEndorser  = big.NewInt(1)
)

const (
	NewBlockMsg = 0x07

	RoRoRoExtraVanity = 32
	rororoMsg         = 0x11

	// TODO: probably want this to be driven by Nc, Ne configuration
	lruPeers    = 100 + 6*2
	lruMessages = 1024
)

// RMsgCode identifies the rororo message type. rororoMsg identifies rororo's
// message type to the devp2p layer as being consensus engine specific. Once
// that outer message is delivered to rororo, RMsgCode is how rororo
// differentiates each of its supported message payloads.
type RMsgCode uint

const (
	RMsgInvalid RMsgCode = iota
	RMsgIntent
	RMsgConfirm
)

type RMsg struct {
	Code RMsgCode
	// Seq should be incremented to cause an explicit message resend. It is not
	// used for any other purpose
	Seq uint
	Raw rlp.RawValue
}

// API is a user facing RPC API to dump Istanbul state
type API struct {
	chain  consensus.ChainReader
	rororo *engine
}

type ChainSubscriber interface {
	SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
	SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription
}

// RoRoRoChainReader the implementation of ChainReader passed to Start must
// implement the RoRoRoChainReader interface. This is a run time check to avoid
// import cycles on the core event types
type RoRoRoChainReader interface {
	consensus.ChainReader
	ChainSubscriber
	CurrentBlock() *types.Block
	HasBadBlock(hash common.Hash) bool
}

// engine implements consensus.Engine using Robust Round Robin consensus
// https://arxiv.org/abs/1804.07391
type engine struct {

	// Don't change these while the engine is running
	config     *Config
	privateKey *ecdsa.PrivateKey
	address    common.Address
	logger     log.Logger
	db         ethdb.Database
	genesisEx  GenesisExtraData
	nodeID     Hash // derived from privateKey
	nodeAddr   common.Address

	chain       consensus.ChainReader
	broadcaster consensus.Broadcaster

	// Subscribed in Start, unsubscribed in Stop
	chainHeadSub event.Subscription
	chainHeadCh  chan core.ChainHeadEvent

	// must be held for any interaction with ARCCache *Messages members
	messagingMu sync.RWMutex

	// Track which messages we have sent or received. We do not re-gossip
	// these. (IBFT calls these 'recentMessages'). We maintain a 2 level arc
	// here, for each of lruPeers we have an lru of recent messages.
	peerMessages *lru.ARCCache

	// Track which messages we have posted on our local processing queue. We do
	// not re-broadcast these. We do not re post these locally.
	selfMessages *lru.ARCCache

	runningMu sync.RWMutex // hold read lock if checking 'runningCh is nil'
	runningWG sync.WaitGroup

	// runningCh is passed as the input channel to the engine run() method.
	// The run method assumes the ownership of all values sent to this channel.
	// Handles all of the  eng* types and core.ChainHeadEvent
	runningCh chan interface{}

	roundNumberC  *sync.Cond
	roundNumberMu sync.RWMutex // is held by roundNumberC
	roundNumber   *big.Int

	intentMu      sync.Mutex
	sealTask      *engSealTask
	intentSeq     uint // ensures we re-issue the intent even if the round doesn't change
	intentMsgHash Hash // we remember the most recent intent hash, even if the intent is cleared, to help with telemetry
	intent        *pendingIntent
	// These get updated each round on all nodes without regard to which are
	// leaders/endorsers or participants.
	candidates map[common.Address]bool
	endorsers  map[common.Address]bool
	// Number of endorsers required to confirm an intent.
	quorum int
}

func (e *engine) HexNodeID() string {
	return hex.EncodeToString(e.nodeID[:])
}

func (e *engine) IsRunning() bool {
	e.runningMu.RLock()
	defer e.runningMu.RUnlock()
	return e.runningCh != nil
}

// New create rororo consensus engine
func New(config *Config, privateKey *ecdsa.PrivateKey, db ethdb.Database) consensus.RoRoRo {

	logger := log.New()
	// Only get err from NewRC if zize requested is <=0
	peerMessages, _ := lru.NewARC(lruPeers)
	selfMessages, _ := lru.NewARC(lruMessages)
	e := &engine{
		config:       config,
		privateKey:   privateKey,
		nodeID:       Pub2NodeID(&privateKey.PublicKey),
		nodeAddr:     crypto.PubkeyToAddress(privateKey.PublicKey),
		logger:       logger,
		db:           db,
		chainHeadCh:  make(chan core.ChainHeadEvent),
		peerMessages: peerMessages,
		selfMessages: selfMessages,

		// Broadcast is called on every round change
		roundNumberMu: sync.RWMutex{},
		roundNumber:   big.NewInt(0),
	}
	e.roundNumberC = sync.NewCond(&e.roundNumberMu)

	return e
}

// NewBlockChain is ignored, we subscribe to the original ChainHeadEvent
func (e *engine) NewChainHead() error {
	return nil
}

// HandleMsg handles a message from peer
func (e *engine) HandleMsg(peerAddr common.Address, data p2p.Msg) (bool, error) {

	var err error

	if data.Code != rororoMsg {
		return false, nil
	}

	if !e.IsRunning() {
		return true, errEngineStopped
	}

	var msg []byte
	if err = data.Decode(&msg); err != nil {
		return true, err
	}
	msgHash := Keccak256Hash(msg)

	rmsg := &RMsg{}
	if err = rlp.DecodeBytes(msg, rmsg); err != nil {
		return true, err
	}

	e.logger.Debug("RoRoRo HandleMsg", "#msg", msgHash.Hex(), "#raw", Keccak256Hash(rmsg.Raw).Hex())

	// Note: it is the msgHash we want here, not the raw hash. We want it to be
	// possible for leader candidates to request a re-evaluation of the same
	// block proposal. Otherwise they can get stuck in small network scenarios.
	if seen := e.updateInboundMsgTracking(peerAddr, msgHash); seen {
		e.logger.Debug("RoRoRo HandleMsg - ignoring previously seen")
		return true, nil
	}

	switch rmsg.Code {
	case RMsgIntent:

		si := &engSignedIntent{ReceivedAt: data.ReceivedAt, Seq: rmsg.Seq}

		if si.Pub, err = si.DecodeSigned(NewBytesStream([]byte(rmsg.Raw))); err != nil {
			e.logger.Info("RoRoRo Intent decodeverify failed", "err", err)
			return true, err
		}

		e.logger.Debug("RoRoRo HandleMsg - post engSignedIntent")
		e.runningCh <- si

		return true, nil

	case RMsgConfirm:

		sc := &engSignedEndorsement{ReceivedAt: data.ReceivedAt, Seq: rmsg.Seq}

		r := bytes.NewReader([]byte(rmsg.Raw))
		s := rlp.NewStream(r, uint64(len(rmsg.Raw)))

		if sc.Pub, err = sc.DecodeSigned(s); err != nil {
			e.logger.Info("RoRoRo Endorsement decodeverify failed", "err", err)
			return true, err
		}

		e.logger.Debug("RoRoRo HandleMsg - post engSignedEndorsement")
		e.runningCh <- sc

		return true, nil

	default:
		return true, errRMsgInvalidCode
	}
}

// Send the message to the peer - if its hash is not in the ARU cache for the
// peer
func (e *engine) Send(peerAddr common.Address, msg []byte) error {
	e.logger.Debug("RoRoRo Send")

	msgHash := Keccak256Hash(msg)

	peers := e.broadcaster.FindPeers(map[common.Address]bool{peerAddr: true})
	if len(peers) != 1 {
		return fmt.Errorf("RoRoRo Send - no peer connection")
	}
	peer := peers[peerAddr]
	if peer == nil {
		return fmt.Errorf("internal error, FindPeers returning unasked for peer")
	}
	return e.peerSend(peer, peerAddr, msg, msgHash)
}

// Broadcast the message to the provided peers, skipping self. If we have
// previously sent the message to a peer, it is not resent.
func (e *engine) Broadcast(self common.Address, peers map[common.Address]consensus.Peer, msg []byte) error {

	msgHash := Keccak256Hash(msg)
	// e.logger.Debug("RoRoRo messaging broadcasting msg", "hash", hex.EncodeToString(msgHash[:]))

	for peerAddr, peer := range peers {

		if peerAddr == self {
			e.logger.Debug("RoRoRo Broadcast - skipping self")
			continue
		}

		if err := e.peerSend(peer, peerAddr, msg, msgHash); err != nil {
			e.logger.Info("RoRoRo Broadcast - error sending msg", "err", err, "peer", peerAddr)
		}
	}
	return nil
}

func (e *engine) peerSend(
	peer consensus.Peer, peerAddr common.Address, msg []byte, msgHash Hash,
) error {

	e.messagingMu.Lock()
	defer e.messagingMu.Unlock()

	var msgs *lru.ARCCache

	if i, ok := e.peerMessages.Get(peerAddr); ok {
		msgs = i.(*lru.ARCCache) // panic if we have put the wrong type in the cache
		if _, ok := msgs.Get(msgHash); ok {
			// have already sent the message to, or received it from, this peer
			return nil
		}
	} else {
		msgs, _ = lru.NewARC(lruMessages)
	}

	msgs.Add(msgHash, true)
	e.peerMessages.Add(peerAddr, msgs)

	e.logger.Debug("RoRoRo peerSend - sending", "hash", msgHash.Hex(), "safe-hash", Keccak256Hash(msg).Hex())

	// Send will error imediately on encoding problems. But otherwise it
	// will block until the receiver consumes the message or the send times
	// out. So we can not sensibly collect errors.
	go peer.Send(rororoMsg, msg)
	return nil
}

// updateInboundMsgTracking updates the tracking of messages inbound from peers
func (e *engine) updateInboundMsgTracking(peerAddr common.Address, hash Hash) bool {

	// keep track of messages seen from this peer recently
	e.messagingMu.Lock()
	defer e.messagingMu.Unlock()

	var msgs *lru.ARCCache
	if i, ok := e.peerMessages.Get(peerAddr); ok {
		msgs, _ = i.(*lru.ARCCache)
	} else {
		msgs, _ = lru.NewARC(lruMessages)
		e.peerMessages.Add(peerAddr, msgs)
	}
	msgs.Add(hash, true)

	// If we have seen this message, do not handle it again.
	var seen bool
	if _, seen = e.selfMessages.Get(hash); !seen {
		e.selfMessages.Add(hash, true)
	}
	return seen
}

// SetBroadcaster implements consensus.Handler.SetBroadcaster
// Which, for the quorum fork, is called by eth/handler.go NewProtocolManager
func (e *engine) SetBroadcaster(broadcaster consensus.Broadcaster) {
	e.broadcaster = broadcaster
}

func (e *engine) stop() {

	if e.chainHeadSub != nil { // we are called from Start
		e.chainHeadSub.Unsubscribe()
	}

	e.runningMu.Lock()
	if e.runningCh != nil {

		close(e.runningCh)
		e.runningCh = nil
		e.runningMu.Unlock()

		e.runningWG.Wait()

	} else {
		e.runningMu.Unlock()
	}
}

// NotifyRoundChange send val to the notify channel when the round number
// changes (it does not care if it increases or decreases, only that it
// changes)
func (e *engine) NotifyRoundChange(notify chan<- interface{}, val interface{}) {
	e.roundNumberC.L.Lock()
	currentRound := big.NewInt(0).Set(e.roundNumber)
	for e.roundNumber.Cmp(currentRound) == 0 {
		e.roundNumberC.Wait()
	}
	e.roundNumberC.L.Unlock()
	notify <- val
}

func (e *engine) RoundNumber() *big.Int {
	e.roundNumberMu.RLock()
	defer e.roundNumberMu.RUnlock()
	return big.NewInt(0).Set(e.roundNumber)
}

func (e *engine) Start(
	reader consensus.ChainReader) error {
	e.logger.Info("RoRoRo Start")
	e.stop()

	chain, ok := reader.(RoRoRoChainReader)
	if !ok {
		return errIncompatibleChainReader
	}

	e.chainHeadSub = chain.SubscribeChainHeadEvent(e.chainHeadCh)

	// When Start is called we can be sure that everything we need is ready. So
	// we process the genesis extra data here.
	hg := chain.GetHeaderByNumber(0)
	if hg == nil {
		return errNoGenesisHeader
	}
	e.logger.Info("genesis block", "extra", hex.EncodeToString(hg.Extra))
	err := rlp.DecodeBytes(hg.Extra, &e.genesisEx)
	if err != nil {
		return err
	}

	signerPub, err := e.genesisEx.IdentInit[0].U.SignerPub(e.genesisEx.IdentInit[0].Q[:])
	signerAddr := crypto.PubkeyToAddress(*signerPub)
	fmt.Printf("signer-addr: %s\n", signerAddr.Hex())
	fmt.Printf("signer-addr: %s\n", hex.EncodeToString(e.genesisEx.IdentInit[0].U[12:]))

	signerNodeID, err := e.genesisEx.IdentInit[0].U.SignerNodeID(e.genesisEx.IdentInit[0].Q[:])
	if err != nil {
		return err
	}
	var foundGenesisSigner bool
	for _, en := range e.genesisEx.IdentInit {
		if en.U == signerNodeID {
			foundGenesisSigner = true
			e.logger.Info("genesis", "signer nodeid", en.U.Hex())
			break
		}
	}
	if !foundGenesisSigner {
		return fmt.Errorf("genesis identity signer not enroled")
	}

	e.runningCh = make(chan interface{})
	go e.run(chain, e.runningCh)

	return nil
}

func (e *engine) Stop() error {
	e.stop()
	return nil
}

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *engine) Author(header *types.Header) (common.Address, error) {
	e.logger.Info("RoRoRo Author")

	_, sealerID, _, err := e.decodeHeaderSeal(header)
	if err != nil {
		return common.Address{}, err
	}

	sealingNodeAddr := common.Address(sealerID.Address())

	if sealingNodeAddr == e.nodeAddr {
		e.logger.Info("RoRoRo sealed by self", "address", sealingNodeAddr)
	} else {
		e.logger.Info("RoRoRo sealed by", "address", sealingNodeAddr)
	}
	return sealingNodeAddr, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *engine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	e.logger.Info("RoRoRo VerifyHeader")

	return e.verifyBranchHeaders(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (e *engine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	e.logger.Info("RoRoRo VerifyHeaders")

	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		errored := false
		for i, header := range headers {
			var err error
			if errored {
				err = consensus.ErrUnknownAncestor
			} else {
				err = e.verifyBranchHeaders(chain, header, headers[:i])
			}

			if err != nil {
				errored = true
			}

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of a given engine.
func (e *engine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	e.logger.Info("RoRoRo VerifyUncles")

	if len(block.Uncles()) > 0 {
		return errInvalidUncleHash
	}
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (e *engine) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	e.logger.Info("RoRoRo VerifySeal")

	if _, err := e.verifyHeader(chain, header); err != nil {
		return err
	}
	return nil
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (e *engine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	e.logger.Info("RoRoRo Prepare")

	// Start witht the default vanity data and nothing else.
	extra := make([]byte, RoRoRoExtraVanity)
	copy(extra, header.Extra)
	header.Extra = extra
	// this is just the block number for rororo
	header.Difficulty = header.Number
	return nil
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// but does not assemble the block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *engine) Finalize(
	chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	e.logger.Info("RoRoRo Finalize")

	// No block rewards in rororo, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = nilUncleHash
}

// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
// rewards) and assembles the final block.
//
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (e *engine) FinalizeAndAssemble(
	chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {

	e.logger.Info("RoRoRo FinalizeAndAssemble", "#tx", len(txs))

	// No block rewards in rororo, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = nilUncleHash

	block := types.NewBlock(header, txs, nil, receipts)

	// Assemble and return the final block for sealing
	return block, nil
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (e *engine) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	hash := sealHash(block.Header())
	e.logger.Info("RoRoRo Seal", "bn", block.Number(), "#s", hex.EncodeToString(hash[:]))

	// Without this check we mine blocks constantly, which may be what we want
	// ... yet with it we stall. not sure why yet
	if false {
		h := block.Header()
		n := h.Number.Uint64()
		ph := chain.GetHeader(h.ParentHash, n-1)
		if ph == nil {
			return consensus.ErrUnknownAncestor
		}
		if ph.Root == h.Root &&
			ph.TxHash == h.TxHash &&
			ph.ReceiptHash == h.ReceiptHash {
			e.logger.Info(
				"RoRoRo Seal skip identical block",
				"#tx", len(block.Transactions()), "txhash", h.TxHash.Hex(),
			)
			results <- nil
			return nil
		}
	}

	// XXX: If we have a intent and the required confirmations for the block,
	// sign it. In ethhash, this is where the PoW happens

	e.runningCh <- &engSealTask{
		RoundNumber: e.RoundNumber(),
		Block:       block, Results: results, Stop: stop}

	return nil
}

// SealHash returns the hash of a block prior to it being sealed. This hash
// excludes the rororo extra data beyond the fixed 32 byte vanity. The various
// elements in the rororo extra data carry their own signatures over data which
// bind the elements to the block being sealed. If the extra data on the header
// is < RoRoRoExtraVanity bytes long this function will panic (to avoid
// accidentally creating the same hash for different blocks).
func (e *engine) SealHash(header *types.Header) common.Hash {
	h := sealHash(header)
	e.logger.Info("RoRoRo SealHash", "#", h.Hex())

	return h
}

func sealHash(header *types.Header) common.Hash {

	hasher := sha3.NewLegacyKeccak256()

	h := common.Hash{}

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:RoRoRoExtraVanity],
	})
	hasher.Sum(h[:0])
	return h
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have. For rororo this is just the round number
func (e *engine) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	e.logger.Info("RoRoRo CalcDifficulty")

	e.intentMu.Lock()
	defer e.intentMu.Unlock()

	if e.candidates[e.nodeAddr] {
		return difficultyForCandidate
	}
	return difficultyForEndorser
}

// APIs returns the RPC APIs this consensus engine provides.
func (e *engine) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{}
	// return []rpc.API{{
	// 	Namespace: "rororo",
	// 	Version:   "1.0",
	// 	Service:   &API{chain: chain, rororo: e},
	// 	Public:    true,
	// }}
}

// Protocol returns the protocol for this consensus
func (e *engine) Protocol() consensus.Protocol {
	return consensus.RoRoRoProtocol
}

// Close terminates any background threads maintained by the consensus engine.
func (e *engine) Close() error {
	e.logger.Info("RoRoRo Close")
	return nil
}
