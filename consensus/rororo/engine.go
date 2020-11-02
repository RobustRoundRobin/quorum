package rororo

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

var (
	// Uncles not relevant outside of PoW
	errInvalidUncleHash    = errors.New("non empty uncle hash")
	errNoGenesisHeader     = errors.New("failed to get genesis header")
	errEndorsersNotQuorate = errors.New("insufficient endorsers online")
	errP2PMsgInvalidCode   = errors.New("recieved p2p.Msg with unsported code")
	errRMsgInvalidCode     = errors.New("recevived RMsg with invalid code")
	errEngineStopped       = errors.New("consensus not running")
	nilUncleHash           = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
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
	Raw  rlp.RawValue
}

// API is a user facing RPC API to dump Istanbul state
type API struct {
	chain  consensus.ChainReader
	rororo *engine
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

	broadcaster consensus.Broadcaster

	// must be held for any interaction with ARCCache *Messages members
	messagingMu sync.RWMutex

	// Track which messages we have sent or received. We do not re-gossip
	// these. (IBFT calls these 'recentMessages'). We maintain a 2 level arc
	// here, for each of lruPeers we have an lru of recentley gossiped
	// messages.
	peerMessages *lru.ARCCache

	// Track which messages we have posted on our local processing queue. We do
	// not re-broadcast these. We do not re post these locally.
	selfMessages *lru.ARCCache

	runningMu sync.RWMutex // hold read lock if checking 'runningCh is nil'
	runningWG sync.WaitGroup

	// runningCh is passed as tthe input channel to the engine run() method.
	// The run method assumes the ownership of all pointer values sent to this
	// channel.
	runningCh chan interface{} // must be one of the Eng* types

	roundNumberC  *sync.Cond
	roundNumberMu sync.RWMutex // is held by roundNumberC
	roundNumber   *big.Int

	intentMu sync.Mutex
	sealTask *engSealTask
	intent   *pendingIntent
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
		address:      crypto.PubkeyToAddress(privateKey.PublicKey),
		logger:       logger,
		db:           db,
		peerMessages: peerMessages,
		selfMessages: selfMessages,

		// Broadcast is called on every round change
		roundNumberMu: sync.RWMutex{},
		roundNumber:   big.NewInt(0),
	}
	e.roundNumberC = sync.NewCond(&e.roundNumberMu)

	return e
}

func (e *engine) NewChainHead() error {
	e.logger.Info("RoRoRo NewChainHead")
	return ErrNotImplemented
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
	rmsg := &RMsg{}
	if err = rlp.DecodeBytes(msg, rmsg); err != nil {
		return true, err
	}

	hash := Keccak256Hash(rmsg.Raw)
	e.logger.Debug("RoRoRo messaging handling msg", "hash", hex.EncodeToString(hash[:]))

	if seen := e.updateInboundMsgTracking(peerAddr, hash); seen {
		return true, nil
	}

	switch rmsg.Code {
	case RMsgIntent:

		si := &SignedIntent{}
		if err = rlp.DecodeBytes(rmsg.Raw, si); err != nil {
			return true, err
		}
		e.logger.Info("RoRoRo Recieved SignedIntent",
			"round", si.RoundNumber,
			"nodeid", hex.EncodeToString(si.NodeID[:]),
			"parent", hex.EncodeToString(si.ParentHash[:]))

		return true, nil

	default:
		return true, errRMsgInvalidCode
	}
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

func (e *engine) startRound() error {
	return nil
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
	chain consensus.ChainReader, currentBlock func() *types.Block, hasBadBlock func(hash common.Hash) bool) error {
	e.logger.Info("RoRoRo Start")
	e.stop()

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
	fmt.Printf("signer-addr: %s\n", hex.EncodeToString(signerAddr[:]))
	fmt.Printf("signer-addr: %s\n", hex.EncodeToString(e.genesisEx.IdentInit[0].U[12:]))

	signerNodeID, err := e.genesisEx.IdentInit[0].U.SignerNodeID(e.genesisEx.IdentInit[0].Q[:])
	if err != nil {
		return err
	}
	var foundGenesisSigner bool
	for _, en := range e.genesisEx.IdentInit {
		if en.U == signerNodeID {
			foundGenesisSigner = true
			e.logger.Info("genesis", "signer nodeid", hex.EncodeToString(en.U[:]))
			break
		}
	}
	if !foundGenesisSigner {
		return fmt.Errorf("genesis identity signer not enroled")
	}

	e.runningCh = make(chan interface{})
	go e.run(chain, currentBlock, hasBadBlock, e.runningCh)

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
	return common.Address{}, ErrNotImplemented
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (e *engine) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	e.logger.Info("RoRoRo VerifyHeader")
	return e.verifyCascadingFields(chain, header)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers.
func (e *engine) verifyCascadingFields(chain consensus.ChainReader, header *types.Header) error {
	number := header.Number.Uint64()
	// The genesis block is the always valid dead-end
	if number == 0 {
		return nil
	}
	return ErrNotImplemented
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (e *engine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	e.logger.Info("RoRoRo VerifyHeaders")
	return nil, nil
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
	return ErrNotImplemented
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (e *engine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	e.logger.Info("RoRoRo Prepare")
	extra := make([]byte, RoRoRoExtraVanity)
	copy(extra, header.Extra)
	header.Extra = extra
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

	e.logger.Info("RoRoRo FinalizeAndAssemble")
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
	h := sealHash(block.Header())
	e.logger.Info("RoRoRo Seal", "bn", block.Number(), "#s", hex.EncodeToString(h[:]))
	// XXX: If we have a intent and the required confirmations for the block,
	// sign it. In ethhash, this is where the PoW happens

	e.runningCh <- &engSealTask{
		RoundNumber: e.RoundNumber(),
		Block:       block, Results: results, Stop: stop}

	// roundChange := make(chan interface{})
	// go e.NotifyRoundChange(roundChange, nil)
	// go func() {
	// 	select {
	// 	case <-stop:
	// 		return
	// 	case <-roundChange:
	// 		return
	// 	}
	// }()

	return nil
}

// SealHash returns the hash of a block prior to it being sealed. This hash
// excludes the rororo extra data beyond the fixed 32 byte vanity. The various
// elements in the rororo extra data carry their own signatures over data which
// bind the elements to the block being sealed. If the extra data on the header
// is < RoRoRoExtraVanity bytes long this function will panic (to avoid
// accidentally creating the same hash for different blocks).
func (e *engine) SealHash(header *types.Header) common.Hash {
	e.logger.Info("RoRoRo SealHash")
	return sealHash(header)
}

func sealHash(header *types.Header) common.Hash {
	newHeader := types.CopyHeader(header)
	newHeader.Extra = newHeader.Extra[:RoRoRoExtraVanity]
	hasher := sha3.NewLegacyKeccak256()
	hash := common.Hash{}
	hasher.Sum(hash[:0])
	return hash
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
func (e *engine) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	e.logger.Info("RoRoRo CalcDifficulty")
	return nil
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
	return ErrNotImplemented
}
