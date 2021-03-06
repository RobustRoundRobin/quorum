package rrr

// This file deals with the age ordering of identities and their selection as
// leader candidates or intent endorsers. And in particular covers 5.1
// "Candidate and Endorser Selection" from the paper.

import (
	"container/list"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var (
	errEnrolmentInvalid           = errors.New("identity enrolment could not be verified")
	errGensisIdentitiesInvalid    = errors.New("failed to enrol the identities from the genesis block")
	errGensisIdentityNotEnroled   = errors.New("the identity that attested the gensis block is not enrolled in the genesis block")
	errEnrolmentNotSignedBySealer = errors.New("identity enrolment was not indidualy signed by the block sealer")
	errEnrolmentIsKnown           = errors.New("new identity (not flagged for re-enrolment) is known")
	errBranchDetected             = errors.New("branch detected")
	errInsuficientActiveIdents    = errors.New("not enough active identities found")
	big0                          = big.NewInt(0)
	zeroAddr                      = Address{}
	zeroHash                      = Hash{}
)

// idActivity is used to cache the 'age' and 'activity' of RRR identities.
//
// * In normal operation 'age' is the number of blocks since an identity last minted
// * When an identity is first enrolled, and so has not minted yet, 'age' is
//   number of blocks since they were enrolled.
// * A node is 'active' in the round (block) that enrolled (or re-enrolled) it.
// * A node is 'active' in any round (block) that it signed an intent endorsement in.
//
// 	"In case multiple candidates have the same age (i.e., they were enrolled in
// 	the same block), we choose the oldest candidate in the order their
// 	enrollment messages appear in the block. If an endorser receives intent
// 	messages that refer to more than one chain branches, the endorser picks the
// 	branch to confirm using Select Branch" -- 5.2 Endorsment
type idActivity struct {

	// nodeID is the 'identity'
	nodeID Hash

	// ageHash is the hash of last block minited by the identity
	ageHash Hash

	// ageBlock is the number of the block most recently minted by the
	// identity OR the block the identity was enrolled on - udpated by
	// esbalishAge
	ageBlock *big.Int

	// endorsedHash is the hash of the block most recently endorsed by the
	// identity
	endorsedHash Hash

	// endorsedBlock is the number of the block most recently endorsed by the
	// identity
	endorsedBlock *big.Int

	// oldestFor - the number of rounds the identity has been found to be the
	// oldest. Reset only after the identity mints a block. Excludes inactive
	// identities from candidate selection -- 5.1 "Candidate and Endorser Selection"
	oldestFor int

	// order in the block that the identities enrolment appeared.  The first
	// time an identity is selected, it has not minted so it is conceivable
	// that its 'age' is the same as another leader candidate (because they
	// were enrolled on the same block and they both have not minted). In this
	// case, the order is the tie breaker. Once the identity mints, order is
	// set to zero. order is initialised to zero for the genesis identity.
	order int

	// genesiOrder is for telemetry, it is (or will be) undefined for nodes
	// whose initial enrol is not in the genesis block.
	genesisOrder int
}

// ActiveSelection tracks the active identities and facilitates ordering them by
// age.
type ActiveSelection struct {

	// activeSelection  is maintained in identity age order - with the youngest at
	// the front.
	activeSelection *list.List                // list of *idActive
	aged            map[Address]*list.Element // map of NodeID.Addresss() -> Element in active

	// The idle pool tracks identities that have gone idle within Ta*2-1 blocks
	// from head at the time the node started. The *2-1 comes from the
	// posibilty of seeing enrolments from nodes after their last
	// (re-)enrolment has gone behond Ta of HEAD. Additionaly, because
	// selectActive processes the chain from HEAD -> genesis, we can encounter
	// endorsments before we see the enrolment. To accomodate this we put 'new'
	// identity activity into the idlePool. Then IF we encounter the enrolment
	// within Ta of HEAD we move it to the activeSelection
	idlePool map[Address]*idActivity

	// When updating activity, we walk back from the block we are presented
	// with. We ERROR if we reach a block number lower than activeBlockFence
	// without matching the hash - that is a branch and we haven't implemented
	// SelectBranch yet.
	lastBlockSeen    Hash
	activeBlockFence *big.Int

	logger log.Logger
}

// Reset resets and primes the active selection such that head - ta is the
// furthest back the next selection will look
func (a *ActiveSelection) Reset(activity uint64, head *types.Block) {
	// It feels wrong to lean this much on garbage collection. But lets see how
	// it goes.
	a.idlePool = make(map[Address]*idActivity)
	a.aged = make(map[Address]*list.Element)
	a.lastBlockSeen = Hash{}
	a.activeBlockFence = nil
	a.activeSelection = nil
	a.Prime(activity, head)
}

// Prime primes the active selection such that the next selection will look as
// far back as head - ta but no further
func (a *ActiveSelection) Prime(activity uint64, head *types.Block) {
	// Note: block sync will stop the consensus. On re-start this will discard
	// the current activeSelection. If we have a list (re-start) then we also
	// need to reset the last block hash seen.
	// if e.activeSelection != nil {
	// 	e.lastBlockSeen = zeroHash
	// }
	a.activeSelection = list.New()

	// If we have just started up. Position lastBlockSeen such that it
	// encompasses the block range required by Ta 'active'. This ensures we
	// always warm up our picture of activity consistently. See
	// selectCandidatesAndEndorsers

	// horizon = head - activity
	headNumber := big.NewInt(0).Set(head.Number())
	horizon := headNumber.Sub(headNumber, big.NewInt(int64(activity)))
	if horizon.Cmp(big0) < 0 {
		horizon.SetInt64(0)
	}
	a.activeBlockFence = horizon

	// Notice that we _do not_ record the hash here, we leave that to
	// accumulateActive, which will then correctly deal with collecting the
	// 'activity' in the genesis block.
}

// blockHeaderReader defines the interface required by AccumulateActive
type blockHeaderReader interface {
	GetHeaderByHash(hash common.Hash) *types.Header
}

// BlockActivity is the decoded RRR consensus block activity data from the
// block header extra data.
type BlockActivity struct {
	Confirm   []Endorsement
	Enrol     []Enrolment
	SealerID  Hash
	SealerPub []byte
}

// Decode decodes the RRR consensus activity data from the header extra data.
// Any activity previously held is completely discarded
func (a *BlockActivity) Decode(chainID Hash, header *types.Header) error {

	var err error
	var se *SignedExtraData

	a.Confirm = nil
	a.Enrol = nil
	a.SealerID = Hash{}
	a.SealerPub = nil

	// Common and fast path first
	if header.Number.Cmp(big0) > 0 {
		se, a.SealerID, a.SealerPub, err = decodeHeaderSeal(header)
		if err != nil {
			return err
		}
		a.Confirm = se.ExtraData.Confirm
		a.Enrol = se.ExtraData.Enrol
		return nil
	}

	// Genesis block needs special handling.
	ge, err := DecodeGenesisExtra(header.Extra)
	if err != nil {
		return fmt.Errorf("%v: %w", err, errDecodingGenesisExtra)
	}

	// But do require consistency, if it has been previously decoded
	h0 := Hash{}
	if chainID != h0 && chainID != ge.ChainID {
		return fmt.Errorf(
			"genesis header with incorrect chainID: %w", errDecodingGenesisExtra)
	}

	// Get the genesis signer public key and node id. Do this derivation of
	// node id and public key unconditionally regardless of wheter we think we
	// have the information to hand - it is just safer that way.
	a.SealerPub, err = Ecrecover(ge.IdentInit[0].U[:], ge.IdentInit[0].Q[:])
	if err != nil {
		return fmt.Errorf("%v:%w", err, errGensisIdentitiesInvalid)
	}

	copy(a.SealerID[:], Keccak256(a.SealerPub[1:65]))

	a.Confirm = []Endorsement{}
	a.Enrol = ge.IdentInit

	return nil
}

// AccumulateActive is effectively SelectActive from the paper, but with the
// 'obvious' caching optimisations. AND importantly we only add active
// identities to the active set here, we do not cull idles. That is left to
// selectCandidatesAndEndorsers.
func (a *ActiveSelection) AccumulateActive(
	chainID Hash, activity uint64, chain blockHeaderReader, head *types.Header,
) error {

	var err error

	if head == nil {
		return nil
	}
	headHash := Hash(head.Hash())
	if headHash == a.lastBlockSeen {
		return nil
	}

	blockActivity := BlockActivity{}

	cur := head

	youngestKnown := a.activeSelection.Front()

	// Record activity of all blocks until we reach the genesis block or
	// until we reach a block we have recorded already. We are traversing
	// 'youngest' block to 'oldest'. We remember the last block seen on the
	// last traversal and use it as our fence.  We insert all block enrolments
	// (also in reverse order) immediately after the fence. This maintains the
	// list in descending age order back -> front (see the spec for a less
	// dense description) Note the sealer is considered older than all of the
	// identities it enrolls.
	for {

		h := Hash(cur.Hash())

		// The seal hash must be used to verify enrolments as the enrolements are
		// contained in the extra data and obviously cant reference the full
		// hash of the block header they are delivered in.
		hseal := Hash(sealHash(cur))

		// Reached the last block we updated for, we are done
		if h == a.lastBlockSeen {
			a.logger.Trace("RRR accumulateActive - complete, reached last seen", "#", h.Hex())
			break
		}

		// If we have exceeded the Ta depth horizon we are done. Note we do this
		// directly on the number in the header and the activity, rather than
		// relying on the cached activeBlockFence.
		headNumber := big.NewInt(0).Set(head.Number) // because Sub modifies self
		depth := headNumber.Sub(headNumber, cur.Number)
		if !depth.IsUint64() || depth.Uint64() >= activity {
			a.logger.Trace("RRR accumulateActive - complete, reached activity depth", "Ta", activity)
			break
		}

		// Now we look at the activeBlockFence. If the number is at or beyond
		// the fence and we haven't matched the hash yet it means we have a
		// chain re-org. The exception accommodates the first pass after node
		// startup.
		if a.lastBlockSeen != zeroHash && cur.Number.Cmp(a.activeBlockFence) <= 0 && head.Number.Cmp(big0) != 0 {
			// re-orgs are fine provided verifyBranch is working, but we can't
			// deal with them sensibly here. The expectation is that everything
			// in aged gets moved to idles then we re-run accumulateActive to
			// re-order the whole list.
			return fmt.Errorf(
				"reached a lower block without matching hash of last seen, head-bn=%v, head-#=%s: %w",
				head.Number, head.Hash(), errBranchDetected)
		}

		if err = blockActivity.Decode(chainID, cur); err != nil {
			return err
		}

		// telemetry only
		if sealer := a.aged[blockActivity.SealerID.Address()]; sealer != nil {
			age := sealer.Value.(*idActivity)
			var agemsg string
			if age.ageBlock.Cmp(cur.Number) < 0 {
				agemsg = fmt.Sprintf("%02d.%d->%d", age.order, age.ageBlock, cur.Number)
			} else {
				agemsg = fmt.Sprintf("%02d.%05d", age.order, cur.Number)
			}

			a.logger.Debug(
				"RRR accumulateActive - sealer",
				"addr", blockActivity.SealerID.Address().HexShort(), "age", agemsg)
		} else {
			// first block from this sealer since it went idle or was first
			// enrolled. if it went idle we could have seen an endorsement for
			// it but we haven't, if it is new this will be the first encounter
			// with the identity.
			a.logger.Debug(
				"RRR accumulateActive - new sealer",
				"addr", blockActivity.SealerID.Address().HexShort(),
				"age", fmt.Sprintf("00.%05d", cur.Number))
		} // end telemetry only

		// The sealer is minting and to preserve the "round" ordering, needs to
		// move to the youngest position - before the identities that may be
		// enrolled.
		a.refreshAge(youngestKnown, blockActivity.SealerID, h, cur.Number, 0)

		// Do any enrolments. (Re) Enrolling an identity moves it to the
		// youngest position in the activity set
		a.enrolIdentities(
			chainID, youngestKnown,
			blockActivity.SealerID, blockActivity.SealerPub, blockActivity.Enrol,
			h, hseal, cur.Number)

		// The endorsers are active, they do not move in the age ordering.
		// Note however, for any identity enrolled after genesis, as we are
		// walking youngest -> oldest we may/probably will encounter
		// confirmations before we see the enrolment. For that to happen, the
		// identity must have been enrolled within Ta of this *cur* block else
		// it could not have been selected as an endorser. However, it may not
		// be within Ta of where we started accumulateActive
		for _, end := range blockActivity.Confirm {
			// xxx: should probably log when we see a confirmation for an
			// enrolment we haven't had yet, that is 'interesting'
			a.recordActivity(end.EndorserID, h, cur.Number)
		}

		parentHash := cur.ParentHash
		if parentHash == common.Hash(zeroHash) {
			a.logger.Debug("RRR accumulateActive - complete, no more blocks")
			break
		}

		cur = chain.GetHeaderByHash(parentHash)

		if cur == nil {
			return fmt.Errorf("block #`%s' not available locally", parentHash.Hex())
		}
	}

	a.lastBlockSeen = headHash
	a.activeBlockFence = big.NewInt(0).Set(head.Number)

	return nil
}

type randPerm func(int) []int

// SelectCandidatesAndEndorsers determines if the current node is a leader
// candidate and what the current endorsers are. The key requirement of RRR met
// here  is that the results of this function should be the same on all nodes
// assuming they run accumulateActive starting from the same `head' block. This
// is both SelectCandidates and SelectEndorsers from the paper.
func (a *ActiveSelection) SelectCandidatesAndEndorsers(
	randPerm randPerm, nCandidates, nEndorsers, quorum, activityHorizon, failedAttempts uint,
	chain RRRChainReader, selfNodeID Hash,
) (map[common.Address]bool, map[common.Address]bool, []common.Address, error) {

	// Start with the oldest identity, and iterate towards the youngest. Move
	// any inactive identities encountered to the idle set (this is the only
	// place we remove 'inactive' entries from the active set). As we walk the
	// active list We gather the candidates and the endorsers The candidates
	// are the Nc first entries, the endorsers the Ne subsequent.
	//
	// XXX: NOTICE: divergence (1) A node is a candidate OR an endorser but not
	// both. The paper allows a candidate to also be an endorser. Discussion
	// with the author suggests this divergence helps small networks without
	// undermining the model.
	//
	// XXX: NOTICE: divergence (2) The paper specifies that the endorsers be
	// sorted by public key to produce a stable ordering for selection. But we
	// get a stable ordering by age naturally. So we use the permutation to
	// pick the endorser entries by position in the age order sort of active
	// identities. We can then eliminate the sort and also, usually, terminate
	// the list scan early.
	//
	// XXX: NOTICE: divergence (4) If no block is produced in the configured
	// time for intent+confirm, we re-sample. See RRR-spec.md Consensus Rounds
	// for details. failedAttempts tracked the number of times the local node
	// timer has expired withoug a block being produced.

	nActive := uint(a.activeSelection.Len())
	if nActive < uint(nCandidates+quorum) {
		return nil, nil, nil, fmt.Errorf(
			"%v < %v(c) + %v(q), len(idle)=%v:%w", nActive, nCandidates, quorum, len(a.idlePool), errInsuficientActiveIdents)
	}

	iFirstLeader, iLastLeader := a.calcLeaderWindow(nCandidates, nEndorsers, nActive, failedAttempts)
	a.logger.Trace(
		"RRR selectCandEs", "na", nActive, "agelen", len(a.aged),
		"f", failedAttempts, "if", iFirstLeader, "self", selfNodeID.Hex())

	candidates := make(map[common.Address]bool)
	endorsers := make(map[common.Address]bool)

	selection := make([]common.Address, 0, nCandidates+nEndorsers)

	var next *list.Element

	// The permutation is limited to active endorser candidate positions. The
	// leader candidates don't consume 'positions'
	pendingEndorserPositions := map[int]bool{}

	// Get a random permutation of ALL active identities eligible as endorsers,
	// then take the first e.config.Endorsers in that permutation. This gives
	// us a random selection of endorsers with replacement.
	permutation := randPerm(int(nActive) - int(nCandidates))
	iend := nEndorsers
	if uint(len(permutation)) < iend {
		iend = uint(len(permutation))
	}
	permutation = permutation[:iend]
	for _, r := range permutation {
		pendingEndorserPositions[r] = true
	}

	// To apply the permutation *around* the leader window, we just add Nc to
	// all endorser positions which are >= iFirstLeader

	endorserPosition := 0
	for cur, icur, inext := a.activeSelection.Back(), uint(0), uint(0); cur != nil; cur, icur = next, inext {

		next = cur.Prev() // so we can remove, and yes, we are going 'backwards'

		age := cur.Value.(*idActivity)

		lastActive := age.lastActiveBlock()

		if !a.withinActivityHorizon(activityHorizon, lastActive) {
			a.logger.Trace("RRR selectCandEs - moving to idle set",
				"gi", age.genesisOrder, "end", age.endorsedBlock, "last", a.activeBlockFence)

			// don't consume the position
			continue
		}
		inext++

		addr := age.nodeID.Address()

		// We are accumulating candidates and endorsers together. We stop once
		// we have enough of *both* (or at the end of the list)

		if icur >= iFirstLeader && icur <= iLastLeader &&
			uint(len(candidates)) < nCandidates {

			// A candidate that is oldest for Nc rounds is moved to the idle pool
			if len(candidates) == 0 && failedAttempts == 0 {
				// Note that we only increment oldestFor on the first attempt.
				// It is a count of *rounds* that the identity has been oldest
				// for. Age does not change with failedAttempts, and attempts
				// are totaly un-coordinated
				age.oldestFor++
			}

			// TODO: Complete the guard against unresponsive nodes, we can now
			// that we have sorted out the relationship between blocks and
			// rounds and attempts. But its a little tricky, it essentially
			// involves moving the window.
			if age.oldestFor > int(nCandidates) {
				a.logger.Info("RRR selectCandEs - unresponsive node (droping tbd)",
					"nodeid", age.nodeID.Address().Hex(), "oldestFor", age.oldestFor)
			}

			selection = append(selection, common.Address(addr)) // telemetry only
			candidates[common.Address(addr)] = true

			a.logger.Debug(
				"RRR selectCandEs - select",
				"cand", fmt.Sprintf("%s:%02d.%05d", addr.Hex(), age.genesisOrder, age.ageBlock),
				"ic", len(candidates)-1, "a", lastActive)
			continue
			// Note: divergence (1) leader candidates can not be endorsers
		}

		// endorserPosition is the *index* into the random permutation, so
		// there is nothing special to do here to account for the leader window
		// - it just doesn't get advanced when we select a leader above.

		// XXX: age < Te (created less than Te rounds) grinding attack mitigation

		// divergence (2) instead of sorting the endorser candidates by address
		// (public key) we rely on all nodes seeing the same 'age ordering',
		// and select them by randomly chosen position in that ordering.
		if pendingEndorserPositions[endorserPosition] {

			a.logger.Debug(
				"RRR selectCandEs - select", "endo",
				fmt.Sprintf("%s:%02d.%05d", addr.Hex(), age.order, age.ageBlock),
				"ie", endorserPosition, "a", lastActive)

			endorsers[common.Address(addr)] = true
			selection = append(selection, common.Address(addr)) // telemetry only
			delete(pendingEndorserPositions, endorserPosition)

			// If the leader window has moved all the way to the end, we can't
			// break out early here.
			if len(pendingEndorserPositions) == 0 && uint(nActive-1) < iLastLeader {
				a.logger.Trace("RRR selectCandEs - early out", "n", a.activeSelection.Len(),
					"e", len(candidates)+endorserPosition)
				break // early out
			}
		}
		endorserPosition++ // endorserPosition advances for all active endorsers
	}

	a.logSelection(candidates, endorsers, selection, nCandidates, nEndorsers)

	a.logger.Debug("RRR selectCandEs - iendorsers", "p", permutation)

	return candidates, endorsers, selection, nil
}

func (a *ActiveSelection) logSelection(

	candidates map[common.Address]bool, endorsers map[common.Address]bool,
	selection []common.Address, nCandidates, nEndorsers uint) {

	// XXX: Use the lazy logger here
	// dump a report of the selection. Can later make this configurable. By
	// reporting as "block.order", we can, for small development networks,
	// easily correlate with the network. We probably also want the full
	// list of nodeID's for larger scale testing.
	strcans := []string{}
	strends := []string{}

	for _, addr := range selection {

		if Address(addr) == zeroAddr {
			a.logger.Info("RRR RRR selectCandEs - no endorsers, to few candidates",
				"len", len(selection), "nc", nCandidates, "ne", nEndorsers)
			break // fewer than desired candidates
		}
		// it is a programming error if we get nil here, either for the map entry or for the type assertion
		el := a.aged[Address(addr)]
		if el == nil {
			a.logger.Crit("no entry for", "addr", addr.Hex())
		}
		age := el.Value.(*idActivity)
		if age == nil {
			a.logger.Crit("element with no value", "addr", addr.Hex())
		}

		s := fmt.Sprintf("%d.%d:%s", age.ageBlock, age.order, Address(addr).HexShort())
		if candidates[common.Address(addr)] {
			strcans = append(strcans, s)
		} else {
			strends = append(strends, s)
		}
	}
	a.logger.Debug("RRR selectCandEs selected", "cans", strings.Join(strcans, ","))
	a.logger.Debug("RRR selectCandEs selected", "ends", strings.Join(strends, ","))
}

// LeaderForRoundAttempt determines if the provided identity was selected as
// leader for the current round given the provided failedAttempts
func (a *ActiveSelection) LeaderForRoundAttempt(
	nCandidates, nEndorsers uint, id Address, failedAttempts uint) bool {

	nActive := uint(a.activeSelection.Len())
	iFirstLeader, iLastLeader := a.calcLeaderWindow(
		nCandidates, nEndorsers, nActive, failedAttempts)

	if iFirstLeader >= uint(a.activeSelection.Len()) {
		a.logger.Trace(
			"RRR leaderForRoundAttempt - if out of range",
			"if", iFirstLeader, "len", a.activeSelection.Len())
		return false
	}

	cur, icur := a.activeSelection.Back(), uint(0)
	for ; cur != nil && icur <= iLastLeader; cur, icur = cur.Prev(), icur+1 {
		if icur < iFirstLeader {
			continue
		}
		if cur.Value.(*idActivity).nodeID.Address() == id {
			return true
		}
	}
	return false
}

// lastActiveBlock returns the higher of endorsedBlock and ageBlock
func (a *idActivity) lastActiveBlock() *big.Int {

	if a.endorsedBlock.Cmp(a.ageBlock) > 0 {
		return a.endorsedBlock
	}
	return a.ageBlock
}

func (a *ActiveSelection) enrolIdentities(
	chainID Hash, fence *list.Element, sealerID Hash,
	sealerPub []byte, enrolments []Enrolment, block Hash, blockSeal Hash, number *big.Int,
) error {

	enbind := &EnrolmentBinding{
		Round: big.NewInt(0),
	}

	// Gensis block can't refer to itself
	if number.Cmp(big0) > 0 {
		enbind.ChainID = chainID
		enbind.Round.Set(number)
		enbind.BlockHash = blockSeal
	}

	verifyEnrolment := func(e Enrolment, reEnrol bool) (bool, error) {

		enbind.NodeID = e.ID
		enbind.ReEnrol = reEnrol

		u, err := enbind.U()
		if err != nil {
			return false, err
		}
		if u != e.U {
			// We try with and without re-enrolment set, so hash match isn't an
			// error
			a.logger.Debug("RRR enrolIdentities - u != e.U", "u", u.Hex(), "e.U", e.U.Hex())
			return false, nil
		}

		// Did the block sealer sign the indidual enrolment.
		if !VerifySignature(sealerPub, u[:], e.Q[:64]) {
			a.logger.Info("RRR enrolIdentities - verify failed",
				"sealerID", sealerID.Hex(), "e.ID", e.ID.Hex(), "e.U", e.U.Hex())
			return false, fmt.Errorf("sealer-id=`%s',id=`%s',u=`%s':%w",
				sealerID.Hex(), e.ID.Hex(), u.Hex(), errEnrolmentNotSignedBySealer)
		}

		// XXX: We ignore the re-enrol flag for now. Strictly, if re-enrol is
		// false we need to ensure that the identity is genuinely new.
		// if !reEnrol {

		return true, nil
	}

	// The 'youngest' enrolment in the block is the last in the slice. And it
	// is essential that we refreshAge youngest to oldest
	// (resuting in oldest <- youngest order)
	for i := 0; i < len(enrolments); i++ {

		order := len(enrolments) - i - 1 // the last enrolment is the youngest
		enr := enrolments[order]

		// the usual case once we are up and running is re-enrolment so we try
		// it first.
		var ok bool
		var err error

		if ok, err = verifyEnrolment(enr, true); err != nil {
			return err
		}
		if !ok {
			if ok, err = verifyEnrolment(enr, false); err != nil {
				return err
			}
		}
		if !ok {
			return fmt.Errorf("sealer-id=`%s',id=`%s',u=`%s':%w",
				sealerID.Hex(), enr.ID.Hex(), enr.U.Hex(), errEnrolmentInvalid)
		}

		// For the genesis block sealer id is also the first enroled identity.
		// The sealer age is refreshed directly in AccumulateActive. But note
		// that we still apply all the verification
		if sealerID == enr.ID {
			a.logger.Trace(
				"RRR enrolIdentities - sealer found in enrolments",
				"bn", number, "#", block.Hex())
			continue
		}
		a.logger.Info("RRR enroled identity", "id", enr.ID.Hex(), "bn", number, "#", block.Hex())

		a.refreshAge(fence, enr.ID, block, number, order)
	}
	return nil
}

func newIDActivity(nodeID Hash) *idActivity {
	return &idActivity{
		nodeID:        nodeID,
		ageBlock:      big.NewInt(0),
		endorsedBlock: big.NewInt(0),
	}
}

// recordActivity is called for a node to indicate it is active in the current
// round. Inactive entries are culled by selectCandidatesAndEndorsers
func (a *ActiveSelection) recordActivity(nodeID Hash, endorsed Hash, blockNumber *big.Int) *idActivity {

	var aged *idActivity
	nodeAddr := nodeID.Address()
	if el := a.aged[nodeAddr]; el != nil {
		// Easy case, we simply don't have to care about age at all, it is what
		// it is.
		aged = el.Value.(*idActivity)
	} else {

		// Interesting case, activity from an identity whose enrolment we
		// haven't seen yet. We put the new entry straight onto the idle set.
		// refreshAge (below) will pluck it out of the idle set if it is
		// encountered within HEAD - Ta

		aged = newIDActivity(nodeID)
		a.idlePool[nodeAddr] = aged
	}
	aged.endorsedHash = endorsed
	aged.endorsedBlock.Set(blockNumber)

	return aged
}

// refreshAge called to indicate that nodeID has minted a block or been
// enrolled. If this is the youngest block minted by the identity, we move its
// entry after the fence.  Counter intuitively, we always insert the at the
// 'oldest' position after the fence. Because accumulateActive works from the
// head (youngest) towards genesis we are visiting from the youngest to the
// oldest. By always inserting after the youngest that was in the list when we
// started, we preserve that order. In the special case where the list starts
// empty the fence is nil. In this case to preserve the order we *PushBack* -
// the first identity we add will be left at the *youngest* position.
// enrolIdentities is careful to processe enrolments for a block in reverse
// order of age. Taken all together, this give us an efficient way to always
// have identities sorted in age order.
func (a *ActiveSelection) refreshAge(
	fence *list.Element, nodeID Hash, block Hash, blockNumber *big.Int, order int,
) {
	var aged *idActivity

	nodeAddr := nodeID.Address()
	if el := a.aged[nodeAddr]; el != nil {

		aged = el.Value.(*idActivity)

		// If the last block we saw for this identity is older, we need to
		// reset the age by moving it after the fence. Otherwise, we assume we
		// have already processed it and it is in the appropriate place.
		// But note if we have a re-org, ageBlock *can* be from the 'other'
		// branch and so > head. The aged pool needs to be re-set for a re-org.
		if aged.ageBlock.Cmp(blockNumber) <= 0 {

			a.logger.Trace("RRR refreshAge - move",
				"fenced", bool(fence != nil), "addr", nodeAddr.HexShort(), "age",
				fmt.Sprintf("%02d.%d->%d", order, aged.ageBlock, blockNumber))

			if fence != nil {
				// Note: 'Before' means *in front of*
				a.activeSelection.MoveBefore(el, fence)
			} else {
				// Here we are assuming the list started *empty*
				a.activeSelection.MoveToBack(el)
			}
			aged.ageBlock.Set(blockNumber)
			aged.ageHash = block
			aged.oldestFor = 0
			aged.order = order
		}

	} else {

		// If it was enrolled within HEAD - Ta and has been active, it will be
		// in the idle pool because the age wasn't known when the activity was
		// seen by recordActivity. In either event there is no previous age.
		if aged = a.idlePool[nodeAddr]; aged != nil {
			a.logger.Trace(
				"RRR refreshAge - from idle", "addr", nodeAddr.HexShort(),
				"age", fmt.Sprintf("%02d.%05d", order, blockNumber))
		} else {
			a.logger.Trace(
				"RRR refreshAge - new", "addr", nodeAddr.HexShort(), "age",
				fmt.Sprintf("%02d.%05d", order, blockNumber))
			aged = newIDActivity(nodeID)
		}
		delete(a.idlePool, nodeAddr)

		aged.ageBlock.Set(blockNumber)
		aged.ageHash = block
		aged.oldestFor = 0
		aged.order = order

		if fence != nil {
			// Note: 'Before' means *in front of*
			a.aged[nodeAddr] = a.activeSelection.InsertBefore(aged, fence)
		} else {
			// Here we are assuming the list started *empty*
			a.aged[nodeAddr] = a.activeSelection.PushBack(aged)
		}

	}

	// Setting ageBlock resets the age of the identity. The test for active is
	// sensitive to this. If endorsedBlock for an identity is outside of Ta,
	// then it is still considered 'active' if ageBlock is inside Ta.
	// Re-enrolment is how the current leader re-activates idle identities.

	if blockNumber.Cmp(big0) == 0 {
		aged.genesisOrder = order
	}
}

// Is the number within Ta blocks of the block head ?
func (a *ActiveSelection) withinActivityHorizon(activity uint, blockNumber *big.Int) bool {

	// Note that activeBlockFence is intialised to the head block in Start

	// depth = activeBlockFence - blockNumber
	depth := big.NewInt(0).Set(a.activeBlockFence)
	depth.Sub(depth, blockNumber)
	if !depth.IsUint64() {
		// blockNumber is *higher* than our activity fence. blockNumber
		// typically comes from an age record, which would imply we have a
		// block extra data with an endorsement for a higher block number than
		// itself, which is clearly invalid - we have to see the block in order
		// that it gets into the age cache
		a.logger.Trace(
			"RRR withinActivityHorizon - future block",
			"Ta", activity, "bn", blockNumber, "last", a.activeBlockFence)
		return false
	}
	if depth.Uint64() > uint64(activity) {
		return false
	}
	return true
}

func (a *ActiveSelection) calcLeaderWindow(
	nCandidates, nEndorsers, nActive, failedAttempts uint) (uint, uint) {

	// a = active mod  [ MAX (n active, Nc + Ne) ]
	na := float64(nActive)
	nc, ne := float64(nCandidates), float64(nEndorsers)
	max := math.Max(na, nc+ne)
	amod, _ := math.Modf(math.Mod(float64(failedAttempts), max))

	iFirstLeader := uint(math.Floor(amod/nc) * nc)
	iLastLeader := iFirstLeader + nCandidates - 1

	a.logger.Trace(
		"RRR calcLeaderWindow", "na", na, "f", failedAttempts, "nc+ne", nc+ne,
		"max", max, "a", amod, "if", iFirstLeader)
	return iFirstLeader, iLastLeader
}
