package rororo

import (
	"container/list"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	errEnrolmentInvalid           = errors.New("identity enrolment could not be verified")
	errGensisIdentitiesInvalid    = errors.New("failed to enrol the identities from the genesis block")
	errGensisIdentityNotEnroled   = errors.New("the identity that attested the gensis block is not enrolled in the genesis block")
	errEnrolmentNotSignedBySealer = errors.New("identity enrolment was not indidualy signed by the block sealer")
	errEnrolmentIsKnown           = errors.New("new identity (not flagged for re-enrolment) is known")
	errBranchDetected             = errors.New("branch detected and we haven't implemented select branch")
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

func (e *engine) primeActivitySelection(chain RoRoRoChainReader) error {

	hg := chain.GetHeaderByNumber(0)
	if hg == nil {
		return errNoGenesisHeader
	}

	if e.genesisEx.ChainID == zeroHash {
		// geth warmup will call VerifyBranchHeaders on the genesis block
		// before doing anything else. This guard simply avoids an anoying and
		// redundant log message, whilst also guarding against changes in the
		// geth implementation outside of our control.
		e.logger.Info("RoRoRo primeActivitySelection - genesis block", "extra", hex.EncodeToString(hg.Extra))
		err := rlp.DecodeBytes(hg.Extra, &e.genesisEx)
		if err != nil {
			return err
		}
	}

	e.activeSelection = list.New()

	// All of the enrolments in the genesis block are signed by the long term
	// identity key (node key) of the genesis node.

	genPub, err := Ecrecover(e.genesisEx.IdentInit[0].U[:], e.genesisEx.IdentInit[0].Q[:])
	if err != nil {
		return fmt.Errorf("%v:%w", err, errGensisIdentitiesInvalid)
	}
	genID := Hash{}
	copy(genID[:], Keccak256(genPub[1:65]))

	e.logger.Debug("RoRoRo primeActivitySelection", "genid", genID.Hex(), "genpub", hex.EncodeToString(genPub))

	// We require the identity that signed the gensis block to also be enrolled
	// in the block.
	var foundGenesisSigner bool
	for _, en := range e.genesisEx.IdentInit {
		if en.ID == genID {
			foundGenesisSigner = true
			break
		}
	}
	if !foundGenesisSigner {
		return fmt.Errorf("genid=`%s':%w", genID.Hex(), errGensisIdentityNotEnroled)
	}

	// If we have just started up. Position lastBlockSeen such that it
	// encompasses the block range required by Ta 'active'. This ensures we
	// always warm up our picture of activity consistently. See
	// selectCandidatesAndEndorsers

	head := chain.CurrentBlock()
	// horizon = head - activity
	headNumber := big.NewInt(0).Set(head.Number())
	horizon := headNumber.Sub(headNumber, big.NewInt(int64(e.config.Activity)))
	if horizon.Cmp(big0) < 0 {
		horizon.SetInt64(0)
	}
	e.activeBlockFence = horizon

	// Notice that we _do not_ record the hash here, we leave that to
	// accumulateActive, which will then correctly deal with collecting the
	// 'activity' in the genesis block.

	return nil
}

func (e *engine) enrolIdentities(
	fence *list.Element, sealerID Hash, sealerPub []byte, enrolments []Enrolment, block Hash, number *big.Int,
) error {

	enbind := &EnrolmentBinding{
		Round: big.NewInt(0),
	}

	// Gensis block can't refer to itself
	if number.Cmp(big0) > 0 {
		enbind.ChainID = e.genesisEx.ChainID
		enbind.Round.Set(number)
		enbind.BlockHash = block
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
			return false, nil
		}

		// Did the block sealer sign the indidual enrolment.
		if !VerifySignature(sealerPub, u[:], e.Q[:64]) {
			return false, fmt.Errorf("sealer-id=`%s',id=`%s',u=`%s':%w",
				sealerID.Hex(), e.ID.Hex(), u.Hex(), errEnrolmentNotSignedBySealer)
		}

		// XXX: We ignore the re-enrol flag for now. Strictly, if re-enrol is
		// false we need to ensure that the identity is genuinely new.
		// if !reEnrol {

		return true, nil
	}

	// The 'youngest' enrolment in the block is the last in the slice. And it
	// is essential that we refreshAge youngest -> oldest
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

		e.refreshAge(fence, enr.ID, block, number, order)
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
func (e *engine) recordActivity(nodeID Hash, endorsed Hash, blockNumber *big.Int) *idActivity {

	var aged *idActivity
	nodeAddr := nodeID.Address()
	if el := e.aged[nodeAddr]; el != nil {
		// Easy case, we simply don't have to care about age at all, it is what
		// it is.
		aged = el.Value.(*idActivity)
	} else {

		// Interesting case, activity from an identity whose enrolment we
		// haven't seen yet. We put the new entry straight onto the idle set.
		// refreshAge (below) will pluck it out of the idle set if it is
		// encountered within HEAD - Ta

		aged = newIDActivity(nodeID)
		e.idlePool[nodeAddr] = aged
	}
	aged.endorsedHash = endorsed
	aged.endorsedBlock.Set(blockNumber)

	return aged
}

// return the hex string formed from the first head 'h' bytes, and last tail 't' bytes as hex,
// formatted with a single '.'. h and t are clamped to len(Address) / 2 - 1
func fmtAddrex(addr Address, h, t int) string {

	if h < 1 && t < 1 {
		return ""
	}
	if h < 0 {
		h = 0
	}
	if t < 0 {
		t = 0
	}

	if t > len(addr)-h-1 {
		t = len(addr) - h - 1
	}

	if h > len(addr)-t-1 {
		h = len(addr) - t - 1
	}

	start := addr[:h]
	end := addr[len(addr)-t:]

	return fmt.Sprintf("%s.%s", hex.EncodeToString(start), hex.EncodeToString(end))
}

// refreshAge called to indicate that nodeID has minted a block or been
// enrolled. If this is the youngest block minted by the identity, we move its
// entry after the fence.  Counter intuitively, we always insert the at the
// 'oldest' position. Because accumulateActive works from the head (youngest)
// towards genesis.  If no fence is provided the entry is added at the back
// (oldest position). If a fence is provided, the entry is added immediately
// after the fence - which is the oldest position *after* the fence.
// accumulateActive uses the last block it saw as the fence. enrolIdentities
// processes enrolments for a block in reverse order of age. These two things
// combined give us an efficient way to always have identities sorted in age
// order.
func (e *engine) refreshAge(
	fence *list.Element, nodeID Hash, block Hash, blockNumber *big.Int, order int,
) {
	var aged *idActivity

	nodeAddr := nodeID.Address()
	if el := e.aged[nodeAddr]; el != nil {

		aged = el.Value.(*idActivity)

		// If the last block we saw for this identity is older, we need to
		// reset the age by moving it after the fence. Otherwise, we assume we
		// have already processed it and it is in the appropriate place.
		if aged.ageBlock.Cmp(blockNumber) <= 0 {

			e.logger.Trace("RoRoRo refreshAge - move",
				"addr", nodeAddr.Hex(), "age", fmt.Sprintf("%2d.%d->%d", order, aged.ageBlock, blockNumber))

			if fence != nil {
				// This is effectively MoveToBack, with fence as the logical back.Prev()
				e.activeSelection.MoveAfter(el, fence)
			} else {
				e.activeSelection.MoveToBack(el)
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
		if aged = e.idlePool[nodeAddr]; aged != nil {
			e.logger.Trace("RoRoRo refreshAge - from idle", "addr", nodeAddr.Hex(), "age", fmt.Sprintf("%02d.%05d", order, blockNumber))
		} else {
			e.logger.Trace("RoRoRo refreshAge - new", "addr", nodeAddr.Hex(), "age", fmt.Sprintf("%02d.%05d", order, blockNumber))
			aged = newIDActivity(nodeID)
		}
		delete(e.idlePool, nodeAddr)

		aged.ageBlock.Set(blockNumber)
		aged.ageHash = block
		aged.oldestFor = 0
		aged.order = order

		if fence != nil {
			// This is effectively PushBack, with fence as the logical back.Prev()
			e.aged[nodeAddr] = e.activeSelection.InsertAfter(aged, fence)
		} else {
			e.aged[nodeAddr] = e.activeSelection.PushBack(aged)
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
func (e *engine) withinActivityHorizon(n *big.Int) bool {

	// Note that activeBlockFence is intialised to the head block in Start

	depth := big.NewInt(0).Set(e.activeBlockFence)
	depth.Sub(depth, n)
	if !depth.IsUint64() {
		e.logger.Trace(
			"RoRoRo blockWithinActivityHorizon - -ve depth",
			"Ta", e.config.Activity, "n", n, "last", e.activeBlockFence)
		return false
	}
	if depth.Uint64() > e.config.Activity {
		return false
	}
	return true
}

// accumulateActive is effectively SelectActive from the paper, but with the
// 'obvious' caching optimisations. AND importantly we only add active
// identities to the active set here, we do not cull idles. That is left to
// selectCandidatesAndEndorsers.
func (e *engine) accumulateActive(chain RoRoRoChainReader, head *types.Header) error {

	if head == nil {
		return nil
	}
	headHash := Hash(head.Hash())
	if headHash == e.lastBlockSeen {
		return nil
	}

	cur := head

	youngestKnown := e.activeSelection.Front()

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

		// Reached the last block we updated for, we are done
		if h == e.lastBlockSeen {
			e.logger.Trace("RoRoRo accumulateActive - complete, reached last seen", "#", h.Hex())
			break
		}

		// If we have exceeded the Ta depth horizon we are done. Note we do this
		// directly on the number in the header and the activity, rather than
		// relying on the cached activeBlockFence.
		headNumber := big.NewInt(0).Set(head.Number) // because Sub modifies self
		depth := headNumber.Sub(headNumber, cur.Number)
		if !depth.IsUint64() || depth.Uint64() > e.config.Activity {
			e.logger.Trace("RoRoRo accumulateActive - complete, reached activity depth", "Ta", e.config.Activity)
			break
		}

		// Now we look at the activeBlockFence. If the number is at or beyond the
		// fence and we haven't matched the hash yet it means we have
		// inconsistent results. The exception accommodates the first pass after
		// node startup.
		if e.lastBlockSeen != zeroHash && cur.Number.Cmp(e.activeBlockFence) <= 0 && head.Number.Cmp(big0) != 0 {
			return fmt.Errorf("reached a lower block without matching hash of last seen: %w", errBranchDetected)
		}

		confirms, enrols, sealerID, sealerPub, err := e.decodeActivity(cur)
		if err != nil {
			return err
		}

		// telemetry only
		if sealer := e.aged[sealerID.Address()]; sealer != nil {
			age := sealer.Value.(*idActivity)
			var agemsg string
			if age.ageBlock.Cmp(cur.Number) < 0 {
				agemsg = fmt.Sprintf("%02d.%d->%d", age.order, age.ageBlock, cur.Number)
			} else {
				agemsg = fmt.Sprintf("%02d.%05d", age.order, cur.Number)
			}

			e.logger.Debug(
				"RoRoRo accumulateActive - sealer",
				"addr", sealerID.Address().Hex(), "age", agemsg)
		} else {
			// first block from this sealer since it went idle or was first
			// enrolled. if it went idle we could have seen an endorsement for
			// it but we haven't, if it is new this will be the first encounter
			// with the identity.
			e.logger.Debug(
				"RoRoRo accumulateActive - new sealer",
				"addr", sealerID.Address().Hex(), "age", fmt.Sprintf("00.%05d", cur.Number))
		} // end telemetry only

		// The sealer is minting and to preserve the "round" ordering, needs to
		// move to the youngest position - before the identities that may be
		// enrolled.
		e.refreshAge(youngestKnown, sealerID, h, cur.Number, 0)

		// Do any enrolments. (Re) Enrolling an identity moves it to the
		// youngest position in the activity set
		e.enrolIdentities(youngestKnown, sealerID, sealerPub, enrols, h, cur.Number)

		// The endorsers are active, they do not move in the age ordering.
		// Note however, for any identity enrolled after genesis, as we are
		// walking youngest -> oldest we may/probably will encounter
		// confirmations before we see the enrolment. For that to happen, the
		// identity must have been enrolled within Ta of this *cur* block else
		// it could not have been selected as an endorser. However, it may not
		// be within Ta of where we started accumulateActive
		for _, end := range confirms {
			// xxx: should probably log when we see a confirmation for an
			// enrolment we haven't had yet, that is 'interesting'
			e.recordActivity(end.EndorserID, h, cur.Number)
		}

		parentHash := cur.ParentHash
		if parentHash == common.Hash(zeroHash) {
			e.logger.Debug("RoRoRo accumulateActive - complete, no more blocks")
			break
		}

		cur = chain.GetHeaderByHash(parentHash)

		if cur == nil {
			return fmt.Errorf("block #`%s' not available locally", parentHash.Hex())
		}
	}

	e.lastBlockSeen = headHash
	e.activeBlockFence = big.NewInt(0).Set(head.Number)

	return nil
}

// selectCandidatesAndEndorsers determines if the current node is a leader
// candidate and what the current endorsers are. The key requirement of RRR met
// here  is that the results of this function should be the same on all nodes
// assuming the start from the same `head'. This is both SelectCandidates and
// SelectEndorsers from the paper.
func (e *engine) selectCandidatesAndEndorsers(
	chain RoRoRoChainReader, head *types.Block) (map[common.Address]bool, map[common.Address]bool, error) {

	header := head.Header()
	if err := e.accumulateActive(chain, header); err != nil {
		return nil, nil, err
	}

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
	candidates := make(map[common.Address]bool)
	endorsers := make(map[common.Address]bool)

	// We do some book keeping in the interests of useful logs - it is
	// essential/very useful to be able to see the orderings and selections in
	// the logs.
	selection := make([]Address, 0, e.config.Candidates+e.config.Endorsers)

	var next *list.Element
	e.logger.Trace("RoRoRo selectCandEs", "agelen", len(e.aged))

	// The permutation is limited to active endorser candidate positions. We
	// will select e.config.Candidates as active entries before we consider the
	// remaining active entries as endorsers.
	pendingEndorserPositions := map[int]bool{}

	// Get a random permutation of ALL active identities eligible as endorsers,
	// then take the first e.config.Endorsers in that permutation. This gives
	// us a random selection of endorsers with replacement.
	nActive := e.activeSelection.Len()
	if uint64(nActive) < e.config.Candidates+e.config.EndorsersQuorum {
		return nil, nil, fmt.Errorf(
			"%v < %v(c) +%v(q):%w", nActive, e.config.Candidates, e.config.EndorsersQuorum, errInsuficientActiveIdents)
	}
	permutation := rand.Perm(nActive - int(e.config.Candidates))
	ne := e.config.Endorsers
	if uint64(len(permutation)) < ne {
		ne = uint64(len(permutation))
	}
	permutation = permutation[:ne]
	for _, r := range permutation {
		pendingEndorserPositions[r] = true
	}

	endorserPosition := 0
	for cur := e.activeSelection.Back(); cur != nil; cur = next {

		next = cur.Prev() // so we can remove, and yes, we are going 'backwards'

		age := cur.Value.(*idActivity)

		if !e.withinActivityHorizon(age.endorsedBlock) {
			e.logger.Trace("RoRoRo selectCandEs - moving to idle set",
				"gi", age.genesisOrder, "end", age.endorsedBlock, "last", e.activeBlockFence)
			continue
		}

		addr := age.nodeID.Address()

		// We are accumulating candidates and endorsers together. We stop once
		// we have enough of *both* (or at the end of the list)

		if uint64(len(candidates)) < e.config.Candidates {

			// A candidate that is oldest for Nc rounds is moved to the idle pool
			if len(candidates) == 1 {
				age.oldestFor++
			}
			// TODO: Complete the guard against unresponsive nodes, can't until
			// we sort out the relationship between blocks and rounds
			if age.oldestFor > int(e.config.Candidates) {
				// Our chain will just stop progressing if Nc == 1, and that is ok
				// for now.
				e.logger.Info("RoRoRo selectCandEs - unresponsive node (droping tbd)",
					"nodeid", age.nodeID.Address().Hex(), "oldestFor", age.oldestFor)
			}

			selection = append(selection, addr) // telemetry only
			candidates[common.Address(addr)] = true

			e.logger.Debug("RoRoRo selectCandEs - select", "cand", fmt.Sprintf("%s:%02d.%05d", addr.Hex(), age.order, age.ageBlock))
			continue
			// Note: divergence (1) leader candidates can not be endorsers
		}

		endorserPosition++ // endorserPosition advances for all active endorsers

		// XXX: age < Te (created less than Te rounds) grinding attack mitigation

		// divergence (2) instead of sorting the endorser candidates by address
		// (public key) we rely on all nodes seeing the same 'age ordering',
		// and select them by randomly chosen position in that ordering.
		if pendingEndorserPositions[endorserPosition] {

			e.logger.Debug("RoRoRo selectCandEs - select", "endo", fmt.Sprintf("%s:%02d.%05d", addr.Hex(), age.order, age.ageBlock), "p", endorserPosition)
			endorsers[common.Address(addr)] = true
			selection = append(selection, addr) // telemetry only
			delete(pendingEndorserPositions, endorserPosition)
			if len(pendingEndorserPositions) == 0 {
				e.logger.Trace("RoRoRo selectCandEs - early out", "n", e.activeSelection.Len(), "e", len(candidates)+endorserPosition)
				break // early out
			}
		}
	}

	if true {
		// dump a report of the selection. Can later make this configurable. By
		// reporting as "block.order", we can, for small development networks,
		// easily correlate with the network. We probably also want the full
		// list of nodeID's for larger scale testing.
		strcans := []string{}
		strends := []string{}

		for _, addr := range selection {

			if addr == zeroAddr {
				e.logger.Info("RoRoRo RoRoRo selectCandEs - no endorsers, to few candidates",
					"len", len(selection), "nc", e.config.Candidates, "ne", e.config.Endorsers)
				break // fewer than desired candidates
			}
			// it is a programming error if we get nil here, either for the map entry or for the type assertion
			el := e.aged[addr]
			if el == nil {
				e.logger.Crit("no entry for", "addr", addr.Hex())
			}
			age := el.Value.(*idActivity)
			if age == nil {
				e.logger.Crit("element with no value", "addr", addr.Hex())
			}

			s := fmt.Sprintf("%d.%d:%s", age.ageBlock, age.order, fmtAddrex(addr, 3, 1))
			if candidates[common.Address(addr)] {
				strcans = append(strcans, s)
			} else {
				strends = append(strends, s)
			}
		}
		e.logger.Info("RoRoRo selectCandEs selected", "cans", strings.Join(strcans, ","))
		e.logger.Info("RoRoRo selectCandEs selected", "ends", strings.Join(strends, ","))
	}

	e.logger.Info("RoRoRo selectCandEs - iendorsers", "p", permutation, "r", header.Number, "s", e.roundSeed)

	return candidates, endorsers, nil
}
