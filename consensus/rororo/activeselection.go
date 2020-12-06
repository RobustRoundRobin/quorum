package rororo

import (
	"bytes"
	"container/list"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	errEnrolmentInvalid           = errors.New("identity enrolment could not be verified")
	errGensisIdentitiesInvalid    = errors.New("failed to enrol the identities from the genesis block")
	errGensisIdentityNotEnroled   = errors.New("the identity that attested the gensis block is not enroled in the genesis block")
	errEnrolmentNotSignedBySealer = errors.New("identity enrolment was not indidualy signed by the block sealer")
	errEnrolmentIsKnown           = errors.New("new identity (not flagged for re-enrolment) is known")
	errBranchDetected             = errors.New("branch detected and we haven't implemented select branch")
	big0                          = big.NewInt(0)
	zeroHash                      = Hash{}
)

// idActivity is used to cache the 'age' and 'activity' of RRR identities.
//
// * In normal operation 'age' is the number of blocks since an identity last minted
// * When an identity is first enroled, and so has not minted yet, 'age' is
//   number of blocks since they were enroled.
// * A node is 'active' in the round (block) that enroled (or re-enroled) it.
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
	// identity OR the block the identity was enroled on - udpated by
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
	// were enroled on the same block and they both have not minted). In this
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

	h0 := Hash{}
	if e.genesisEx.ChainID == h0 {
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

	e.seniority = list.New()

	hashGen := Hash(hg.Hash())

	// All of the enrolments in the genesis block are signed by the long term
	// identity key (node key) of the genesis node.

	genPub, err := Ecrecover(e.genesisEx.IdentInit[0].U[:], e.genesisEx.IdentInit[0].Q[:])
	if err != nil {
		return fmt.Errorf("%v:%w", err, errGensisIdentitiesInvalid)
	}
	genID := Hash{}
	copy(genID[:], Keccak256(genPub[1:65]))

	e.logger.Debug("RoRoRo primeActivitySelection", "genid", genID.Hex(), "genpub", hex.EncodeToString(genPub))

	// signerPub, err := e.genesisEx.IdentInit[0].U.SignerPub(e.genesisEx.IdentInit[0].Q[:])
	// signerAddr := crypto.PubkeyToAddress(*signerPub)
	// fmt.Printf("signer-addr: %s\n", signerAddr.Hex())
	// fmt.Printf("signer-addr: %s\n", hex.EncodeToString(e.genesisEx.IdentInit[0].U[12:]))

	// We require the identity that signed the gensis block to also be enroled
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

	if err = e.enrolIdentities(genID, genPub, e.genesisEx.IdentInit, hashGen, big0); err != nil {
		return err
	}

	return nil
}

func (e *engine) enrolIdentities(
	sealerID Hash, sealerPub []byte, enrolments []Enrolment, block Hash, number *big.Int) error {

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
		// false we need to ensure that the identityjkIf we just check the
		// memory cache, it can lead to situtations where the 'age' is
		// different on diffent nodes.
		// if !reEnrol {

		return true, nil
	}

	for order, enr := range enrolments {

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

		e.establishAge(enr.ID, block, number, order)
	}
	return nil
}

// getIDActivity returns the activity record for the identity.
// * If the identity is absent it is created at the front.
// * If peek is false, the identy is moved to the front of the active list.
// * If the record is new, the nodeID is set and the block numbers are initialised to big 0's
func (e *engine) getIDActivity(nodeID Hash, peek bool) *idActivity {

	var aged *idActivity
	if el, ok := e.aged[nodeID]; ok {
		if !peek {
			e.seniority.MoveToFront(el)
		}
		aged = el.Value.(*idActivity)
	} else {
		aged = &idActivity{
			ageBlock:      big.NewInt(0),
			endorsedBlock: big.NewInt(0),
		}
		// If its new, it goes at the front regardless of peek
		e.aged[nodeID] = e.seniority.PushFront(aged)
	}
	return aged
}

// establishAge updates the age for a node, marks it has having been active in
// the block round, and resets its oldestFor counter. ageBlock and
// endorsedBlock are not changed - the identity has neither minted nor endorsed
func (e *engine) establishAge(nodeID Hash, block Hash, blockNumber *big.Int, order int) {

	// (re-)enrolment counts as being active for the block round. And
	// re-enrolment sets the age to zero (puts it at the front of the active
	// list)
	aged := e.getIDActivity(nodeID, false /*peek*/)
	aged.nodeID = nodeID

	// Setting ageBlock resets the age of the identity. The test for active is
	// sensitive to this. If endorsedBlock for an identity is outside of Ta,
	// then it is still considered 'active' if ageBlock is inside Ta.
	// Re-enrolment is how the current leader re-activates idle identities.
	aged.ageBlock.Set(blockNumber)
	aged.ageHash = block
	aged.oldestFor = 0
	aged.order = order
	if blockNumber.Cmp(big0) == 0 {
		aged.genesisOrder = order
	}
}

// Is the number within Ta blocks of the block head ?
func (e *engine) withinActivityHorizon(n *big.Int) bool {
	depth := e.lastBlockNumberSeen.Sub(e.lastBlockNumberSeen, n)
	if !depth.IsUint64() {
		e.logger.Trace(
			"RoRoRo blockWithinActivityHorizon - -ve depth",
			"Ta", e.config.Activity, "n", n, "last", e.lastBlockNumberSeen)
		return false
	}
	if depth.Uint64() > e.config.Activity {
		return false
	}
	return true
}

func (e *engine) activityUpdate(chain RoRoRoChainReader, head *types.Header) error {

	if head == nil {
		return nil
	}
	headHash := Hash(head.Hash())
	if headHash == e.lastBlockSeen {
		return nil
	}

	next := head
	headNumber := big.NewInt(0).Set(head.Number) // because Sub modifies self

	for {

		// Record activity of all blocks until we reach the genesis block or
		// until we reach a block we have recorded already.
		if next == nil {
			if e.lastBlockSeen != zeroHash || e.lastBlockNumberSeen != nil && e.lastBlockNumberSeen.Cmp(big0) != 0 {
				return fmt.Errorf("reached and of chain without finding previously seen: %w", errBranchDetected)
			}
			e.logger.Debug("RoRoRo activityUpdate - complete, no more blocks")
			break
		}

		h := Hash(next.Hash())

		// Reached the last block we updated for, we are done
		if h == e.lastBlockSeen {
			e.logger.Trace("RoRoRo activityUpdate - complete, reached last seen", "#", h.Hex())
			break
		}

		// If we have exceded the Ta depth horizon we are done.
		depth := headNumber.Sub(headNumber, next.Number)
		if !depth.IsUint64() || depth.Uint64() > e.config.Activity {
			e.logger.Trace("RoRoRo activityUpdate - complete, reached activity depth", "Ta", e.config.Activity)
			break
		}

		// If the hash didn't match and yet the number is less than or equal
		// the last we processed, we have encountered a branch, and we don't
		// have SelectBranch yet.
		if e.lastBlockNumberSeen != nil && next.Number.Cmp(e.lastBlockNumberSeen) <= 0 {
			return fmt.Errorf("reached a lower block without matching hash of last seen: %w", errBranchDetected)
		}

		confirms, enrols, sealerID, sealerPub, err := e.decodeActivity(next)
		if err != nil {
			return err
		}

		// Update the age of the minter
		e.establishAge(sealerID, h, next.Number, 0)

		// Do any enrolments. (Re) Enroling an identity moves it to the
		// youngest position in the activity set
		e.enrolIdentities(sealerID, sealerPub, enrols, h, next.Number)

		// The endorsers are active, they do not move in the age ordering.
		for _, end := range confirms {
			endorserAge := e.getIDActivity(end.EndorserID, true /*peek: age position un-changed*/)
			endorserAge.endorsedHash = h
			endorserAge.endorsedBlock.Set(next.Number)
		}

		e.logger.Debug("RoRoRo activityUpdate - block processed", "number", next.Number)

		if next.ParentHash == common.Hash(zeroHash) {
			next = nil
			continue
		}
		next = chain.GetHeaderByHash(next.ParentHash)
	}

	e.lastBlockSeen = headHash
	e.lastBlockNumberSeen = big.NewInt(0).Set(head.Number)

	return nil
}

// The paper specifies sorting enrolment candidates by public key, the address
// is more convenient and effectively the same result.
type Addresses []common.Address

func (s Addresses) Len() int      { return len(s) }
func (s Addresses) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type ByAddress struct{ Addresses }

func (s ByAddress) Less(i, j int) bool {
	return bytes.Compare(s.Addresses[i][:], s.Addresses[j][:]) < 0
}

// selectCandidatesAndEndorsers determines if the current node is a leader
// candidate and what the current endorsers are
func (e *engine) selectCandidatesAndEndorsers(
	chain RoRoRoChainReader, head *types.Block) (map[common.Address]bool, map[common.Address]bool, error) {

	header := head.Header()
	if err := e.activityUpdate(chain, header); err != nil {
		return nil, nil, err
	}

	// start with the oldest identity, and iterate towards the youngest. Move
	// any inactive identities encountered to the idle set. Gather the Nc
	// oldest active for this round as we go.
	candidates := make(map[common.Address]bool)
	endsort := make([]common.Address, 0, e.config.Endorsers)

	canorder := make([]string, 0, e.config.Candidates) // for telemetry
	endorder := make(map[common.Address]int)           // needed for telemetry, enrolment order is a proxy for node id

	var next *list.Element
	e.logger.Trace("RoRoRo selectCandidatesAndEndorsers", "agelen", len(e.aged))
	for cur := e.seniority.Back(); cur != nil; cur = next {

		next = cur.Prev() // so we can remove, and yes, we are going 'backwards' for now

		age := cur.Value.(*idActivity)
		if !e.withinActivityHorizon(age.endorsedBlock) {
			e.logger.Trace("RoRoRo selectOldestActive - moving to idle set",
				"gi", age.genesisOrder, "end", age.endorsedBlock, "last", e.lastBlockNumberSeen)
			continue
		}

		// XXX: A node is a canidate OR an endorser but not both. The paper isn't
		// particularly clear on this point but for small networks where Nc is
		// close to Ne, I can't see how it can be robust otherwise.

		if len(candidates) >= int(e.config.Candidates) {
			// Have enough leader candidates, now we are only concerned with
			// endorsers.
			endsort = append(endsort, common.Address(age.nodeID.Address()))
			endorder[endsort[len(endsort)-1]] = age.genesisOrder
			// e.logger.Trace("RoRoRo selectOldestActive - select", "end", age.nodeID.Address().Hex())
			continue
		}

		// when we see a block from this node.
		age.oldestFor++

		// TODO: Complete the guard against unresponsive nodes
		if age.oldestFor > int(e.config.Candidates) {
			// Our chain will just stop progressing if Nc == 1, and that is ok
			// for now.
			e.logger.Info("RoRoRo selectCandidatesAndEndorsers - unresponsive node (droping tbd)",
				"nodeid", age.nodeID.Address().Hex(), "oldestFor", age.oldestFor)
		}

		// e.logger.Trace("RoRoRo selectOldestActive - select", "can", age.nodeID.Address().Hex())
		candidates[common.Address(age.nodeID.Address())] = true
		canorder = append(canorder, strconv.Itoa(age.genesisOrder))
	}

	endorsers := make(map[common.Address]bool)
	sort.Sort(ByAddress{endsort})
	var permutation []string // telemetry
	for _, i := range rand.Perm(int(e.config.Endorsers)) {
		endorsers[endsort[i]] = true
		permutation = append(permutation, strconv.Itoa(i))
	}
	e.logger.Info("RoRoRo selectOldestActive - permutation", "p", strings.Join(permutation, ", "))

	if true { // XXX: lets add a selection debug flag on cli
		endstr := make([]string, 0, len(endorsers))
		for eaddr := range endorsers {
			endstr = append(endstr, strconv.Itoa(endorder[eaddr]))
			// endstr = append(endstr, eaddr.Hex())
		}
		cstr := strings.Join(canorder, ", ")
		estr := strings.Join(endstr, ", ")
		e.logger.Info("RoRoRo selection", "r", header.Number, "cans", cstr, "ends", estr)
	}

	return candidates, endorsers, nil
}
