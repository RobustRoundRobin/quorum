// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// note: Quorum, States, and Value Transfer
//
// In Quorum there is a tricky issue in one specific case when there is call from private state to public state:
// * The state db is selected based on the callee (public)
// * With every call there is an associated value transfer -- in our case this is 0
// * Thus, there is an implicit transfer of 0 value from the caller to callee on the public state
// * However in our scenario the caller is private
// * Thus, the transfer creates a ghost of the private account on the public state with no value, code, or storage
//
// The solution is to skip this transfer of 0 value under Quorum

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *EVM, contract *Contract, input []byte, readOnly bool) ([]byte, error) {
	if contract.CodeAddr != nil {
		// Using CodeAddr is favour over contract.Address()
		// During DelegateCall() CodeAddr is the address of the delegated account
		address := *contract.CodeAddr
		if _, ok := evm.affectedContracts[address]; !ok {
			evm.affectedContracts[address] = MessageCall
		}
		precompiles := PrecompiledContractsHomestead
		if evm.chainRules.IsByzantium {
			precompiles = PrecompiledContractsByzantium
		}
		if evm.chainRules.IsIstanbul {
			precompiles = PrecompiledContractsIstanbul
		}
		if p := precompiles[address]; p != nil {
			return RunPrecompiledContract(p, input, contract)
		}
	}
	for _, interpreter := range evm.interpreters {
		if interpreter.CanRun(contract.Code) {
			if evm.interpreter != interpreter {
				// Ensure that the interpreter pointer is set back
				// to its current value upon return.
				defer func(i Interpreter) {
					evm.interpreter = i
				}(evm.interpreter)
				evm.interpreter = interpreter
			}
			return interpreter.Run(contract, input, readOnly)
		}
	}
	return nil, ErrNoCompatibleInterpreter
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc

	// Message information
	Origin   common.Address // Provides information for ORIGIN
	GasPrice *big.Int       // Provides information for GASPRICE

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

type PublicState StateDB
type PrivateState StateDB

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	vmConfig Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	interpreters []Interpreter
	interpreter  Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64

	// Quorum additions:
	publicState       PublicState
	privateState      PrivateState
	states            [1027]*state.StateDB // TODO(joel) we should be able to get away with 1024 or maybe 1025
	currentStateDepth uint

	// This flag has different semantics from the `Interpreter:readOnly` flag (though they interact and could maybe
	// be simplified). This is set by Quorum when it's inside a Private State -> Public State read.
	quorumReadOnly bool
	readOnlyDepth  uint

	// these are for privacy enhancements
	affectedContracts map[common.Address]AffectedType // affected contract account address -> type
	currentTx         *types.Transaction              // transaction currently being applied on this EVM
}

type AffectedType byte

const (
	_                     = iota
	Creation AffectedType = iota
	MessageCall
)

// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(ctx Context, statedb, privateState StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		Context:      ctx,
		StateDB:      statedb,
		vmConfig:     vmConfig,
		chainConfig:  chainConfig,
		chainRules:   chainConfig.Rules(ctx.BlockNumber),
		interpreters: make([]Interpreter, 0, 1),

		publicState:  statedb,
		privateState: privateState,

		affectedContracts: make(map[common.Address]AffectedType),
	}

	if chainConfig.IsEWASM(ctx.BlockNumber) {
		// to be implemented by EVM-C and Wagon PRs.
		// if vmConfig.EWASMInterpreter != "" {
		//  extIntOpts := strings.Split(vmConfig.EWASMInterpreter, ":")
		//  path := extIntOpts[0]
		//  options := []string{}
		//  if len(extIntOpts) > 1 {
		//    options = extIntOpts[1..]
		//  }
		//  evm.interpreters = append(evm.interpreters, NewEVMVCInterpreter(evm, vmConfig, options))
		// } else {
		// 	evm.interpreters = append(evm.interpreters, NewEWASMInterpreter(evm, vmConfig))
		// }
		panic("No supported ewasm interpreter yet.")
	}

	evm.Push(privateState)

	// vmConfig.EVMInterpreter will be used by EVM-C, it won't be checked here
	// as we always want to have the built-in EVM as the failover option.
	evm.interpreters = append(evm.interpreters, NewEVMInterpreter(evm, vmConfig))
	evm.interpreter = evm.interpreters[0]

	return evm
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Cancelled returns true if Cancel has been called
func (evm *EVM) Cancelled() bool {
	return atomic.LoadInt32(&evm.abort) == 1
}

// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() Interpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	evm.Push(getDualState(evm, addr))
	defer func() { evm.Pop() }()

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	if !evm.StateDB.Exist(addr) {
		precompiles := PrecompiledContractsHomestead
		if evm.chainRules.IsByzantium {
			precompiles = PrecompiledContractsByzantium
		}
		if evm.chainRules.IsIstanbul {
			precompiles = PrecompiledContractsIstanbul
		}
		if precompiles[addr] == nil && evm.chainRules.IsEIP158 && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer
			if evm.vmConfig.Debug && evm.depth == 0 {
				evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
				evm.vmConfig.Tracer.CaptureEnd(ret, 0, 0, nil)
			}
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	if evm.ChainConfig().IsQuorum {
		// skip transfer if value /= 0 (see note: Quorum, States, and Value Transfer)
		if value.Sign() != 0 {
			if evm.quorumReadOnly {
				return nil, gas, ErrReadOnlyValueTransfer
			}
			evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)
		}
	} else {
		evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)
	}

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// Even if the account has no code, we need to continue because it might be a precompile
	start := time.Now()

	// Capture the tracer start/end events in debug mode
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)

		defer func() { // Lazy evaluation of the parameters
			evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
		}()
	}
	ret, err = run(evm, contract, input, false)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	evm.Push(getDualState(evm, addr))
	defer func() { evm.Pop() }()

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input, false)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	evm.Push(getDualState(evm, addr))
	defer func() { evm.Pop() }()

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)

	// Initialise a new contract and make initialise the delegate values
	contract := NewContract(caller, to, nil, gas).AsDelegate()
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input, false)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		to       = AccountRef(addr)
		stateDb  = getDualState(evm, addr)
		snapshot = stateDb.Snapshot()
	)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, new(big.Int), gas)
	contract.SetCallCode(&addr, stateDb.GetCodeHash(addr), stateDb.GetCode(addr))

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	stateDb.AddBalance(addr, bigZero)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in Homestead this also counts for code storage gas errors.
	ret, err = run(evm, contract, input, true)
	if err != nil {
		stateDb.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// create creates a new contract using code as deployment code.
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}

	// Quorum
	// Get the right state in case of a dual state environment. If a sender
	// is a transaction (depth == 0) use the public state to derive the address
	// and increment the nonce of the public state. If the sender is a contract
	// (depth > 0) use the private state to derive the nonce and increment the
	// nonce on the private state only.
	//
	// If the transaction went to a public contract the private and public state
	// are the same.
	var creatorStateDb StateDB
	if evm.depth > 0 {
		creatorStateDb = evm.privateState
	} else {
		creatorStateDb = evm.publicState
	}

	nonce := creatorStateDb.GetNonce(caller.Address())
	creatorStateDb.SetNonce(caller.Address(), nonce+1)

	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	evm.affectedContracts[address] = Creation
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	if nil != evm.currentTx && evm.currentTx.IsPrivate() && evm.currentTx.PrivacyMetadata() != nil {
		// for calls (reading contract state) or finding the affected contracts there is no transaction
		if evm.currentTx.PrivacyMetadata().PrivacyFlag.IsNotStandardPrivate() {
			pm := state.NewStatePrivacyMetadata(common.BytesToEncryptedPayloadHash(evm.currentTx.Data()), evm.currentTx.PrivacyMetadata().PrivacyFlag)
			evm.StateDB.SetStatePrivacyMetadata(address, pm)
			log.Trace("Set Privacy Metadata", "key", address, "privacyMetadata", pm)
		}
	}
	if evm.ChainConfig().IsQuorum {
		// skip transfer if value /= 0 (see note: Quorum, States, and Value Transfer)
		if value.Sign() != 0 {
			if evm.quorumReadOnly {
				return nil, common.Address{}, gas, ErrReadOnlyValueTransfer
			}
			evm.Transfer(evm.StateDB, caller.Address(), address, value)
		}
	} else {
		evm.Transfer(evm.StateDB, caller.Address(), address, value)
	}

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, address, gas, nil
	}

	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), address, true, codeAndHash.code, gas, value)
	}
	start := time.Now()

	ret, err := run(evm, contract, nil, false)

	maxCodeSize := evm.ChainConfig().GetMaxCodeSize(evm.BlockNumber)
	// check whether the max code size has been exceeded, check maxcode size from chain config
	maxCodeSizeExceeded := evm.chainRules.IsEIP158 && len(ret) > maxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if maxCodeSizeExceeded || (err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas)) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}
	return ret, address, contract.Gas, err

}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	// Quorum
	// Get the right state in case of a dual state environment. If a sender
	// is a transaction (depth == 0) use the public state to derive the address
	// and increment the nonce of the public state. If the sender is a contract
	// (depth > 0) use the private state to derive the nonce and increment the
	// nonce on the private state only.
	//
	// If the transaction went to a public contract the private and public state
	// are the same.
	var creatorStateDb StateDB
	if evm.depth > 0 {
		creatorStateDb = evm.privateState
	} else {
		creatorStateDb = evm.publicState
	}

	// Ensure there's no existing contract already at the designated address
	nonce := creatorStateDb.GetNonce(caller.Address())
	contractAddr = crypto.CreateAddress(caller.Address(), nonce)
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses sha3(0xff ++ msg.sender ++ salt ++ sha3(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), common.BigToHash(salt), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr)
}

// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// Quorum functions for dual state
func getDualState(env *EVM, addr common.Address) StateDB {
	// priv: (a) -> (b)  (private)
	// pub:   a  -> [b]  (private -> public)
	// priv: (a) ->  b   (public)
	state := env.StateDB

	if env.PrivateState().Exist(addr) {
		state = env.PrivateState()
	} else if env.PublicState().Exist(addr) {
		state = env.PublicState()
	}

	return state
}

func (env *EVM) PublicState() PublicState           { return env.publicState }
func (env *EVM) PrivateState() PrivateState         { return env.privateState }
func (env *EVM) SetCurrentTX(tx *types.Transaction) { env.currentTx = tx }
func (env *EVM) SetTxPrivacyMetadata(pm *types.PrivacyMetadata) {
	env.currentTx.SetTxPrivacyMetadata(pm)
}
func (env *EVM) Push(statedb StateDB) {
	// Quorum : the read only depth to be set up only once for the entire
	// op code execution. This will be set first time transition from
	// private state to public state happens
	// statedb will be the state of the contract being called.
	// if a private contract is calling a public contract make it readonly.
	if !env.quorumReadOnly && env.privateState != statedb {
		env.quorumReadOnly = true
		env.readOnlyDepth = env.currentStateDepth
	}

	if castedStateDb, ok := statedb.(*state.StateDB); ok {
		env.states[env.currentStateDepth] = castedStateDb
		env.currentStateDepth++
	}

	env.StateDB = statedb
}
func (env *EVM) Pop() {
	env.currentStateDepth--
	if env.quorumReadOnly && env.currentStateDepth == env.readOnlyDepth {
		env.quorumReadOnly = false
	}
	env.StateDB = env.states[env.currentStateDepth-1]
}

func (env *EVM) Depth() int { return env.depth }

// We only need to revert the current state because when we call from private
// public state it's read only, there wouldn't be anything to reset.
// (A)->(B)->C->(B): A failure in (B) wouldn't need to reset C, as C was flagged
// read only.
func (self *EVM) RevertToSnapshot(snapshot int) {
	self.StateDB.RevertToSnapshot(snapshot)
}

// Returns all affected contracts that are NOT due to creation transaction
func (evm *EVM) AffectedContracts() []common.Address {
	addr := make([]common.Address, 0, len(evm.affectedContracts))
	for a, t := range evm.affectedContracts {
		if t == MessageCall {
			addr = append(addr, a)
		}
	}
	return addr[:]
}

func (evm *EVM) CreatedContracts() []common.Address {
	addr := make([]common.Address, 0, len(evm.affectedContracts))
	for a, t := range evm.affectedContracts {
		if t == Creation {
			addr = append(addr, a)
		}
	}
	return addr[:]
}

// Return MerkleRoot of all affected contracts (due to both creation and message call)
func (evm *EVM) CalculateMerkleRoot() (common.Hash, error) {
	combined := new(trie.Trie)
	for addr := range evm.affectedContracts {
		data, err := getDualState(evm, addr).GetRLPEncodedStateObject(addr)
		if err != nil {
			return common.Hash{}, err
		}
		if err := combined.TryUpdate(addr.Bytes(), data); err != nil {
			return common.Hash{}, err
		}
	}
	return combined.Hash(), nil
}
