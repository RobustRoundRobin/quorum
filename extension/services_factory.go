package extension

import (
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/private"
)

type ServicesFactory interface {
	BackendService() *PrivacyService

	AccountManager() IAccountManager
	DataHandler() DataHandler
	StateFetcher() *StateFetcher
}

type DefaultServicesFactory struct {
	backendService *PrivacyService
	accountManager *AccountManager
	dataHandler    *JsonFileDataHandler
	stateFetcher   *StateFetcher
}

func NewServicesFactory(node *node.Node, ptm private.PrivateTransactionManager, thirdpartyunixfile string, ethService *eth.Ethereum) (*DefaultServicesFactory, error) {
	factory := &DefaultServicesFactory{}

	factory.accountManager = NewAccountManager(ethService.AccountManager())
	factory.dataHandler = NewJsonFileDataHandler(node.InstanceDir())
	factory.stateFetcher = NewStateFetcher(ethService.ChainDb(), ethService.BlockChain())

	backendService, err := New(ptm, factory.AccountManager(), factory.DataHandler(), factory.StateFetcher())
	if err != nil {
		return nil, err
	}
	factory.backendService = backendService
	go backendService.initialise(node, thirdpartyunixfile)

	return factory, nil
}

func (factory *DefaultServicesFactory) BackendService() *PrivacyService {
	return factory.backendService
}

func (factory *DefaultServicesFactory) AccountManager() IAccountManager {
	return factory.accountManager
}

func (factory *DefaultServicesFactory) DataHandler() DataHandler {
	return factory.dataHandler
}

func (factory *DefaultServicesFactory) StateFetcher() *StateFetcher {
	return factory.stateFetcher
}