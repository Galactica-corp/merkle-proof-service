/*
 * Copyright 2025 Galactica Network
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package indexer

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	db "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/sync/errgroup"

	"github.com/Galactica-corp/merkle-proof-service/internal/indexer"
	"github.com/Galactica-corp/merkle-proof-service/internal/query"
	"github.com/Galactica-corp/merkle-proof-service/internal/zkregistry"
)

const (
	dbName = "merkle"
)

type (
	// ContractConfig represents a contract configuration with optional start block override
	ContractConfig struct {
		Address    common.Address
		StartBlock *uint64 // nil means use contract's InitBlockHeight
	}
	ApplicationConfig struct {
		// EvmRpc is the URL of the EVM RPC. Must be a WebSocket URL.
		EvmRpc string

		// DbPath is the path to the database folder
		DbPath string

		// DbBackend Database backend: goleveldb | cleveldb | boltdb | rocksdb
		// * goleveldb (github.com/syndtr/goleveldb - most popular implementation)
		//   - pure go
		//   - stable
		// * cleveldb (uses levigo wrapper)
		//   - fast
		//   - requires gcc
		//   - use cleveldb build tag (go build -tags cleveldb)
		// * boltdb (uses etcd's fork of bolt - github.com/etcd-io/bbolt)
		//   - EXPERIMENTAL
		//   - may be faster is some use-cases (random reads - indexer)
		//   - use boltdb build tag (go build -tags boltdb)
		// * rocksdb (uses github.com/tecbot/gorocksdb)
		//   - EXPERIMENTAL
		//   - requires gcc
		//   - use rocksdb build tag (go build -tags rocksdb)
		// * badgerdb (uses github.com/dgraph-io/badger)
		//   - EXPERIMENTAL
		//   - use badgerdb build tag (go build -tags badgerdb)
		DbBackend db.BackendType

		// Jobs is a list of jobs that should be applied to the indexer
		ZkCertificateRegistry []ContractConfig

		// V2 contracts with queue-based processing
		ZkCertificateRegistryV2 []ContractConfig

		// QueryServer is the configuration for the query server
		QueryServer QueryServerConfig

		// IndexerConfig is the configuration for the indexer
		IndexerConfig indexer.Config
	}

	QueryServerConfig struct {
		GRPC struct {
			Address string
		}
		GRPCGateway struct {
			Address string
		}
	}

	Application struct {
		config ApplicationConfig

		kvDB            db.DB
		ethereumClient  *ethclient.Client
		queryServer     *query.Server
		registryService *zkregistry.Service

		// indexer
		jobStorage   *indexer.JobStorage
		jobFactory   *indexer.JobFactory
		evmIndexer   *indexer.Indexer
		configurator *indexer.Configurator
		jobs         []indexer.JobDescriptor

		logger log.Logger
	}
)

func NewApplication(config ApplicationConfig, logger log.Logger) *Application {
	return &Application{
		config: config,
		logger: logger,
	}
}

func StartApplication(ctx context.Context, config ApplicationConfig, logger log.Logger) error {
	logger.Info("starting merkle indexer application")

	app := NewApplication(config, logger)
	if err := app.Init(ctx); err != nil {
		return fmt.Errorf("init application: %w", err)
	}

	// close resources on exit
	defer app.ethereumClient.Close()
	defer func() {
		if err := app.kvDB.Close(); err != nil {
			logger.Error("close key-value DB", "error", err)
		}
	}()

	wgr, ctx := errgroup.WithContext(ctx)

	wgr.Go(func() error {
		return app.RunIndexer(ctx)
	})
	wgr.Go(func() error {
		return app.RunQueryServerGRPC(ctx)
	})
	wgr.Go(func() error {
		return app.RunQueryServerGRPCGateway(ctx)
	})

	if err := wgr.Wait(); err != nil {
		logger.Error("wait application workers", "error", err)
	}

	logger.Info("merkle indexer application stopped")

	return nil
}

// Init initializes the application and all its dependencies
func (app *Application) Init(ctx context.Context) error {
	app.logger.Info("connecting to EVM RPC", "evm_rpc", app.config.EvmRpc)
	if err := backoff.Retry(func() error {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		var err error
		app.ethereumClient, err = ethclient.DialContext(ctxWithTimeout, app.config.EvmRpc)
		if err != nil {
			app.logger.Error("ethereum node dial", "error", err)
		}

		return err
	}, backoff.NewExponentialBackOff()); err != nil {
		app.logger.Error("connect via RPC", "error", err)
		return fmt.Errorf("connect via RPC: %w", err)
	}

	app.logger.Info("connected to EVM RPC")

	ctxGetBlock, cancelGetBlock := context.WithTimeout(ctx, 15*time.Second)
	defer cancelGetBlock()

	latestBlock, err := app.ethereumClient.BlockNumber(ctxGetBlock)
	if err != nil {
		app.logger.Error("get latest block", "error", err)
		return fmt.Errorf("get latest block: %w", err)
	}
	app.logger.Info("latest block", "number", latestBlock)

	// Initialize storage
	app.logger.Info("initializing db", "db_backend", app.config.DbBackend, "db_path", app.config.DbPath)
	app.kvDB, err = db.NewDB(dbName, app.config.DbBackend, app.config.DbPath)
	if err != nil {
		return fmt.Errorf("create storage DB: %w", err)
	}

	app.registryService = zkregistry.InitializeService(app.kvDB, app.ethereumClient)

	// Apply all ZK Registry addresses to the index
	app.jobs = []indexer.JobDescriptor{}

	// Configure V1 contracts
	v1Jobs, err := app.configureZkCertificateRegistry(ctx, app.config.ZkCertificateRegistry)
	if err != nil {
		return fmt.Errorf("configure zk certificate registry: %w", err)
	}
	app.jobs = append(app.jobs, v1Jobs...)

	// Configure V2 contracts
	v2Jobs, err := app.configureZkCertificateRegistryV2(ctx, app.config.ZkCertificateRegistryV2)
	if err != nil {
		return fmt.Errorf("configure zk certificate registry v2: %w", err)
	}
	app.jobs = append(app.jobs, v2Jobs...)

	if len(app.jobs) == 0 {
		return fmt.Errorf("no jobs to apply, please specify at least one zk certificate registry address")
	}

	app.jobStorage = indexer.NewJobStorage(app.kvDB)
	app.evmIndexer = indexer.NewEVMIndexer(app.ethereumClient, app.config.IndexerConfig, app.logger)
	app.jobFactory = indexer.NewJobFactory(
		app.ethereumClient,
		app.registryService,
		app.jobStorage,
		app.kvDB,
		app.logger,
	)

	app.queryServer = query.NewServer(app.registryService, app.logger)

	return nil
}

func (app *Application) RunQueryServerGRPC(ctx context.Context) error {
	return app.queryServer.RunGRPC(ctx, app.config.QueryServer.GRPC.Address)
}

func (app *Application) RunQueryServerGRPCGateway(ctx context.Context) error {
	return app.queryServer.RunGateway(ctx, app.config.QueryServer.GRPCGateway.Address)

}

func (app *Application) RunIndexer(ctx context.Context) error {
	var err error

	// run the jobs
	app.configurator, err = indexer.InitConfiguratorFromStorage(
		ctx,
		app.jobStorage,
		app.jobFactory,
		app.evmIndexer,
		app.jobs,
		app.logger,
	)
	if err != nil {
		return fmt.Errorf("init configurator: %w", err)
	}

	// apply all jobs to the indexer
	if err := app.configurator.ReloadConfig(ctx, app.jobs); err != nil {
		return fmt.Errorf("start job: %w", err)
	}

	var jobErr error

	select {
	case <-ctx.Done():
		app.logger.Info("shutting down indexer server")
		<-app.configurator.Wait()

	case err = <-app.configurator.Wait():
		if err != nil {
			jobErr = err
		}
	}

	// report for every job the last known block
	ctxReport, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finishedJobs, err := app.jobStorage.SelectAllJobs(ctxReport)
	if err != nil {
		return fmt.Errorf("select all jobs: %w", err)
	}
	for _, job := range finishedJobs {
		app.logger.Info("job finished", "job", job.String())
	}

	app.logger.Info("indexer server stopped")

	return jobErr
}

// configureZkCertificateRegistry configures the ZK Certificate Registry jobs
func (app *Application) configureZkCertificateRegistry(ctx context.Context, configs []ContractConfig) ([]indexer.JobDescriptor, error) {
	jobs := make([]indexer.JobDescriptor, 0, len(configs))
	for _, config := range configs {
		registry, err := app.registryService.InitializeRegistry(ctx, config.Address)
		if err != nil {
			return nil, fmt.Errorf("initialize registry for address %s: %w", config.Address.Hex(), err)
		}

		app.logger.Info(
			"initialized registry",
			"address", config.Address.Hex(),
			"tree_depth", registry.Metadata().Depth,
			"description", registry.Metadata().Description,
			"init_block_height", registry.Metadata().InitBlockHeight,
		)

		// Use override start block if provided, otherwise use contract's InitBlockHeight
		var startBlock uint64
		if config.StartBlock != nil {
			startBlock = *config.StartBlock
			app.logger.Info(
				"using override start block",
				"address", config.Address.Hex(),
				"override_block", startBlock,
				"contract_init_block", registry.Metadata().InitBlockHeight,
			)
		} else {
			startBlock = registry.Metadata().InitBlockHeight
			if startBlock > 0 {
				// start from the previous block to avoid missing events in first initialization
				startBlock--
			}
		}

		job := indexer.JobDescriptor{
			Address:    config.Address,
			Contract:   indexer.ContractZkCertificateRegistry,
			StartBlock: startBlock,
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

// configureZkCertificateRegistryV2 configures the ZK Certificate Registry V2 jobs
func (app *Application) configureZkCertificateRegistryV2(ctx context.Context, configs []ContractConfig) ([]indexer.JobDescriptor, error) {
	jobs := make([]indexer.JobDescriptor, 0, len(configs))
	for _, config := range configs {
		registry, err := app.registryService.InitializeRegistry(ctx, config.Address)
		if err != nil {
			return nil, fmt.Errorf("initialize registry v2 for address %s: %w", config.Address.Hex(), err)
		}

		app.logger.Info(
			"initialized registry v2",
			"address", config.Address.Hex(),
			"tree_depth", registry.Metadata().Depth,
			"description", registry.Metadata().Description,
			"init_block_height", registry.Metadata().InitBlockHeight,
		)

		// Use override start block if provided, otherwise use contract's InitBlockHeight
		var startBlock uint64
		if config.StartBlock != nil {
			startBlock = *config.StartBlock
			app.logger.Info(
				"using override start block",
				"address", config.Address.Hex(),
				"override_block", startBlock,
				"contract_init_block", registry.Metadata().InitBlockHeight,
			)
		} else {
			startBlock = registry.Metadata().InitBlockHeight
			if startBlock > 0 {
				// start from the previous block to avoid missing events in first initialization
				startBlock--
			}
		}

		job := indexer.JobDescriptor{
			Address:    config.Address,
			Contract:   indexer.ContractZkCertificateRegistryV2,
			StartBlock: startBlock,
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}
