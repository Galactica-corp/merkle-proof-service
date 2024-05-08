/*
 * Copyright 2024 Galactica Network
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
		ZkCertificateRegistry []common.Address

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

	return nil
}

// Init initializes the application and all its dependencies
func (app *Application) Init(ctx context.Context) error {
	app.logger.Info("connecting to EVM RPC", "evm_rpc", app.config.EvmRpc)
	if err := backoff.Retry(func() error {
		var err error
		app.ethereumClient, err = ethclient.DialContext(ctx, app.config.EvmRpc)

		return err
	}, backoff.NewExponentialBackOff()); err != nil {
		app.logger.Error("connect via RPC", "error", err)
		return fmt.Errorf("connect via RPC: %w", err)
	}

	app.logger.Info("connected to EVM RPC")

	ctxGetBlock, cancelGetBlock := context.WithTimeout(ctx, 15*time.Second)
	defer cancelGetBlock()

	latestBlock, err := app.ethereumClient.BlockByNumber(ctxGetBlock, nil)
	if err != nil {
		app.logger.Error("get latest block", "error", err)
		return fmt.Errorf("get latest block: %w", err)
	}
	app.logger.Info("latest block", "number", latestBlock.Number().Uint64())

	// Initialize storage
	app.logger.Info("initializing db", "db_backend", app.config.DbBackend, "db_path", app.config.DbPath)
	app.kvDB, err = db.NewDB(dbName, app.config.DbBackend, app.config.DbPath)
	if err != nil {
		return fmt.Errorf("create storage DB: %w", err)
	}

	app.registryService = zkregistry.InitializeService(app.kvDB, app.ethereumClient)

	// Apply all ZK Registry addresses to the index
	app.jobs, err = app.configureZkCertificateRegistry(ctx, app.config.ZkCertificateRegistry)
	if err != nil {
		return fmt.Errorf("configure zk certificate registry: %w", err)
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

	return jobErr
}

// configureZkCertificateRegistry configures the ZK Certificate Registry jobs
func (app *Application) configureZkCertificateRegistry(ctx context.Context, addresses []common.Address) ([]indexer.JobDescriptor, error) {
	jobs := make([]indexer.JobDescriptor, 0, len(addresses))
	for _, address := range addresses {
		registry, err := app.registryService.InitializeRegistry(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("initialize registry for address %s: %w", address.Hex(), err)
		}

		app.logger.Info(
			"initialized registry",
			"address", address.Hex(),
			"tree_depth", registry.Metadata().Depth,
			"description", registry.Metadata().Description,
			"init_block_height", registry.Metadata().InitBlockHeight,
		)

		initBlockHeight := registry.Metadata().InitBlockHeight
		if initBlockHeight > 0 {
			// start from the previous block to avoid missing events in first initialization
			initBlockHeight--
		}

		job := indexer.JobDescriptor{
			Address:    address,
			Contract:   indexer.ContractZkCertificateRegistry,
			StartBlock: initBlockHeight,
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}
