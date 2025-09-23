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

	db "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/Galactica-corp/merkle-proof-service/internal/zkregistry"
)

type (
	JobHandler interface {
		PrepareContext(ctx context.Context) (context.Context, error)
		HandleEVMLog(ctx context.Context, log types.Log) error
		Commit(ctx context.Context, block uint64) error
		FilterQuery() (ethereum.FilterQuery, error)
		JobDescriptor() JobDescriptor
		OnIndexerModeChange(mode Mode)
	}

	DBBatchCreator interface {
		NewBatch() db.Batch
	}

	JobUpdater interface {
		UpsertJob(_ context.Context, store StoreSetter, job Job) error
	}

	// JobFactory is a factory that produces event handlers based on provided contract.
	JobFactory struct {
		client          bind.ContractFilterer
		registryService *zkregistry.Service
		jobUpdater      JobUpdater
		batchCreator    DBBatchCreator
		logger          log.Logger
	}
)

func NewJobFactory(
	client bind.ContractFilterer,
	registryService *zkregistry.Service,
	jobUpdater JobUpdater,
	batchCreator DBBatchCreator,
	logger log.Logger,
) *JobFactory {
	return &JobFactory{
		client:          client,
		registryService: registryService,
		jobUpdater:      jobUpdater,
		batchCreator:    batchCreator,
		logger:          logger,
	}
}

// Produce creates a new event handler based on provided job descriptor.
func (f *JobFactory) Produce(ctx context.Context, jobDescriptor JobDescriptor) (JobHandler, error) {
	switch jobDescriptor.Contract {
	case ContractZkCertificateRegistry:
		registry, err := f.registryService.ZKCertificateRegistry(ctx, jobDescriptor.Address)
		if err != nil {
			return nil, fmt.Errorf("get zk certificate registry for address %s: %w", jobDescriptor.Address, err)
		}

		return NewZkCertificateRegistryJob(jobDescriptor, f.jobUpdater, f.batchCreator, registry, f.logger), nil

	case ContractZkCertificateRegistryV2:
		registry, err := f.registryService.ZKCertificateRegistry(ctx, jobDescriptor.Address)
		if err != nil {
			return nil, fmt.Errorf("get zk certificate registry v2 for address %s: %w", jobDescriptor.Address, err)
		}

		return NewZkCertificateRegistryV2Job(jobDescriptor, f.jobUpdater, f.batchCreator, registry, f.logger), nil

	default:
		return nil, fmt.Errorf("unknown contract: %s", jobDescriptor.Contract)
	}
}
