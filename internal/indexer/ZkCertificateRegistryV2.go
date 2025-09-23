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
	"math/big"

	db "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"

	"github.com/Galactica-corp/merkle-proof-service/internal/contract/ZkCertificateRegistryV2"
	"github.com/Galactica-corp/merkle-proof-service/internal/zkregistry"
)

const (
	// EventOperationQueued is emitted when an operation is added to the queue
	EventOperationQueued = "OperationQueued"
	// EventCertificateProcessed is emitted when an operation is processed from the queue
	EventCertificateProcessed = "CertificateProcessed"
)

type (
	// ZkCertificateRegistryV2Job handles events from the V2 contract which uses a queue-based system.
	// Unlike V1 which processes additions/revocations immediately, V2 queues operations first
	// and then processes them, emitting CertificateProcessed events when complete.
	ZkCertificateRegistryV2Job struct {
		jobDescriptor JobDescriptor
		jobUpdater    JobUpdater
		batchCreator  DBBatchCreator
		registry      *zkregistry.ZKCertificateRegistry

		logger log.Logger
		parser *ZkCertificateRegistryV2.ZkCertificateRegistryFilterer
	}
)

func NewZkCertificateRegistryV2Job(
	jobDescriptor JobDescriptor,
	jobUpdater JobUpdater,
	dbBatchCreator DBBatchCreator,
	registry *zkregistry.ZKCertificateRegistry,
	logger log.Logger,
) *ZkCertificateRegistryV2Job {
	return &ZkCertificateRegistryV2Job{
		jobDescriptor: jobDescriptor,
		jobUpdater:    jobUpdater,
		batchCreator:  dbBatchCreator,
		registry:      registry,
		logger:        logger,
	}
}

// PrepareContext prepares the context for the job.
func (job *ZkCertificateRegistryV2Job) PrepareContext(ctx context.Context) (context.Context, error) {
	return WithOperationsBuffer(ctx, zkregistry.NewOperationsBuffer()), nil
}

// HandleEVMLog handles the EVM log and updates the leaves buffer.
func (job *ZkCertificateRegistryV2Job) HandleEVMLog(ctx context.Context, log types.Log) error {
	contractABI, err := ZkCertificateRegistryV2.ZkCertificateRegistryMetaData.GetAbi()
	if err != nil {
		return fmt.Errorf("get abi: %w", err)
	}

	if log.Removed {
		// Do not process removed logs because Cosmos SDK does not chain reorgs.
		// TODO: implement if needed for other blockchains.
		return nil
	}

	switch log.Topics[0] {
	case contractABI.Events[EventCertificateProcessed].ID:
		if err := job.handleCertificateProcessedLog(ctx, log); err != nil {
			return fmt.Errorf("handle CertificateProcessed log: %w", err)
		}

	case contractABI.Events[EventOperationQueued].ID:
		// For now, we only care about processed certificates, not queued operations
		job.logger.Debug("OperationQueued event received but not processed", "tx", log.TxHash.Hex())

	default:
		// Skip unknown events
	}

	return nil
}

func (job *ZkCertificateRegistryV2Job) handleCertificateProcessedLog(ctx context.Context, log types.Log) error {
	contractABI, err := ZkCertificateRegistryV2.ZkCertificateRegistryMetaData.GetAbi()
	if err != nil {
		return fmt.Errorf("get abi: %w", err)
	}

	operationsBuffer, ok := OperationsBufferFromContext(ctx)
	if !ok {
		return fmt.Errorf("operations buffer not found in context")
	}
	event := contractABI.Events[EventCertificateProcessed]

	// Parse indexed fields
	if len(log.Topics) < 3 {
		return fmt.Errorf("insufficient topics for CertificateProcessed event")
	}

	zkCertHash := common.BytesToHash(log.Topics[1].Bytes())
	guardianAddress := common.BytesToAddress(log.Topics[2].Bytes())

	// Parse non-indexed fields
	type CertificateProcessedData struct {
		Operation  uint8
		QueueIndex *big.Int
		LeafIndex  *big.Int
	}

	var data CertificateProcessedData
	if err := contractABI.UnpackIntoInterface(&data, event.Name, log.Data); err != nil {
		return fmt.Errorf("unpack CertificateProcessed data: %w", err)
	}

	// Convert operation enum to our internal type
	// 0 = Add, 1 = Revoke in the V2 contract
	var operation zkregistry.Operation
	switch data.Operation {
	case 0:
		operation = zkregistry.OperationAddition
	case 1:
		operation = zkregistry.OperationRevocation
	default:
		return fmt.Errorf("unknown operation type: %d", data.Operation)
	}

	job.logger.Info(
		"certificate processed",
		"operation", operation,
		"zkCertHash", zkCertHash.Hex(),
		"guardian", guardianAddress.Hex(),
		"leafIndex", data.LeafIndex.String(),
		"queueIndex", data.QueueIndex.String(),
		"tx", log.TxHash.Hex(),
		"block", log.BlockNumber,
	)

	leafIndex := zkregistry.TreeLeafIndex(data.LeafIndex.Uint64())
	leaf, overflow := uint256.FromBig(new(big.Int).SetBytes(zkCertHash[:]))
	if overflow {
		return fmt.Errorf("leaf hash overflow for index %d", leafIndex)
	}

	switch operation {
	case zkregistry.OperationAddition:
		if err := operationsBuffer.AppendAddition(leafIndex, leaf); err != nil {
			return fmt.Errorf("append addition: %w", err)
		}
	case zkregistry.OperationRevocation:
		if err := operationsBuffer.AppendRevocation(leafIndex, leaf); err != nil {
			return fmt.Errorf("append revocation: %w", err)
		}
	}

	return nil
}

// Commit commits the buffer to the database.
func (job *ZkCertificateRegistryV2Job) Commit(ctx context.Context, block uint64) error {
	operationsBuffer, ok := OperationsBufferFromContext(ctx)
	if !ok {
		return fmt.Errorf("operations buffer not found in context")
	}

	batch := job.batchCreator.NewBatch()
	operations := operationsBuffer.Operations()

	if len(operations) > 0 {
		if err := job.registry.CommitOperations(ctx, batch, operations); err != nil {
			return fmt.Errorf("commit operations: %w", err)
		}

		job.logger.Info(
			"job committing operations",
			"job", job.jobDescriptor.String(),
			"operations", len(operations),
			"block", block,
		)
	}

	// update the job's current block in order to resume from the last known block later
	if err := job.jobUpdater.UpsertJob(ctx, batch, Job{
		JobDescriptor: job.jobDescriptor,
		CurrentBlock:  block,
	}); err != nil {
		return fmt.Errorf("update job's current block: %w", err)
	}

	if err := job.writeBatchWithLock(batch); err != nil {
		return fmt.Errorf("write batch with lock: %w", err)
	}

	job.logger.Info("job progress", "job", job.jobDescriptor.String(), "block", block)

	return nil
}

// writeBatchWithLock writes the batch to the database with a lock on the tree index.
func (job *ZkCertificateRegistryV2Job) writeBatchWithLock(batch db.Batch) error {
	// we need to lock the tree index to prevent reading the tree while it is being updated
	job.registry.Mutex().Lock()
	defer job.registry.Mutex().Unlock()

	return batch.WriteSync()
}

// FilterQuery returns the filter query for the job.
func (job *ZkCertificateRegistryV2Job) FilterQuery() (ethereum.FilterQuery, error) {
	contractABI, err := ZkCertificateRegistryV2.ZkCertificateRegistryMetaData.GetAbi()
	if err != nil {
		return ethereum.FilterQuery{}, fmt.Errorf("get abi: %w", err)
	}

	topics, err := abi.MakeTopics(
		[]interface{}{
			contractABI.Events[EventCertificateProcessed].ID,
			contractABI.Events[EventOperationQueued].ID,
		},
	)
	if err != nil {
		return ethereum.FilterQuery{}, fmt.Errorf("make topics: %w", err)
	}

	query := ethereum.FilterQuery{
		Addresses: []common.Address{job.jobDescriptor.Address},
		Topics:    topics,
	}

	return query, nil
}

// JobDescriptor returns the job descriptor for the job.
func (job *ZkCertificateRegistryV2Job) JobDescriptor() JobDescriptor {
	return job.jobDescriptor
}

// OnIndexerModeChange is called when the indexer mode changes.
func (job *ZkCertificateRegistryV2Job) OnIndexerModeChange(mode Mode) {
	progressTracker := job.registry.ProgressTracker()
	if progressTracker == nil {
		return
	}

	// Update progress tracker based on mode
	switch mode {
	case ModeWS, ModePoll:
		if !progressTracker.IsOnHead() {
			progressTracker.SetOnHead(true)
		}
	case ModeHistory:
		if progressTracker.IsOnHead() {
			progressTracker.SetOnHead(false)
		}
	}
}
