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

package merkle

import (
	"sync"

	db "github.com/cometbft/cometbft-db"
	"github.com/holiman/uint256"
)

type (
	// BatchWithLeavesBuffer is a wrapper around db.Batch that allows reading leaf nodes from the buffer.
	BatchWithLeavesBuffer struct {
		db.Batch
		treeIndex TreeIndex
		buffer    map[[LeafKeyLength]byte]*uint256.Int
		mu        sync.RWMutex
	}
)

func NewBatchWithLeavesBuffer(batch db.Batch, treeIndex TreeIndex) *BatchWithLeavesBuffer {
	return &BatchWithLeavesBuffer{
		Batch:     batch,
		treeIndex: treeIndex,
		buffer:    make(map[[LeafKeyLength]byte]*uint256.Int),
		mu:        sync.RWMutex{},
	}
}

// SetLeaf sets the leaf node at the given level and index to the given value to the buffer.
// The value is not written to the database until the batch is committed.
// Call batch.Write() or batch.WriteSync() to write the changes to the database.
func (b *BatchWithLeavesBuffer) SetLeaf(level TreeLevel, index LeafIndex, value *uint256.Int) error {
	key := makeLeafKey(b.treeIndex, level, index)

	b.mu.Lock()
	b.buffer[[LeafKeyLength]byte(key[:LeafKeyLength])] = value
	b.mu.Unlock()

	return b.Set(key, value.Bytes())
}

// GetLeaf reads the leaf node at the given level and index from the buffer.
// If the leaf node is not found in the buffer, it is returned an error ErrNotFound.
func (b *BatchWithLeavesBuffer) GetLeaf(level TreeLevel, index LeafIndex) (*uint256.Int, error) {
	key := makeLeafKey(b.treeIndex, level, index)

	b.mu.RLock()
	value, ok := b.buffer[[LeafKeyLength]byte(key[:LeafKeyLength])]
	b.mu.RUnlock()

	if ok {
		return value, nil
	}

	return nil, ErrNotFound
}
