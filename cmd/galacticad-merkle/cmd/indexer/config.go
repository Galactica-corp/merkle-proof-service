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
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	pkgindexer "github.com/Galactica-corp/merkle-proof-service/pkg/indexer"
)

// parseContractConfigsToPackageType parses the contract configuration from viper
// Supports both formats:
// - Simple string array: ["0xAddr1", "0xAddr2"]
// - Extended format: [{"address": "0xAddr1", "start_block": 12345}, "0xAddr2"]
func parseContractConfigsToPackageType(rawConfigs []any) ([]pkgindexer.ContractConfig, error) {
	var configs []pkgindexer.ContractConfig

	for i, rawConfig := range rawConfigs {
		switch v := rawConfig.(type) {
		case string:
			// Simple address string
			if !common.IsHexAddress(v) {
				return nil, fmt.Errorf("invalid address at index %d: %s", i, v)
			}
			configs = append(configs, pkgindexer.ContractConfig{
				Address:    common.HexToAddress(v),
				StartBlock: nil,
			})

		case map[string]any:
			// Extended format with optional start_block
			addressRaw, ok := v["address"]
			if !ok {
				return nil, fmt.Errorf("missing 'address' field at index %d", i)
			}

			addressStr, ok := addressRaw.(string)
			if !ok {
				return nil, fmt.Errorf("'address' must be a string at index %d", i)
			}

			if !common.IsHexAddress(addressStr) {
				return nil, fmt.Errorf("invalid address at index %d: %s", i, addressStr)
			}

			config := pkgindexer.ContractConfig{
				Address: common.HexToAddress(addressStr),
			}

			// Check for optional start_block
			if startBlockRaw, exists := v["start_block"]; exists {
				// Handle different numeric types that viper might return
				var startBlock uint64
				switch sb := startBlockRaw.(type) {
				case float64:
					startBlock = uint64(sb)
				case int:
					startBlock = uint64(sb)
				case int64:
					startBlock = uint64(sb)
				case uint64:
					startBlock = sb
				default:
					return nil, fmt.Errorf("'start_block' must be a number at index %d", i)
				}
				config.StartBlock = &startBlock
			}

			configs = append(configs, config)

		default:
			return nil, fmt.Errorf("invalid configuration format at index %d: must be string or object", i)
		}
	}

	return configs, nil
}
