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
	"fmt"
	"path/filepath"
	"strings"
	"time"

	db "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Galactica-corp/merkle-proof-service/cmd/galacticad-merkle/cmd/ctx"
	"github.com/Galactica-corp/merkle-proof-service/internal/indexer"
	"github.com/Galactica-corp/merkle-proof-service/internal/query"
	"github.com/Galactica-corp/merkle-proof-service/internal/utils"
	pkgindexer "github.com/Galactica-corp/merkle-proof-service/pkg/indexer"
)

const (
	evmRpcFlag  = "evm-rpc"
	evmRpcEnv   = "EVM_RPC"
	evmRpcViper = "evm_rpc"

	grpcAddressFlag  = "grpc.address"
	grpcAddressViper = "grpc.address"
	grpcAddressEnv   = "GRPC_ADDRESS"

	grpcGatewayAddressFlag  = "grpc-gateway.address"
	grpcGatewayAddressViper = "grpc_gateway.address"
	grpcGatewayAddressEnv   = "GRPC_GATEWAY_ADDRESS"

	indexerMode                  = "indexer.mode"
	indexerPollingInterval       = "indexer.polling_interval"
	indexerMaxBlocksDistanceFlag = "indexer.max_blocks_distance"
	indexerSinkChannelSizeFlag   = "indexer.sink_channel_size"
	indexerSinkProgressTickFlag  = "indexer.sink_progress_tick"

	zkCertificateRegistryViper   = "zk_certificate_registry"
	zkCertificateRegistryV2Viper = "zk_certificate_registry_v2"

	defaultEvmRpc = "ws://localhost:8546"

	dbFolder = "db"
)

func CreateStartCmd() *cobra.Command {
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the indexer",
		Long:  `Start the indexer with the specified EVM RPC endpoint.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			evmRpc := viper.GetString(evmRpcViper)
			if evmRpc == "" {
				return fmt.Errorf("EVM RPC endpoint is required")
			}

			logger, ok := cmd.Context().Value(ctx.LoggerKey).(log.Logger)
			if !ok {
				return fmt.Errorf("logger not found in context")
			}

			homeDir, ok := cmd.Context().Value(ctx.HomeDirKey).(string)
			if !ok {
				return fmt.Errorf("home dir not found in context")
			}

			dbBackend, ok := cmd.Context().Value(ctx.DBBackendKey).(db.BackendType)
			if !ok {
				return fmt.Errorf("db backend not found in context")
			}

			dbPath := filepath.Join(homeDir, dbFolder)

			zkCertificateRegistry, err := getZkCertificateRegistry()
			if err != nil {
				return fmt.Errorf("zk certificate registry: %w", err)
			}

			zkCertificateRegistryV2, err := getZkCertificateRegistryV2()
			if err != nil {
				return fmt.Errorf("zk certificate registry v2: %w", err)
			}

			appConfig := pkgindexer.ApplicationConfig{
				EvmRpc:                  evmRpc,
				DbPath:                  dbPath,
				DbBackend:               dbBackend,
				ZkCertificateRegistry:   zkCertificateRegistry,
				ZkCertificateRegistryV2: zkCertificateRegistryV2,
				QueryServer:             getQueryServerConfig(),
				IndexerConfig:           getIndexConfig(),
			}

			// check if the indexer mode are compatible with the EVM RPC endpoint
			if appConfig.IndexerConfig.IndexerMode == indexer.ModeWS && !strings.HasPrefix(evmRpc, "ws") {
				logger.Error("current indexer mode is ws, but EVM RPC endpoint is not supported websocket", "evm_rpc", evmRpc)
				logger.Info("switching indexer mode to poll")
				appConfig.IndexerConfig.IndexerMode = indexer.ModePoll
			}

			for {
				if err := pkgindexer.StartApplication(cmd.Context(), appConfig, logger); err != nil {
					logger.Error("service produced an error", "error", err)
				}

				needStop := false
				select {
				case <-cmd.Context().Done():
					needStop = true
				default:
				}

				if !needStop {
					logger.Error("restarting application in 5 seconds")
					<-time.After(5 * time.Second)
				} else {
					logger.Info("stopping application")
					break
				}
			}

			logger.Info("gracefully stopped indexer server")

			return nil
		},
	}

	initFlags(startCmd)

	return startCmd
}

func initFlags(indexerStartCmd *cobra.Command) {
	indexerStartCmd.Flags().String(evmRpcFlag, defaultEvmRpc, "EVM RPC endpoint")
	indexerStartCmd.Flags().String(grpcAddressFlag, query.GrpcServerAddr, "gRPC server address")
	indexerStartCmd.Flags().String(grpcGatewayAddressFlag, query.GatewayAddr, "gRPC gateway address")
	indexerStartCmd.Flags().String(indexerMode, string(indexer.ModePoll), "indexer mode, either 'poll' or 'ws'")
	indexerStartCmd.Flags().Duration(indexerPollingInterval, indexer.PollingInterval, "indexer polling interval for the 'poll' mode")
	indexerStartCmd.Flags().Uint64(indexerMaxBlocksDistanceFlag, indexer.MaxBlocksDistance, "max blocks distance to retrieve logs from the EVM node")
	indexerStartCmd.Flags().Uint(indexerSinkChannelSizeFlag, indexer.SinkSize, "indexer sink channel buffer size for the 'ws' mode")
	indexerStartCmd.Flags().Duration(indexerSinkProgressTickFlag, indexer.SinkProgressTick, "indexer sink progress tick duration for the 'ws' mode")
	indexerStartCmd.Flags().StringSlice(zkCertificateRegistryViper, []string{}, "zk certificate registry contract addresses list")
	indexerStartCmd.Flags().StringSlice(zkCertificateRegistryV2Viper, []string{}, "zk certificate registry v2 contract addresses list")

	utils.MustBindPFlag(viper.GetViper(), evmRpcViper, indexerStartCmd.Flags().Lookup(evmRpcFlag))
	utils.MustBindPFlag(viper.GetViper(), grpcAddressViper, indexerStartCmd.Flags().Lookup(grpcAddressFlag))
	utils.MustBindPFlag(viper.GetViper(), grpcGatewayAddressViper, indexerStartCmd.Flags().Lookup(grpcGatewayAddressFlag))
	utils.MustBindPFlag(viper.GetViper(), indexerMode, indexerStartCmd.Flags().Lookup(indexerMode))
	utils.MustBindPFlag(viper.GetViper(), indexerPollingInterval, indexerStartCmd.Flags().Lookup(indexerPollingInterval))
	utils.MustBindPFlag(viper.GetViper(), indexerMaxBlocksDistanceFlag, indexerStartCmd.Flags().Lookup(indexerMaxBlocksDistanceFlag))
	utils.MustBindPFlag(viper.GetViper(), indexerSinkChannelSizeFlag, indexerStartCmd.Flags().Lookup(indexerSinkChannelSizeFlag))
	utils.MustBindPFlag(viper.GetViper(), indexerSinkProgressTickFlag, indexerStartCmd.Flags().Lookup(indexerSinkProgressTickFlag))
	utils.MustBindPFlag(viper.GetViper(), zkCertificateRegistryViper, indexerStartCmd.Flags().Lookup(zkCertificateRegistryViper))
	utils.MustBindPFlag(viper.GetViper(), zkCertificateRegistryV2Viper, indexerStartCmd.Flags().Lookup(zkCertificateRegistryV2Viper))

	viper.MustBindEnv(evmRpcViper, evmRpcEnv)
	viper.MustBindEnv(grpcAddressViper, grpcAddressEnv)
	viper.MustBindEnv(grpcGatewayAddressViper, grpcGatewayAddressEnv)
}

func getZkCertificateRegistry() ([]common.Address, error) {
	addresses := viper.GetStringSlice(zkCertificateRegistryViper)
	if len(addresses) == 0 {
		return nil, nil
	}

	var contractAddresses []common.Address
	for _, address := range addresses {
		if !common.IsHexAddress(address) {
			return nil, fmt.Errorf("invalid address: %s", address)
		}

		contractAddresses = append(contractAddresses, common.HexToAddress(address))
	}

	return contractAddresses, nil
}

func getZkCertificateRegistryV2() ([]common.Address, error) {
	addresses := viper.GetStringSlice(zkCertificateRegistryV2Viper)
	if len(addresses) == 0 {
		return nil, nil
	}

	var contractAddresses []common.Address
	for _, address := range addresses {
		if !common.IsHexAddress(address) {
			return nil, fmt.Errorf("invalid address: %s", address)
		}

		contractAddresses = append(contractAddresses, common.HexToAddress(address))
	}

	return contractAddresses, nil
}

func getQueryServerConfig() pkgindexer.QueryServerConfig {
	return pkgindexer.QueryServerConfig{
		GRPC: struct{ Address string }{
			Address: viper.GetString(grpcAddressViper),
		},
		GRPCGateway: struct{ Address string }{
			Address: viper.GetString(grpcGatewayAddressViper),
		},
	}
}

func getIndexConfig() indexer.Config {
	return indexer.Config{
		IndexerMode:       indexer.Mode(viper.GetString(indexerMode)),
		PollingInterval:   viper.GetDuration(indexerPollingInterval),
		MaxBlocksDistance: viper.GetUint64(indexerMaxBlocksDistanceFlag),
		SinkChannelSize:   viper.GetUint(indexerSinkChannelSizeFlag),
		SinkProgressTick:  viper.GetDuration(indexerSinkProgressTickFlag),
	}
}
