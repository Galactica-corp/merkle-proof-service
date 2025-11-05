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

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	db "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Galactica-corp/merkle-proof-service/cmd/galacticad-merkle/cmd/ctx"
	"github.com/Galactica-corp/merkle-proof-service/cmd/galacticad-merkle/cmd/indexer"
	"github.com/Galactica-corp/merkle-proof-service/internal/utils"
)

const (
	FlagHome  = "home"
	EnvHome   = "MERKLE_HOME"
	ViperHome = "home"

	FlagConfig  = "config"
	EnvConfig   = "MERKLE_CONFIG"
	ViperConfig = "config"

	FlagDBBackend  = "db-backend"
	EvnDBBackend   = "DB_BACKEND"
	ViperDBBackend = "db_backend"

	FlagLogLevel    = "log-level"
	EvnLogLevel     = "LOG_LEVEL"
	ViperLogLevel   = "log_level"
	DefaultLogLevel = "info"

	DefaultHomeSubDir     = ".galacticad-merkle"
	DefaultConfigFileName = "merkle-613419.yaml"
)

type Config struct {
	Home      string
	Config    string
	LogLevel  string
	DBBackend db.BackendType
}

func createRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "galacticad-merkle",
		Short: "Galactica Network merkle cli",
		Long: `Galactica Network merkle cli.
This is a CLI tool to interact with the Galactica Network merkle service.`,
	}
}

func Execute() {
	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	rootCmd := initRootCmd(createRootCmd())
	if err := rootCmd.ExecuteContext(rootCtx); err != nil {
		fmt.Println(err)
	}
}

func initRootCmd(rootCmd *cobra.Command) *cobra.Command {
	cfg := Config{}

	// root command flags
	rootCmd.PersistentFlags().StringVar(
		&cfg.Home,
		FlagHome,
		"",
		"home directory (default is $HOME/"+DefaultHomeSubDir+")",
	)
	rootCmd.PersistentFlags().StringVar(
		&cfg.Config,
		FlagConfig,
		"",
		"config file (default is $HOME/"+DefaultHomeSubDir+"/"+DefaultConfigFileName+")",
	)
	rootCmd.PersistentFlags().StringVar(
		&cfg.LogLevel,
		FlagLogLevel,
		DefaultLogLevel,
		"log level, available options: [debug, info, error, none]",
	)
	rootCmd.PersistentFlags().String(
		FlagDBBackend,
		string(db.GoLevelDBBackend),
		"database backend, available options: "+dbBackendsString(),
	)

	// bind flags to viper
	utils.MustBindPFlag(viper.GetViper(), ViperHome, rootCmd.PersistentFlags().Lookup(FlagHome))
	utils.MustBindPFlag(viper.GetViper(), ViperConfig, rootCmd.PersistentFlags().Lookup(FlagConfig))
	utils.MustBindPFlag(viper.GetViper(), ViperLogLevel, rootCmd.PersistentFlags().Lookup(FlagLogLevel))
	utils.MustBindPFlag(viper.GetViper(), ViperDBBackend, rootCmd.PersistentFlags().Lookup(FlagDBBackend))

	// bind env variables to viper
	viper.MustBindEnv(ViperHome, EnvHome)
	viper.MustBindEnv(ViperConfig, EnvConfig)
	viper.MustBindEnv(ViperLogLevel, EvnLogLevel)
	viper.MustBindEnv(ViperDBBackend, EvnDBBackend)

	// init config

	// set logger to root command
	writer := log.NewSyncWriter(os.Stdout)
	rootCmd.SetOut(writer)
	rootCmd.SetErr(writer)

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if initedCfg, err := initConfig(cfg); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			cfg = initedCfg
		}

		// init logger
		logger := initLogger(cfg.LogLevel, writer)

		cmd.SetContext(context.WithValue(cmd.Context(), ctx.LoggerKey, logger))
		cmd.SetContext(context.WithValue(cmd.Context(), ctx.HomeDirKey, cfg.Home))
		cmd.SetContext(context.WithValue(cmd.Context(), ctx.DBBackendKey, cfg.DBBackend))
	}

	// add subcommands
	rootCmd.AddCommand(indexer.CreateIndexerCmd())

	// add version command
	rootCmd.AddCommand(CreateVersion())

	return rootCmd
}

func initLogger(
	level string,
	writer io.Writer,
) log.Logger {
	logger := log.NewTMLogger(writer)
	logLevel, err := log.AllowLevel(level)
	if err != nil {
		level = DefaultLogLevel
		logLevel, err = log.AllowLevel(level)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
	logger = log.NewFilter(logger, logLevel)

	return logger
}

func initConfig(cfg Config) (Config, error) {
	if home := viper.GetString(FlagHome); home != "" {
		cfg.Home = home
	} else {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return cfg, fmt.Errorf("failed to get user home directory: %w", err)
		}

		cfg.Home = filepath.Join(userHome, DefaultHomeSubDir)
	}

	if config := viper.GetString(FlagConfig); config != "" {
		cfg.Config = config
	} else {
		cfg.Config = filepath.Join(cfg.Home, DefaultConfigFileName)
	}

	viper.AddConfigPath(cfg.Home)
	viper.SetConfigFile(cfg.Config)

	// no need to return error if config file not found
	_ = viper.ReadInConfig()

	// set log level
	cfg.LogLevel = viper.GetString(ViperLogLevel)

	// set db backend
	cfg.DBBackend = db.BackendType(viper.GetString(ViperDBBackend))
	if !slices.Contains(availableDBBackends(), cfg.DBBackend) {
		return cfg, fmt.Errorf("invalid db backend %s, expected one of %s", cfg.DBBackend, dbBackendsString())
	}

	return cfg, nil
}

func availableDBBackends() []db.BackendType {
	return []db.BackendType{
		db.GoLevelDBBackend,
		db.CLevelDBBackend,
		db.MemDBBackend,
		db.BoltDBBackend,
		db.RocksDBBackend,
		db.BadgerDBBackend,
		db.PebbleDBBackend,
	}
}

func dbBackendsString() string {
	backends := availableDBBackends()
	strs := make([]string, 0, len(backends))
	for _, backend := range backends {
		strs = append(strs, string(backend))
	}
	return fmt.Sprintf("[%s]", filepath.Join(strs...))
}
