# Merkle Proof Service

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Galactica-corp/merkle-proof-service)](https://github.com/Galactica-corp/merkle-proof-service/releases)

The Merkle Proof Service is an advanced utility engineered to facilitate the indexing of Merkle trees derived from Ethereum Solidity contracts. It further provides an API, enabling the retrieval of Merkle proofs, inclusive of root and path details. The service is equipped with two distinct API interfaces: gRPC and gRPC-gateway, the latter being an implementation of OpenAPI v2.


## Building the Executable

The process of building the executable for the Merkle Proof Service involves utilizing the Makefile provided at the root of the project. The procedure is as follows:

1. Clone the repository to your local machine and navigate to the root directory of the project:
    ```bash
    git clone https://github.com/Galactica-corp/merkle-proof-service.git
    cd merkle-proof-service
    ```

2. Execute the following command to build the binary:
    ```bash
    make build
    ```
   This operation will result in the creation of a binary named `galacticad-merkle` within the `build` directory.

3. Alternatively, the binary can be installed by executing the following command:
    ```bash
    make install
    ```

The `galacticad-merkle` binary can build with a variety of database backends by passing the `DB_BACKEND` variable to the `make build` command. For instance, to build `galacticad-merkle` with the `pebbledb` backend, the following command can be executed:

```bash
make build DB_BACKEND=pebbledb
```

The database backends available for selection include: `goleveldb`, `cleveldb`, `memdb`, `boltdb`, `rocksdb`, `badgerdb`, and `pebbledb`.

Each database backend possesses unique performance characteristics. For instance, `pebbledb` is recommended for production use due to its superior performance in reading data to generate the Merkle proof.

For testing purposes, the `memdb` backend is recommended. This backend stores data in memory, resulting in the fastest data write and read speeds.

## Running the Service

To run the service, you can use the built binary. Here's an example of how to start the indexer with a specified EVM RPC endpoint:

```bash
./build/galacticad-merkle indexer start --evm-rpc ws://localhost:8546
```

Here are the available flags for the `start` command:

- `--evm-rpc string`: EVM RPC endpoint (default "ws://localhost:8546")
- `--grpc-gateway.address string`: gRPC gateway server address (default "localhost:8480")
- `--grpc.address string`: gRPC server address (default "localhost:50651")
- `--indexer.max_blocks_distance uint`: max blocks distance to retrieve logs from the EVM node (default 10000)
- `--indexer.sink_channel_size uint`: indexer sink channel buffer size (default 100)
- `--indexer.sink_progress_tick duration`: indexer sink progress tick duration (default 5s)
- `--zk_certificate_registry strings`: zk certificate registry contract addresses list

And the global flags:

- `--home string`: home directory to store data (default is $HOME/.galacticad-merkle)
- `--config string`: config file (default is $HOME/.galacticad-merkle/merkle-613419.yaml)
- `--db-backend string`: database backend, available options: `goleveldb` (default), `cleveldb`, `memdb`, `boltdb`, `rocksdb`, `badgerdb`, `pebbledb`
- `--log-level string`: log level, available options: debug, info, error, none. Default is info


## API to Retrieve Merkle Proofs

The Merkle Proof Service provides two distinct API interfaces: `gRPC` and `gRPC-gateway`. The `gRPC-gateway` interface is an implementation of `OpenAPI v2`, which allows for the generation of client libraries in various programming languages.

### gRPC

The `gRPC` interface is available at `http://localhost:50651`. You cain find the gRPC query server definition in the following file: [proto/galactica/merkle/query.proto](proto/galactica/merkle/query.proto).

The service provides the following methods:

- `Proof`: Retrieves the Merkle proof for a given contract address and leaf value.
- `GetEmptyLeafProof`: Retrieves the random empty index with the Merkle proof for a given contract address.

### gRPC-gateway

By default, the `gRPC-gateway` interface is available at `http://localhost:8480`. The OpenAPI v2 specification can be accessed at `http://localhost:8480/swagger.json` and documentation can be viewed at `http://localhost:8480/docs`.

The service provides the following endpoints:

- `GET /v1/galactica/merkle/proof/{registry}/{leaf}`: Retrieves the Merkle proof for a given contract address and leaf value.
- `GET /v1/galactica/merkle/empty_proof/{registry}`: Retrieves the random empty index with the Merkle proof for a given contract address.

## Configuration

The Merkle Proof Service can be configured using a YAML file. By default, the configuration file is located at `$HOME/.galacticad-merkle/merkle-613419.yaml`. The configuration file can be customized to specify the database backend, log level, and other parameters.

Here is an example of the configuration file:

```yaml
log_level: info
evm_rpc: wss://galactica-mainnet.g.alchemy.com/public
db_backend: pebbledb
grpc:
  address: localhost:50651
grpc_gateway:
  address: localhost:8480
indexer:
  max_blocks_distance: 1000
  sink_channel_size: 100
  sink_progress_tick: 5s
zk_certificate_registry:
   - 0xbc196948e8c1Bc416aEaCf309a63DCEFfdf0cE31
```

### Ethereum contract configuration

The `zk_certificate_registry` field in the configuration file specifies the Ethereum contract addresses for the zk certificate registry. The Merkle Proof Service uses these contracts to fill the Merkle tree storage.
The initial block number fetching from the smart contract.

You can specify multiple contract addresses in the configuration file.

### Environment variables

The Merkle Proof Service can be configured using environment variables. The following environment variables can be used to configure the service:

- `MERKLE_HOME` - home directory to store data (default is `$HOME/.galacticad-merkle`)
- `MERKLE_CONFIG` - config file (default is `$HOME/.galacticad-merkle/merkle-613419.yaml`)
- `DB_BACKEND` - database backend, available options: `goleveldb` (default), `cleveldb`, `memdb`, `boltdb`, `rocksdb`, `badgerdb`, `pebbledb`
- `EVM_RPC` - EVM RPC endpoint (default `ws://localhost:8546`)
- `GRPC_ADDRESS` - gRPC server address (default `localhost:50651`)
- `GRPC_GATEWAY_ADDRESS` - gRPC gateway server address (default `localhost:8480`)

## Docker

The Merkle Proof Service can be run in a Docker container. To build the Docker image, execute the following command:

```bash
make docker-build DB_BACKEND=pebbledb
```

To run the Docker container, execute the following command:

```bash
docker run -d \
  --name merkle-proof-service \
  -p 50651:50651 \
  -p 8480:8480 \
  -e EVM_RPC=wss://evm-rpc-ws-reticulum.galactica.com \
  -e DB_BACKEND=pebbledb \
  -v $HOME/.galacticad-merkle:/root/.galacticad-merkle \
   Galactica-corp/merkle-proof-service
```

This command will start the Merkle Proof Service in a Docker container with the default configuration. You can customize the configuration by passing environment variables to the `docker run` command.

## License

The Merkle Proof Service is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.
