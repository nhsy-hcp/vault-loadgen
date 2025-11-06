# vault-loadgen

[![CI](https://github.com/nhsy/vault-loadgen/actions/workflows/ci.yml/badge.svg)](https://github.com/nhsy/vault-loadgen/actions/workflows/ci.yml)

A load generation tool for HashiCorp Vault.

`vault-loadgen` is a command-line tool designed to generate synthetic load on HashiCorp Vault clusters. It helps you test Vault's performance, stability, and scalability under various workloads. It supports multiple secret engines, concurrent operations, and both Vault Enterprise (multi-namespace) and Vault OSS (single-namespace) environments.

## Features

-   **Multiple Load Modes**: Generate load for different secret engines:
    -   `pki`: Create a large number of certificate leases.
    -   `approle`: Generate AppRole credentials and perform logins to create token leases.
    -   `kv`: Populate KVv2 engines with a large number of secrets.
-   **Concurrent Workloads**: Utilizes a configurable worker pool to generate load concurrently, simulating high-traffic scenarios.
-   **Vault Enterprise & OSS Support**:
    -   **Enterprise**: Full support for multi-namespace testing, distributing load across hundreds or thousands of child namespaces.
    -   **OSS**: Fully compatible with Vault Open Source for single-namespace (root) load testing.
-   **Rate Limiting**: Control the load precisely with a configurable rate limiter (`--rate-limit`) to avoid overwhelming Vault.
-   **Graceful Shutdown**: Handles interruptions (Ctrl+C) gracefully, ensuring a clean exit.
-   **Detailed Statistics**: Provides a summary of operations, including duration, success/failure counts, and operations per second.
-   **Flexible Configuration**: Configure via CLI flags, environment variables, or a YAML file.

## Installation

You can download a pre-built binary for your operating system from the [GitHub Releases](https://github.com/your-repo/vault-loadgen/releases) page.

Alternatively, you can build it from source.

## Building from Source

To build `vault-loadgen` from source, you need Go 1.21 or later.

1.  **Clone the repository:**

    ```sh
    git clone https://github.com/your-repo/vault-loadgen.git
    cd vault-loadgen
    ```

2.  **Build the binary using Taskfile:**

    The project includes a `Taskfile.yml` for easy development. Make sure you have [Task](https://taskfile.dev/installation/) installed.

    ```sh
    task build
    ```

    This will create the binary at `./bin/vault-loadgen`.

3.  **Build the binary using `go build`:**

    ```sh
    go build -o ./bin/vault-loadgen ./cmd/vault-loadgen
    ```

## Usage

The tool uses a subcommand-based CLI (powered by Cobra) for each load generation mode.

```sh
./bin/vault-loadgen --help
```

### Subcommands

-   `vault-loadgen pki`: Generate PKI certificate leases.
-   `vault-loadgen approle`: Generate AppRole token leases.
-   `vault-loadgen kv`: Populate KVv2 secrets engines.

Each subcommand has its own set of flags. Use `--help` on a subcommand for more details:

```sh
./bin/vault-loadgen pki --help
./bin/vault-loadgen approle --help
./bin/vault-loadgen kv --help
```

## Authentication

`vault-loadgen` requires a Vault token with sufficient permissions to perform its operations. You can provide the token in two ways:

1.  **Environment Variable (Recommended)**:

    ```sh
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="your-vault-token"
    ```

2.  **CLI Flag**:

    ```sh
    ./bin/vault-loadgen pki --vault-addr="http://127.0.0.1:8200" --vault-token="your-vault-token" ...
    ```

Using the environment variable is recommended to avoid exposing the token in your shell history.

## Examples

### PKI Mode Examples

#### Vault Enterprise (Multi-Namespace)

This command creates 10 child namespaces and distributes the creation of 1,000 certificate leases across them using 8 workers.

```sh
./bin/vault-loadgen pki \
  --namespaces 10 \
  --pki-leases 1000 \
  --workers 8 \
  --pki-ttl 48h
```

#### Vault OSS (Single-Namespace)

This command runs all operations in the root namespace, as Vault OSS does not support namespaces. Set `--namespaces=0` for single-namespace mode.

```sh
./bin/vault-loadgen pki \
  --namespaces 0 \
  --pki-leases 500 \
  --workers 4
```

### AppRole Mode Examples

#### Vault Enterprise (Multi-Namespace)

This command creates 5 child namespaces and performs 500 AppRole logins, distributing the load across the namespaces.

```sh
./bin/vault-loadgen approle \
  --namespaces 5 \
  --approle-logins 500 \
  --workers 8
```

#### Vault OSS (Single-Namespace)

This command performs 200 AppRole logins in the root namespace.

```sh
./bin/vault-loadgen approle \
  --namespaces 0 \
  --approle-logins 200 \
  --workers 4
```

### KV Mode Examples

#### Vault Enterprise (Multi-Namespace)

This command creates 5 child namespaces. In each namespace, it creates 10 KVv2 engines and writes 100 secrets into each engine.

```sh
./bin/vault-loadgen kv \
  --namespaces 5 \
  --kv-engines 10 \
  --secrets-per-engine 100 \
  --workers 16
```

#### Vault OSS (Single-Namespace)

This command creates 10 KVv2 engines in the root namespace and writes 100 secrets into each.

```sh
./bin/vault-loadgen kv \
  --namespaces 0 \
  --kv-engines 10 \
  --secrets-per-engine 100 \
  --workers 8
```

## Configuration

All configuration options can be set via CLI flags, environment variables, or a YAML configuration file.

### Configuration File

You can use a YAML configuration file to simplify complex configurations. Create a file (e.g., `config.yml`) with your settings:

```yaml
# Vault connection settings
vault-addr: "http://127.0.0.1:8200"
vault-token: "your-vault-token"
vault-cacert: ""
vault-skip-verify: false
parent-namespace: ""

# Global settings
workers: 8
namespaces: 10
create-namespaces: true
log-level: "info"
rate-limit: 0
dry-run: false
output: "text"
progress: true

# PKI mode settings
pki-leases: 1000
pki-ttl: "48h"
pki-root-ca-ttl: "168h"
pki-key-size: 2048
pki-common-name: "loadtest-{index}.example.com"

# AppRole mode settings
approle-logins: 500
secret-id-ttl: "1h"
token-ttl: "1h"
token-max-ttl: "2h"

# KV mode settings
kv-engines: 10
secrets-per-engine: 100
secret-size: 5
```

Then use the configuration file with any command:

```sh
./bin/vault-loadgen pki --config config.yml
```

Note: CLI flags and environment variables take precedence over configuration file settings.

### Global Flags

| Flag                  | Description                                                              | Default                          |
| --------------------- | ------------------------------------------------------------------------ | -------------------------------- |
| `--vault-addr`        | Vault server address.                                                    | `http://127.0.0.1:8200`         |
| `--vault-token`       | Vault authentication token.                                              | (required)                       |
| `--vault-cacert`      | Path to CA certificate for Vault TLS.                                    | `""`                             |
| `--vault-skip-verify` | Skip TLS certificate verification (insecure).                            | `false`                          |
| `--parent-namespace`  | Parent namespace for load test resources.                                | `""`                             |
| `--workers`           | Number of concurrent workers.                                            | `4`                              |
| `--namespaces`        | Number of child namespaces to create (`0` = single-namespace mode).      | `5`                              |
| `--create-namespaces` | Create child namespaces for load distribution.                           | `true`                           |
| `--log-level`         | Log level (debug, info, warn, error).                                    | `"info"`                         |
| `--rate-limit`        | Rate limit (operations per second, `0` = unlimited).                     | `0`                              |
| `--dry-run`           | Perform a dry run without making changes.                                | `false`                          |
| `--output`            | Output format (text, json).                                              | `"text"`                         |
| `--progress`          | Show progress indicators.                                                | `true`                           |

### PKI Mode Flags

| Flag                 | Description                                              | Default                          |
| -------------------- | -------------------------------------------------------- | -------------------------------- |
| `--pki-leases`       | Number of PKI certificate leases to generate.            | `100`                            |
| `--pki-ttl`          | TTL for PKI certificates.                                | `"24h"`                          |
| `--pki-root-ca-ttl`  | TTL for PKI root CA.                                     | `"168h"` (7 days)                |
| `--pki-key-size`     | Key size for PKI certificates (2048 or 4096).            | `2048`                           |
| `--pki-common-name`  | Common name pattern for PKI certificates.                | `"loadtest-{index}.example.com"` |

### AppRole Mode Flags

| Flag                 | Description                                              | Default                          |
| -------------------- | -------------------------------------------------------- | -------------------------------- |
| `--approle-logins`   | Number of AppRole logins to perform.                     | `100`                            |
| `--secret-id-ttl`    | TTL for AppRole secret IDs.                              | `"1h"`                           |
| `--token-ttl`        | TTL for AppRole tokens.                                  | `"1h"`                           |
| `--token-max-ttl`    | Max TTL for AppRole tokens.                              | `"2h"`                           |

### KV Mode Flags

| Flag                    | Description                                           | Default                          |
| ----------------------- | ----------------------------------------------------- | -------------------------------- |
| `--kv-engines`          | Number of KV engines to create.                       | `1`                              |
| `--secrets-per-engine`  | Number of secrets to write per KV engine.             | `100`                            |
| `--secret-size`         | Number of key-value pairs per secret.                 | `5`                              |

## Development with Taskfile

The project includes a `Taskfile.yml` with common development tasks:

### Building

```sh
# Build the binary
task build

# Build for all platforms
task build:all
```

### Testing

```sh
# Run all tests with race detector
task test

# Run tests with coverage
task test:cover

# Run unit tests only
task test:unit
```

### Vault Development Environment

```sh
# Start local Vault dev server
task vault:up

# Stop local Vault dev server
task vault:down

# View Vault logs
task vault:logs

# Reset Vault dev server
task vault:reset
```

### Running Examples

```sh
# Run all load generation modes (PKI, AppRole, KV)
task run:all

# Run PKI mode example
task run:pki

# Run AppRole mode example
task run:approle

# Run KV mode example
task run:kv
```

### Code Quality

```sh
# Format code
task fmt

# Run linters
task lint

# Run pre-commit checks (format, lint, test)
task pre-commit
```

### Cleanup

```sh
# Clean build artifacts
task clean

# Clean everything including dependencies
task clean:all
```

## Development Setup

### Prerequisites

-   Go 1.21 or newer
-   [Task](https://taskfile.dev/installation/) (optional but recommended)
-   A running HashiCorp Vault instance (for testing)

### Running Tests

Run all tests:

```sh
task test
```

Or using Go directly:

```sh
go test ./...
```

Run tests with verbose output:

```sh
go test -v ./...
```

Run tests with coverage:

```sh
task test:cover
```

### Code Quality

Format code:

```sh
task fmt
```

Run linters:

```sh
task lint
```

## Architecture

The project follows the Golang Standards Project Layout:

-   `cmd/vault-loadgen/` - Application entry point (main package) with Cobra CLI
-   `internal/` - Private application code
    -   `internal/client/` - Vault client wrapper and helpers
    -   `internal/config/` - Configuration management
    -   `internal/loadgen/` - Load generation logic (PKI, AppRole, KV, namespace management, validation)
    -   `internal/ratelimit/` - Rate limiting implementation
    -   `internal/shutdown/` - Graceful shutdown handling
    -   `internal/stats/` - Statistics tracking and reporting

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
