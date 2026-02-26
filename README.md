# Symbiotic CLI (symb)

Simple CLI tool for fetching data and interacting with Symbiotic core smart contracts.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/symbioticfi/cli)

## Documentation

Can be found [here](https://docs.symbiotic.fi/guides/cli).

## Prerequisites

- Node >= 20
- pnpm (optional; the installer will enable it via `corepack` if missing)

## Install

### Quick Install (macOS/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/symbioticfi/cli/main/install.sh | bash
symb --help
symb op list
```

By default, this installs into `~/.symb/cli` and adds `~/.symb/bin` to your `PATH` (shell profile).

### Local Install (repo)

```bash
pnpm install
```

## Usage

### CLI

```bash
# Help
symb --help

# Example
symb op list
```

Write/signature commands require a signer:

- `--private-key <hex>` (discouraged) or `SYMB_PRIVATE_KEY`.
- Ledger: `--ledger` (optionally `--ledger-path`, `--ledger-address`).

Common env vars:

- `SYMB_RPC_URL`
- `SYMB_PRIVATE_KEY`
- `SYMB_ADDRESSES_JSON` (JSON object with deployed addresses overrides)

If `SYMB_RPC_URL`/`--rpc` is not provided, the CLI uses a built-in fallback list of public RPC endpoints for the selected chain.

### Development (repo)

```bash
pnpm dev -- --help
pnpm build
./dist/index.js --help
```

## Commands

### net

- `symb net is <address>` - Check if address is network.
- `symb net middleware <network_address>` - Get network middleware address.
- `symb net list [--full]` - List all networks.
- `symb net ops <network_address>` - List all operators opted in network.
- `symb net stakes <network_address>` - Show stakes of all operators in network.
- `symb net max-network-limit <vault_address> <network_address>` - Get a maximum network limit at the vault's delegator.
- `symb net resolver <vault_address> <network_address>` - Get a current resolver for a subnetwork in a vault.
- `symb net pending-resolver <vault_address> <network_address>` - Get a pending resolver for a subnetwork in a vault.
- `symb net register [write options]` - Register the signer as a network.
- `symb net set-max-limit [write options] <vault_address> <max_limit> [subnetwork_id]` - Set a maximum network limit at the vault's delegator.
- `symb net set-resolver [write options] <vault_address> <resolver> [subnetwork_id]` - Set a resolver for a subnetwork at VetoSlasher.

### op

- `symb op is <address>` - Check if address is operator.
- `symb op list` - List all operators.
- `symb op nets <operator_address>` - List all networks where operator is opted in.
- `symb op stakes <operator_address>` - Show operator stakes in all networks.
- `symb op stake <operator_address> <vault_address> <network_address>` - Get operator stake in vault for network (includes shares for NetworkRestakeDelegator).
- `symb op opted-in-vault <operator_address> <vault_address>` - Check if operator is opted in to a vault.
- `symb op opted-in-net <operator_address> <network_address>` - Check if operator is opted in to a network.
- `symb op register [write options]` - Register the signer as an operator.
- `symb op opt-in-vault [write options] <vault_address>` - Opt-in to a vault.
- `symb op opt-out-vault [write options] <vault_address>` - Opt-out from a vault.
- `symb op opt-in-net [write options] <network_address>` - Opt-in to a network.
- `symb op opt-out-net [write options] <network_address>` - Opt-out from a network.
- `symb op opt-in-vault-sig [sign options] <vault_address> [duration]` - Get a signature for opt-in to a vault.
- `symb op opt-out-vault-sig [sign options] <vault_address> [duration]` - Get a signature for opt-out from a vault.
- `symb op opt-in-net-sig [sign options] <network_address> [duration]` - Get a signature for opt-in to a network.
- `symb op opt-out-net-sig [sign options] <network_address> [duration]` - Get a signature for opt-out from a network.

### vault

- `symb vault is <address>` - Check if address is vault.
- `symb vault list [--full]` - List all vaults.
- `symb vault ops <vault_address>` - List all operators opted into the given vault.
- `symb vault nets <vault_address>` - List all networks associated with the given vault.
- `symb vault netsops <vault_address>` - List all operators and their associated networks for the given vault.
- `symb vault network-limit <vault_address> <network_address>` - Get a network limit at the vault's delegator.
- `symb vault operator-network-limit <vault_address> <network_address> <operator_address>` - Get an operator-network limit at the vault's delegator.
- `symb vault operator-network-shares <vault_address> <network_address> <operator_address>` - Get operator-network shares at the vault's delegator.
- `symb vault total-operator-network-shares <vault_address> <network_address>` - Get total operator-network shares at the vault's delegator.
- `symb vault set-network-limit [write options] <vault_address> <network_address> <limit> [subnetwork_id]` - Set a network limit at the vault's delegator.
- `symb vault set-operator-network-limit [write options] <vault_address> <network_address> <operator_address> <limit> [subnetwork_id]` - Set an operator-network limit at the vault's delegator.
- `symb vault set-operator-network-shares [write options] <vault_address> <network_address> <operator_address> <shares> [subnetwork_id]` - Set an operator-network shares at the vault's delegator.

### staker

- `symb staker active-balance <vault_address> <address>` - Get an active balance of a given account at a particular vault.
- `symb staker withdrawals <vault_address> <epoch> <address>` - Get some epoch's withdrawals of a given account at a particular vault.
- `symb staker withdrawals-claimed <vault_address> <epoch> <address>` - Check if some epoch's withdrawals of a given account at a particular vault are claimed.
- `symb staker withdraw [write options] <vault_address> <amount> [claimer]` - Withdraw from the vault.
- `symb staker claim [write options] <vault_address> <epoch> [recipient]` - Claim a withdrawal for some epoch at the vault.

### rewards

- `symb rewards curator <vault_address>` - Get the curator address for a vault.
- `symb rewards operators-fee <vault_address> <network_address>` - Get effective operators fee (ppm) for a vault+network.
- `symb rewards curator-fee <vault_address> <network_address>` - Get effective curator fee (ppm) for a vault+network.
- `symb rewards protocol-fee <rewards_type> <network_address>` - Get protocol fee (ppm) for a rewards type and network.
- `symb rewards curator-fees <vault_address> <token>` - Get claimable curator fees (amount) for a vault+token.
- `symb rewards set-curator [write options] <vault_address> <curator>` - Set curator for a vault.
- `symb rewards set-operators-fee [write options] <vault_address> <fee>` - Set default operators fee (ppm) for a vault.
- `symb rewards set-operators-network-fee [write options] <vault_address> <network_address> <fee>` - Set network-specific operators fee (ppm) for a vault.
- `symb rewards set-curator-fee [write options] <vault_address> <fee>` - Set default curator fee (ppm) for a vault.
- `symb rewards set-curator-network-fee [write options] <vault_address> <network_address> <fee>` - Set network-specific curator fee (ppm) for a vault.
- `symb rewards claim-vault-snapshot-rewards [write options] <vault_address> <network_address> <token> [recipient] [first_reward_to_claim] [max_rewards]` - Claim vault snapshot rewards for the signer.
- `symb rewards claim-operator-fees [write options] <vault_address> <network_address> <token> [recipient] [first_reward_to_claim] [max_rewards]` - Claim vault snapshot operator fees for the signer.
- `symb rewards claim-curator-fees [write options] <vault_address> <token> [recipient]` - Claim vault snapshot curator fees for the signer curator.

## Options / Flags

Global (all commands):

- `--chain <chain>`: Chain key or chainId (default: `mainnet`; supported: `mainnet`, `hoodi`, `sepolia`)
- `--rpc <url>`: RPC URL override
- `--timeout-ms <n>`: RPC request timeout (ms)
- `--retries <n>`: RPC retry count
- `--batch-size <n>`: Multicall batch size
- `--concurrency <n>`: Multicall concurrency
- `--json`: Machine-readable JSON output
- `--quiet`: Minimal output

Signing (write + signature commands):

- `--private-key <hex>` (discouraged; use `SYMB_PRIVATE_KEY`)
- `--ledger`
- `--ledger-path <path>`
- `--ledger-address <address>`

Write-only:

- `--yes`: Bypass confirmation prompts
- `--dry-run`: Simulate only (do not send transaction)
