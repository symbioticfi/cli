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
symb ops
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
symb ops
```

### Development (repo)

```bash
pnpm dev -- --help
pnpm build
./dist/index.js --help
```

Write/signature commands require a signer:

- `--private-key <hex>` (discouraged) or `SYMB_PRIVATE_KEY`.
- Ledger: `--ledger` (optionally `--ledger-path`, `--ledger-address`).

Ledger troubleshooting:

- If Ledger transport fails due to native deps not being built, run `pnpm approve-builds` and then `pnpm install`.

Common env vars:

- `SYMB_RPC_URL`
- `SYMB_PRIVATE_KEY`
- `SYMB_ADDRESSES_JSON` (JSON object with deployed addresses overrides)

If `SYMB_RPC_URL`/`--rpc` is not provided, the CLI uses a built-in fallback list of public RPC endpoints for the selected chain.

## Commands

### Read Commands

Networks:

- `isnet` - Check if address is network.
- `middleware` - Get network middleware address.
- `nets` - List all networks.
- `netops` - List all operators opted in network.
- `netstakes` - Show stakes of all operators in network.

Operators:

- `isop` - Check if address is operator.
- `ops` - List all operators.
- `op-vault-net-stake` - Get operator stake in vault for network (includes shares for NetworkRestakeDelegator).
- `opnets` - List all networks where operator is opted in.
- `opstakes` - Show operator stakes in all networks.
- `check-opt-in-vault` - Check if operator is opted in to a vault.
- `check-opt-in-network` - Check if operator is opted in to a network.

Vaults:

- `isvault` - Check if address is vault.
- `vaults` - List all vaults.
- `vaultops` - List all operators opted into the given vault.
- `vaultnets` - List all networks associated with the given vault.
- `vaultnetsops` - List all operators and their associated networks for the given vault.

Stakers:

- `active-balance-of` - Get an active balance of a given account at a particular vault.
- `withdrawals-of` - Get some epoch's withdrawals of a given account at a particular vault.
- `withdrawals-claimed` - Check if some epoch's withdrawals of a given account at a particular vault are claimed.

Limits:

- `max-network-limit` - Get a maximum network limit at the vault's delegator.
- `resolver` - Get a current resolver for a subnetwork in a vault.
- `pending-resolver` - Get a pending resolver for a subnetwork in a vault.
- `network-limit` - Get a network limit at the vault's delegator.
- `operator-network-limit` - Get an operator-network limit at the vault's delegator.
- `operator-network-shares` - Get operator-network shares at the vault's delegator.
- `total-operator-network-shares` - Get total operator-network shares at the vault's delegator.

RewardsV2:

- `curator` - Get the curator address for a vault.
- `operators-fee` - Get effective operators fee for a vault+network.
- `curator-fee` - Get effective curator fee for a vault+network.
- `rewards-protocol-fee` - Get protocol fee for a rewards type and network.
- `vault-snapshot-curator-fees` - Get claimable curator fees (amount) for a vault+token .

### Write/Sign Commands

Networks:

- `register-network` - Register the signer as a network.
- `set-max-network-limit` - Set a maximum network limit at the vault's delegator.
- `set-resolver` - Set a resolver for a subnetwork at VetoSlasher.

Operators:

- `register-operator` - Register the signer as an operator.
- `opt-in-vault` - Opt-in to a vault.
- `opt-out-vault` - Opt-out from a vault.
- `opt-in-network` - Opt-in to a network.
- `opt-out-network` - Opt-out from a network.
- `opt-in-vault-signature` - Get a signature for opt-in to a vault.
- `opt-out-vault-signature` - Get a signature for opt-out from a vault.
- `opt-in-network-signature` - Get a signature for opt-in to a network.
- `opt-out-network-signature` - Get a signature for opt-out from a network.

Vault Curators:

- `set-network-limit` - Set a network limit at the vault's delegator.
- `set-operator-network-limit` - Set an operator-network limit at the vault's delegator.
- `set-operator-network-shares` - Set an operator-network shares at the vault's delegator.

Stakers:

- `withdraw` - Withdraw from the vault.
- `claim` - Claim a withdrawal for some epoch at the vault.

RewardsV2:

- `set-curator` - Set curator for a vault (RewardsV2 CuratorRegistry).
- `set-operators-fee` - Set default operators fee (ppm) for a vault (RewardsV2 FeeRegistry).
- `set-operators-network-fee` - Set network-specific operators fee (ppm) for a vault (RewardsV2 FeeRegistry).
- `set-curator-fee` - Set default curator fee (ppm) for a vault (RewardsV2 FeeRegistry).
- `set-curator-network-fee` - Set network-specific curator fee (ppm) for a vault (RewardsV2 FeeRegistry).
- `claim-vault-snapshot-rewards` - Claim vault snapshot rewards for the signer (RewardsV2 Rewards).
- `claim-operator-fees` - Claim vault snapshot operator fees for the signer (RewardsV2 Rewards).
- `claim-curator-fees` - Claim vault snapshot curator fees for the signer curator (RewardsV2 Rewards).
