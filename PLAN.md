# PLAN: Rewrite `symb` CLI to TypeScript + viem

> Scope: Port the existing Python `click` CLI (`symb.py`) to a production-grade Node/TypeScript CLI powered by **viem** (no `ethers`), while refactoring for maintainability, performance, and safer key handling.

## 0. High-level goals

### Functional parity (must-have)
- Keep the same command surface area & behavior (read + write + signature flows):
  - Network queries: `isnet`, `middleware`, `nets`, `netops`, `netstakes`
  - Operator queries: `isop`, `ops`, `opnets`, `opstakes`, `op_vault_net_stake`, opt-in checks
  - Vault queries: `isvault`, `vaults`, `vaultops`, `vaultnets`, `vaultnetsops`
  - Staker queries + actions: `active_balance_of`, `withdrawals_of`, `withdrawals_claimed`, `deposit`, `withdraw`, `claim`
  - Network/operator/vault curator actions: `register_*`, `opt_in_*`, `opt_out_*`, limits, resolver ops, shares ops
  - Off-chain EIP-712 signature generation: `*_signature` commands
- Preserve chain selection (`mainnet`, `holesky`, `sepolia`, `hoodi`) and default RPCs.
- Preserve address normalization (checksum) and input validation.

### Refactor / improve / optimize (should-have)
- **Split monolith** into a small reusable library (`core/`) and a thin CLI layer (`commands/`).
- Replace ad-hoc conversions with viem utilities (`parseUnits`, `formatUnits`, address helpers).
- Use viem’s built-in Multicall batching with **chunking** & concurrency limits for large registries.
- Introduce structured outputs (`--json`) for scripting and stable formatting.
- Safer secrets: discourage `--private-key` CLI arg; support env + prompt + file.
- Better error decoding and clearer revert messages.
- Fix correctness bugs found in the Python code (e.g., `get_vaults` delegator-type enrichment gate uses the last loop variable).

### Non-goals (explicitly out of scope for first rewrite)
- UI/daemon mode, background indexers, database storage.
- Supporting *all* hardware wallets beyond Ledger (but make the architecture pluggable).
- Replacing on-chain enumeration with event indexing (can be a later optimization).

---

## 1. Repository + toolchain setup

### 1.1 Project skeleton
- Initialize with **pnpm**.
- Node runtime target: Node **>= 20** (ES2022+).
- TypeScript config:
  - `"module": "ESNext"`, `"moduleResolution": "Bundler"`, `"target": "ES2022"`
  - `"resolveJsonModule": true` (to import ABI JSON as modules)
  - `"strict": true`, `"noUncheckedIndexedAccess": true`
- Lint/format:
  - `eslint` + `@typescript-eslint/*`
  - `prettier`
- Build + run:
  - Dev: `tsx` for fast iteration
  - Build: `tsdown` (rolldown) -> `dist/`
  - `package.json` `bin` entry: `symb` -> `dist/index.js`

### 1.2 Dependencies (suggested)
- Core:
  - `viem`
  - `zod` (validation)
  - `commander` or `clipanion` (CLI routing)
  - `chalk` (optional; output)
- Ledger (optional but parity with Python):
  - `@ledgerhq/hw-app-eth`
  - `@ledgerhq/hw-transport-node-hid` (or `...-hid-singleton`)
- UX:
  - `prompts` (confirmations, password prompts)
  - `ora` (progress spinners for long registry scans)

---

## 2. Target architecture

### 2.1 File layout
```
src/
  index.ts                 # CLI entry, global flags, command registration
  config/
    chains.ts              # chainId, default RPC, deployed addresses
    env.ts                 # env var parsing
  abi/
    *.json                 # existing ABI JSONs (imported via resolveJsonModule)
  core/
    client.ts              # publicClient/walletClient factory + chain checks
    contracts.ts           # getContract helpers, typed wrappers
    multicall.ts           # batching, chunking utilities
    symbiotic.ts           # high-level read API (nets/ops/vaults/etc.)
    signing/
      local.ts             # privateKeyToAccount wrapper
      ledger.ts            # Ledger account (viem Custom Account)
      typedData.ts         # EIP-712 message builders (OptIn/OptOut)
    errors.ts              # revert decoding + nice printing
    units.ts               # parse/format token amounts, decimals cache
    subnetwork.ts          # bytes32 subnetwork encoding/decoding
    cache.ts               # TTL/LRU caches for token meta, registries
    output.ts              # printers (pretty tables) + JSON serialization
  commands/
    nets.ts
    ops.ts
    vaults.ts
    staker.ts
    operator.ts
    network.ts
    curator.ts
```

### 2.2 Layering rules
- `commands/*` contains **zero** RPC logic; only:
  - parse args/flags
  - call `core/*`
  - print results
- `core/*` contains all chain logic and must be importable as a library for scripts/tests.

---

## 3. Chain + address configuration refactor

### 3.1 Chain configs

### 3.1.1 Chain selector compatibility (keep Python behavior)
- Accept both names and numeric chain IDs (strings) like the Python CLI:
  - `holesky` or `17000`
  - `sepolia` or `11155111`
  - `mainnet` or `1`
  - `hoodi` or `560048`
- Keep `--chain` defaulting to `mainnet`.
- Keep `--provider` as an alias for `--rpc` for backwards compatibility.
Create a single typed config object:
```ts
type ChainKey = 'mainnet' | 'holesky' | 'sepolia' | 'hoodi'
type ChainConfig = {
  key: ChainKey
  chainId: number
  defaultRpcUrl: string
  addresses: {
    op_registry: Address
    net_registry: Address
    op_vault_opt_in: Address
    op_net_opt_in: Address
    middleware_service: Address
    vault_factory: Address
  }
}
```
Improvements vs Python:
- Avoid duplication: holesky/sepolia/hoodi share the same addresses → use `baseTestnetAddresses`.
- Support override sources in priority order:
  1) CLI flags (`--rpc`, `--addresses-file`)
  2) env vars (`SYMB_RPC_URL`, `SYMB_ADDRESSES_JSON`)
  3) defaults in `chains.ts`

### 3.2 Validation
- On startup, query `eth_chainId` and assert it matches the selected chainId.
- Normalize all addresses via viem `getAddress()` at load time.

---

## 4. ABI strategy (type-safety + ergonomics)

### 4.1 Import ABI JSON and freeze as const
- Import ABIs from `src/abi/*.json`.
- `as const` to get ABITyped inference.

### 4.2 Single source of truth for contract ABIs
Create `core/contracts.ts` exporting:
- ABI maps by logical entity:
  - `OperatorRegistry`, `NetworkRegistry`, `VaultFactory`, `Vault`, `ERC20`, delegators, slasher(s)
- Helper `getContract({ address, abi, publicClient })` returning typed contract actions:
  - `read.*`
  - `simulate.*` / `write.*` (walletClient)

---

## 5. Data fetching refactor + performance plan

### 5.1 Replace W3Multicall with viem multicall
Use viem’s `multicall` batching (Multicall3), with:
- chunking by N calls (e.g., 200–500) to avoid RPC payload limits
- `--concurrency` flag (default 4)
- retry/backoff for flaky public RPCs

### 5.2 Caching strategy
Introduce TTL caches:
- `tokenMetaCache`: `{ symbol, decimals }` by token address (TTL 24h)
- `netsCache`, `opsCache`, `vaultsCache` (TTL 30–120s; configurable)
- Consider an in-memory LRU for long-running invocations.

### 5.3 Avoid O(N*M) where possible
Some current flows are expensive:
- `get_net_ops(net)` loops over *all operators* and checks opt-in per op.
- `get_op_nets(op)` loops over *all networks* and checks opt-in per net.
Mitigations:
- Keep parity first, but implement:
  - chunked multicalls with progress indicator
  - optional `--max-entities` / `--limit` / `--offset`
  - optional `--no-full` to avoid nested scans
Later (optional v2):
- add event-driven index mode (off-chain caching) if needed.

### 5.4 Fix correctness issues during port
- Fix `get_vaults()` enrichment gate:
  - In Python, extra delegator fields (`operator`, `network`) are only fetched if the *last* vault has a non-zero delegator.
  - In TS, perform enrichment based on `results.some(v => v.delegator !== zeroAddress)` and/or `delegator_type in {2,3}`.

---

## 6. Core domain model (typed)

Define internal types used across commands:
```ts
type TokenMeta = { symbol: string; decimals: number }

type NetInfo = { net: Address; middleware: Address }

type VaultInfo = {
  vault: Address
  collateral: Address
  tvl: bigint
  delegator: Address
  slasher: Address
  delegatorType: bigint | -1n
  slasherType: bigint | -1n
  delegatorOperator?: Address
  delegatorNetwork?: Address
}

type StakeBySubnetwork = Record<number, bigint> // subnetId -> stake/limit
```

---

## 7. Subnetwork encoding utility

Port `get_subnetwork(net, subnetId)`:
- Current Python: bytes32 = `net (20 bytes)` + `subnetId (12 bytes, hex padded)`
- Implement in TS with viem hex utilities:
  - `subnetworkId` should be treated as uint96 (12 bytes)
  - return `Hex` of length 66 (`0x` + 64 chars)
- Provide both:
  - `encodeSubnetwork({ net, subnetId }): Hex`
  - `decodeSubnetwork(subnetwork: Hex): { net: Address; subnetId: bigint }`

---

## 8. Token amount parsing & formatting

Replace Decimal math with viem primitives:
- Parse user-facing amounts:
  - fetch decimals (via cache + multicall)
  - `parseUnits(amountStr, decimals)` -> `bigint`
- Print amounts:
  - `formatUnits(value, decimals)`
- Add safety:
  - reject `<= 0`
  - reject `> maxUint256`
  - optional `--wei` mode to accept raw bigint inputs without decimals fetch.

---

## 9. Error handling & revert decoding

### 9.1 Decode known custom errors
- Build a combined ABI “error registry” from all ABIs at startup (or prebuild step).
- When a call/tx reverts:
  - Extract revert data (`0x...`)
  - Use viem `decodeErrorResult({ abi, data })`
  - Fallback to `Error(string)` and `Panic(uint256)`
- Print both:
  - error signature + decoded args
  - raw data for debugging (`--verbose`)

### 9.2 Preflight writes
For every write command:
1. `simulateContract()` (or `walletClient.prepareTransactionRequest`) to:
   - surface revert reasons early
   - estimate gas
2. Prompt confirmation (unless `--yes`)
3. Send transaction
4. `waitForTransactionReceipt`

---

## 10. Signing & accounts (private key + Ledger)

### 10.1 Account selection UX
Global options for write/signature commands:
- `--account <address>` (optional; used for display + sanity checks)
- `--private-key` (discouraged; also allow `SYMB_PRIVATE_KEY`)
- `--ledger` + `--ledger-path "m/44'/60'/0'/0/0"` (default)
- `--ledger-address` (optional; verify it matches derived address)
Rules:
- Exactly one signing method must be chosen for write/signature commands.
- Never print private key; never log env vars.

### 10.2 Local account
- `privateKeyToAccount` from viem.
- Use `account.signTypedData` for EIP-712 signatures.

### 10.3 Ledger account (viem Custom Account)
Implement a viem Custom Account adapter:
- `getAddress()` → derive via Ledger path
- `signTransaction(tx)` → Ledger sign tx
- `signTypedData(typedData)` → Ledger EIP-712 signing
- `signMessage(message)` → Ledger personal sign (optional; not needed for parity)
Considerations:
- Provide clear prompts (“Open Ethereum app”, “Enable blind signing”, etc.).
- Add a `--transport` flag if needed (`hid` vs `usb`).

---

## 11. Porting the EIP-712 signature commands

Implement typed data builders for:
- `OperatorNetworkOptInService` OptIn / OptOut
- `OperatorVaultOptInService` OptIn / OptOut

Steps per command:
1. Resolve signer address (local/ledger).
2. Read `nonce` from the target service contract (`nonces(who, where)`).
3. Compute `deadline = now + duration`.
4. Construct typed data:
   - domain: `{ name, version, chainId, verifyingContract }`
   - types + message
5. `account.signTypedData(typedData)`
6. Print signature + context lines (operator, vault/network, nonce, deadline + human datetime).

---

## 12. Command-by-command port plan

### 12.1 Read-only commands (Phase 1)
- `isnet`, `isop`, `isvault`
- `middleware`
- `nets` (+ `--full`)
- `ops`
- `vaults` (+ `--full`)
- `netops`, `vaultops`
- `opnets`, `vaultnets`
- `netstakes`, `opstakes`
- `vaultnetsops`
- `active_balance_of`, `withdrawals_of`, `withdrawals_claimed`
- `max_network_limit`, `network_limit`, `operator_network_limit`, `operator_network_shares`, `total_operator_network_shares`
- `resolver`, `pending_resolver`
Acceptance criteria:
- Output matches Python’s semantics for the same RPC endpoint.

### 12.2 Signature commands (Phase 2)
- `opt_in_vault_signature`, `opt_out_vault_signature`
- `opt_in_network_signature`, `opt_out_network_signature`
Acceptance criteria:
- Signatures verify on-chain (can be checked in a small test script).

### 12.3 Write commands (Phase 3)
- Registration:
  - `register_network`, `register_operator`
- Opt-in/out:
  - `opt_in_vault`, `opt_out_vault`
  - `opt_in_network`, `opt_out_network`
- Curator actions:
  - `set_max_network_limit`
  - `set_network_limit`
  - `set_operator_network_limit`
  - `set_operator_network_shares`
  - `set_resolver`
- Staker actions:
  - `deposit` (incl. ERC20 approve flow)
  - `withdraw`
  - `claim`
Acceptance criteria:
- Each tx path supports:
  - local private key
  - Ledger (if enabled)
  - `--dry-run` to simulate only

---

## 13. Output & UX improvements

### 13.1 Output modes
- Default: human-readable, close to Python format (indented blocks).
- `--json`: machine-readable output for scripting.
- `--quiet`: only print the essential (e.g., address/tx hash).

### 13.2 Progress & timeouts
- For registry scans:
  - show progress (`ora`) + estimated counts
  - add `--timeout-ms` and `--retries`

### 13.3 Confirmations
- Keep safety prompts for:
  - setting resolver when a pending resolver exists
  - deposits/claims on behalf of another address
  - shares updates (percentage changes)
- Add `--yes` to bypass prompts for automation.

---

## 14. Testing strategy

### 14.1 Unit tests (Vitest)
- Address/bytes32/uint parsing
- Subnetwork encode/decode
- Token unit parsing/formatting
- Error decode helpers (given known ABI + revert data)

### 14.2 Integration tests
- “Read” integration against a public RPC (rate-limited; mark as optional).
- Deterministic local tests:
  - Prefer Foundry `anvil` in CI (no Hardhat).
  - Minimal mock contracts or use deployed addresses on testnets for smoke tests.

### 14.3 Golden output tests (optional)
- Snapshot CLI outputs for stable formatting in `--json` mode.

---

## 15. Documentation & release

### 15.1 Docs
- `README.md`:
  - install (`pnpm i -g` or `pnpm dlx`)
  - examples for each command category
  - security notes (private key handling)
  - Ledger troubleshooting
- `CHANGELOG.md`
- `docs/`:
  - chain config overrides
  - how to add a new chain

### 15.2 Packaging
- `symb` binary published to npm.
- Ensure `dist/` contains ESM output compatible with Node 20.
- Provide `pnpm pack` verification.

---

## 16. Implementation order (recommended)

1) **Scaffold repo** + chain config + ABI imports.
2) Implement `publicClient` factory + chainId check.
3) Implement `multicall` wrapper + chunking.
4) Implement `SymbioticClient` read APIs: `getNets`, `getOps`, `getVaults`, `getTokenMeta`.
5) Port read-only commands (most value, easiest to validate).
6) Add error decoding and `--json` output.
7) Add signature commands (local first, then Ledger).
8) Add write tx pipeline with simulate → confirm → send → wait.
9) Add approve+deposit flow and withdrawal/claim flow.
10) Test, document, polish.

---

## 17. “Done” checklist

- [ ] All 45 commands exist in TS CLI with matching names (or documented aliases).
- [ ] `--chain` + `--rpc` work, and chainId mismatch errors are clear.
- [ ] Read commands use multicall batching and don’t time out on large registries (chunking).
- [ ] `--json` outputs are stable and documented.
- [ ] Writes are preflight-simulated; failures decode to readable errors.
- [ ] Local private key signing works end-to-end.
- [ ] Ledger flows work end-to-end (tx signing + EIP-712 signatures), or are clearly feature-flagged if not available on a given platform.
- [ ] Tests cover critical utilities + at least one end-to-end smoke test.
- [ ] README includes examples and security guidance.
