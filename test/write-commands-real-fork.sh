#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd anvil
require_cmd cast
require_cmd solc
require_cmd node

if [[ ! -x ./dist/index.js ]]; then
  require_cmd pnpm
  pnpm -s build >/dev/null
fi

FORK_URL="${FORK_URL:-https://ethereum-rpc.gprptest.net/mainnet}"
ANVIL_PORT="${ANVIL_PORT:-9546}"
ANVIL_HOST="${ANVIL_HOST:-127.0.0.1}"
RPC_URL="http://${ANVIL_HOST}:${ANVIL_PORT}"
START_ANVIL="${START_ANVIL:-1}"

TMP_DIR="$(mktemp -d)"
ANVIL_LOG="$TMP_DIR/anvil.log"
ANVIL_PID=""

cleanup() {
  if [[ -n "$ANVIL_PID" ]]; then
    kill "$ANVIL_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ "$START_ANVIL" == "1" ]]; then
  anvil --fork-url "$FORK_URL" --host "$ANVIL_HOST" --port "$ANVIL_PORT" >"$ANVIL_LOG" 2>&1 &
  ANVIL_PID="$!"
fi

for _ in $(seq 1 60); do
  if cast block latest --rpc-url "$RPC_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! cast block latest --rpc-url "$RPC_URL" >/dev/null 2>&1; then
  echo "RPC is not reachable at $RPC_URL" >&2
  [[ -f "$ANVIL_LOG" ]] && tail -n 40 "$ANVIL_LOG" >&2
  exit 1
fi

# Core addresses.
NET_REGISTRY="0xC773b1011461e7314CF05f97d95aa8e92C1Fd8aA"
CURATOR_REGISTRY="0xF75D8d8F790178F0d7F2ee7656874567d382C21e"
FEE_REGISTRY="0x3E5a669F673712Bf72De956608E89D36561cbAf1"
REWARDS="0xa13e65cA0FeFa52cCb9615108fF400EF4806866B"

# Anvil account #0.
PK0="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
NETWORK_SENDER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# Rewards tuple created during setup.
REWARD_VAULT="0x93b96D7cDe40DC340CA55001F46B3B8E41bC89B4"
REWARD_OPERATOR="0x4B9F8FEbAfDeD90E66C9896B729196a061d69B2F"

# 1) Ensure NETWORK_SENDER is a registered network.
if [[ "$(cast call "$NET_REGISTRY" "isEntity(address)(bool)" "$NETWORK_SENDER" --rpc-url "$RPC_URL")" != "true" ]]; then
  ./dist/index.js --rpc "$RPC_URL" net register --private-key "$PK0" --yes >/dev/null
fi

# 2) Ensure NETWORK_SENDER is curator for REWARD_VAULT.
ZERO_ADDR="0x0000000000000000000000000000000000000000"
CURRENT_CURATOR="$(cast call "$CURATOR_REGISTRY" "getCurator(address)(address)" "$REWARD_VAULT" --rpc-url "$RPC_URL")"
to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

if [[ "$(to_lower "$CURRENT_CURATOR")" == "$(to_lower "$ZERO_ADDR")" ]]; then
  VAULT_OWNER="$(cast call "$REWARD_VAULT" "owner()(address)" --rpc-url "$RPC_URL")"
  cast rpc --rpc-url "$RPC_URL" anvil_setBalance "$VAULT_OWNER" 0x3635C9ADC5DEA00000 >/dev/null
  cast rpc --rpc-url "$RPC_URL" anvil_impersonateAccount "$VAULT_OWNER" >/dev/null
  cast send "$CURATOR_REGISTRY" "setCurator(address,address)" "$REWARD_VAULT" "$NETWORK_SENDER" --rpc-url "$RPC_URL" --from "$VAULT_OWNER" --unlocked >/dev/null
elif [[ "$(to_lower "$CURRENT_CURATOR")" != "$(to_lower "$NETWORK_SENDER")" ]]; then
  cast rpc --rpc-url "$RPC_URL" anvil_setBalance "$CURRENT_CURATOR" 0x3635C9ADC5DEA00000 >/dev/null
  cast rpc --rpc-url "$RPC_URL" anvil_impersonateAccount "$CURRENT_CURATOR" >/dev/null
  cast send "$CURATOR_REGISTRY" "setCurator(address,address)" "$REWARD_VAULT" "$NETWORK_SENDER" --rpc-url "$RPC_URL" --from "$CURRENT_CURATOR" --unlocked >/dev/null
fi

# 3) Set non-zero fees for reward distribution.
cast send "$FEE_REGISTRY" "setOperatorsFee(address,uint256)" "$REWARD_VAULT" 50000 --rpc-url "$RPC_URL" --private-key "$PK0" >/dev/null
cast send "$FEE_REGISTRY" "setCuratorFee(address,uint256)" "$REWARD_VAULT" 50000 --rpc-url "$RPC_URL" --private-key "$PK0" >/dev/null

# 4) Deploy ERC20 for realistic rewards distribution on fork.
cat >"$TMP_DIR/RealForkToken.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
contract RealForkToken {
  string public name = "Fork Real Test Token";
  string public symbol = "FRT";
  uint8 public decimals = 18;
  uint256 public totalSupply;
  mapping(address => uint256) public balanceOf;
  mapping(address => mapping(address => uint256)) public allowance;
  event Transfer(address indexed from, address indexed to, uint256 amount);
  event Approval(address indexed owner, address indexed spender, uint256 amount);
  constructor() {
    uint256 s = 1_000_000_000 ether;
    totalSupply = s;
    balanceOf[msg.sender] = s;
    emit Transfer(address(0), msg.sender, s);
  }
  function transfer(address to, uint256 amount) external returns (bool) {
    require(balanceOf[msg.sender] >= amount, "bal");
    unchecked { balanceOf[msg.sender] -= amount; balanceOf[to] += amount; }
    emit Transfer(msg.sender, to, amount);
    return true;
  }
  function approve(address spender, uint256 amount) external returns (bool) {
    allowance[msg.sender][spender] = amount;
    emit Approval(msg.sender, spender, amount);
    return true;
  }
  function transferFrom(address from, address to, uint256 amount) external returns (bool) {
    uint256 allowed = allowance[from][msg.sender];
    require(allowed >= amount, "allow");
    require(balanceOf[from] >= amount, "bal");
    unchecked {
      allowance[from][msg.sender] = allowed - amount;
      balanceOf[from] -= amount;
      balanceOf[to] += amount;
    }
    emit Transfer(from, to, amount);
    return true;
  }
}
SOL

solc --bin "$TMP_DIR/RealForkToken.sol" -o "$TMP_DIR" --overwrite >/dev/null
TOKEN_BYTECODE="$(tr -d '\n' <"$TMP_DIR/RealForkToken.bin")"
REWARD_TOKEN="$(cast send --rpc-url "$RPC_URL" --private-key "$PK0" --create "0x${TOKEN_BYTECODE}" | awk '/contractAddress/ {print $2}')"
if [[ -z "$REWARD_TOKEN" ]]; then
  echo "Failed to deploy test ERC20 token." >&2
  exit 1
fi
cast send "$REWARD_TOKEN" "approve(address,uint256)" "$REWARDS" 1000000000000000000000000 --rpc-url "$RPC_URL" --private-key "$PK0" >/dev/null

# 5) Pick a valid past timestamp with non-zero active shares and distribute rewards.
NOW_TS="$(cast block latest --rpc-url "$RPC_URL" | awk '/^timestamp/ {print $2; exit}')"
REWARD_TS=""
for offset in 60 600 3600 86400 604800 2592000; do
  candidate="$((NOW_TS - offset))"
  shares="$(cast call "$REWARD_VAULT" "activeSharesAt(uint48,bytes)(uint256)" "$candidate" 0x --rpc-url "$RPC_URL" 2>/dev/null || true)"
  shares="${shares%% *}"
  if [[ -n "$shares" && "$shares" != "0" ]]; then
    REWARD_TS="$candidate"
    break
  fi
done
if [[ -z "$REWARD_TS" ]]; then
  echo "Could not find a valid reward timestamp with active shares." >&2
  exit 1
fi

SUBNETWORK="$(node -e "const net='${NETWORK_SENDER}'.toLowerCase().slice(2); console.log('0x'+net+'0'.repeat(24));")"
cast send "$REWARDS" "distributeVaultSnapshotRewards(bytes32,address,address,uint256,uint48,bytes)" "$SUBNETWORK" "$REWARD_TOKEN" "$REWARD_VAULT" 100000000000000000000000 "$REWARD_TS" 0x --rpc-url "$RPC_URL" --private-key "$PK0" >/dev/null

# 6) Sanity checks for generated real rewards state.
rewards_len="$(cast call "$REWARDS" "rewardsLength(address,address,address)(uint256)" "$REWARD_VAULT" "$NETWORK_SENDER" "$REWARD_TOKEN" --rpc-url "$RPC_URL")"
curator_fees="$(cast call "$REWARDS" "curatorFees(address,address)(uint256)" "$REWARD_VAULT" "$REWARD_TOKEN" --rpc-url "$RPC_URL")"
if [[ "$rewards_len" == "0" ]]; then
  echo "Rewards setup failed: rewardsLength=0." >&2
  exit 1
fi
if [[ "$curator_fees" == "0" ]]; then
  echo "Rewards setup failed: curatorFees=0." >&2
  exit 1
fi

pass=0
fail=0

run_cmd() {
  local name="$1"
  shift
  if "$@" >"$TMP_DIR/out.log" 2>"$TMP_DIR/err.log"; then
    echo "PASS | $name"
    pass=$((pass + 1))
  else
    echo "FAIL | $name"
    sed -n '1,6p' "$TMP_DIR/err.log"
    fail=$((fail + 1))
  fi
}

# 25 write commands.
run_cmd "net register" ./dist/index.js --rpc "$RPC_URL" net register --dry-run --from 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC --json
run_cmd "net set-max-limit" ./dist/index.js --rpc "$RPC_URL" net set-max-limit 0x65B560d887c010c4993C8F8B36E595C171d69D63 123 1 --dry-run --from 0x9101eda106A443A0fA82375936D0D1680D5a64F5 --json
run_cmd "net set-resolver" ./dist/index.js --rpc "$RPC_URL" net set-resolver 0x65B560d887c010c4993C8F8B36E595C171d69D63 0x8560C667Ae72F28D09465B342A480daB28821f6b 1 --dry-run --from 0x9101eda106A443A0fA82375936D0D1680D5a64F5 --json

run_cmd "op register" ./dist/index.js --rpc "$RPC_URL" op register --dry-run --from 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC --json
run_cmd "op opt-in-net" ./dist/index.js --rpc "$RPC_URL" op opt-in-net 0x9101eda106A443A0fA82375936D0D1680D5a64F5 --dry-run --from 0x4Ea457e3F11B1ba9a8D58d3Fd2A501FB9d989E6B --json
run_cmd "op opt-out-net" ./dist/index.js --rpc "$RPC_URL" op opt-out-net 0x9101eda106A443A0fA82375936D0D1680D5a64F5 --dry-run --from 0xAC128Aa884c64cbE6Afecf5c006D51C2bb1Bf819 --json
run_cmd "op opt-in-vault" ./dist/index.js --rpc "$RPC_URL" op opt-in-vault 0x3F326DD5f9368C9A9988353129bFA7Ad68820fE2 --dry-run --from 0x4Ea457e3F11B1ba9a8D58d3Fd2A501FB9d989E6B --json
run_cmd "op opt-out-vault" ./dist/index.js --rpc "$RPC_URL" op opt-out-vault 0x65B560d887c010c4993C8F8B36E595C171d69D63 --dry-run --from 0xAC128Aa884c64cbE6Afecf5c006D51C2bb1Bf819 --json
run_cmd "op opt-in-vault-sig" ./dist/index.js --rpc "$RPC_URL" op opt-in-vault-sig 0xfE53Bca0DF7ebe8e43Cd1b976275cCCE7C4A5edA --private-key "$PK0" --json
run_cmd "op opt-out-vault-sig" ./dist/index.js --rpc "$RPC_URL" op opt-out-vault-sig 0x65B560d887c010c4993C8F8B36E595C171d69D63 --private-key "$PK0" --json
run_cmd "op opt-in-net-sig" ./dist/index.js --rpc "$RPC_URL" op opt-in-net-sig 0x9101eda106A443A0fA82375936D0D1680D5a64F5 --private-key "$PK0" --json
run_cmd "op opt-out-net-sig" ./dist/index.js --rpc "$RPC_URL" op opt-out-net-sig 0x9101eda106A443A0fA82375936D0D1680D5a64F5 --private-key "$PK0" --json

run_cmd "vault set-network-limit" ./dist/index.js --rpc "$RPC_URL" vault set-network-limit 0x65B560d887c010c4993C8F8B36E595C171d69D63 0x9101eda106A443A0fA82375936D0D1680D5a64F5 1 1 --dry-run --from 0xe46d876BA2F3C991F3AC3321B8C0A1c323ef8bCf --json
run_cmd "vault set-operator-network-limit" ./dist/index.js --rpc "$RPC_URL" vault set-operator-network-limit 0x9D9C57AE5DC7a8fCf71062a5d155216A170a7a4A 0x9101eda106A443A0fA82375936D0D1680D5a64F5 0xAC128Aa884c64cbE6Afecf5c006D51C2bb1Bf819 1 --dry-run --from 0xfcAF34f30fa2EbCD22DB4F4ABBaD8615D3EAA8bD --json
run_cmd "vault set-operator-network-shares" ./dist/index.js --rpc "$RPC_URL" vault set-operator-network-shares 0x65B560d887c010c4993C8F8B36E595C171d69D63 0x9101eda106A443A0fA82375936D0D1680D5a64F5 0xAC128Aa884c64cbE6Afecf5c006D51C2bb1Bf819 1 --dry-run --from 0xe46d876BA2F3C991F3AC3321B8C0A1c323ef8bCf --json

run_cmd "staker withdraw" ./dist/index.js --rpc "$RPC_URL" staker withdraw 0xc6132FAF04627c8d05d6E759FAbB331Ef2D8F8fD 1 --dry-run --from 0xdF4C5f20BE2514E3B65Eb1746B27aF6721Cc0F8B --json
run_cmd "staker claim" ./dist/index.js --rpc "$RPC_URL" staker claim 0xE1F23869776c82f691d9Cb34597Ab1830Fb0De58 4 --dry-run --from 0x729e72292917844F7C4E5c37Effa43C222aBa5E4 --json

run_cmd "rewards set-curator" ./dist/index.js --rpc "$RPC_URL" rewards set-curator "$REWARD_VAULT" "$REWARD_OPERATOR" --dry-run --from "$NETWORK_SENDER" --json
run_cmd "rewards set-operators-fee" ./dist/index.js --rpc "$RPC_URL" rewards set-operators-fee "$REWARD_VAULT" 50000 --dry-run --from "$NETWORK_SENDER" --json
run_cmd "rewards set-operators-network-fee" ./dist/index.js --rpc "$RPC_URL" rewards set-operators-network-fee "$REWARD_VAULT" "$NETWORK_SENDER" 50000 --dry-run --from "$NETWORK_SENDER" --json
run_cmd "rewards set-curator-fee" ./dist/index.js --rpc "$RPC_URL" rewards set-curator-fee "$REWARD_VAULT" 50000 --dry-run --from "$NETWORK_SENDER" --json
run_cmd "rewards set-curator-network-fee" ./dist/index.js --rpc "$RPC_URL" rewards set-curator-network-fee "$REWARD_VAULT" "$NETWORK_SENDER" 50000 --dry-run --from "$NETWORK_SENDER" --json
run_cmd "rewards claim-vault-snapshot-rewards" ./dist/index.js --rpc "$RPC_URL" rewards claim-vault-snapshot-rewards "$REWARD_VAULT" "$NETWORK_SENDER" "$REWARD_TOKEN" --dry-run --from "$REWARD_OPERATOR" --json
run_cmd "rewards claim-operator-fees" ./dist/index.js --rpc "$RPC_URL" rewards claim-operator-fees "$REWARD_VAULT" "$NETWORK_SENDER" "$REWARD_TOKEN" --dry-run --from "$REWARD_OPERATOR" --json
run_cmd "rewards claim-curator-fees" ./dist/index.js --rpc "$RPC_URL" rewards claim-curator-fees "$REWARD_VAULT" "$REWARD_TOKEN" --dry-run --from "$NETWORK_SENDER" --json

echo
echo "Summary: pass=$pass fail=$fail"
echo "Reward token: $REWARD_TOKEN"
echo "Reward timestamp: $REWARD_TS"

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
