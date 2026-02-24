import { getAddress, isHex, type Address, type Hex } from 'viem'

const MAX_UINT256 = (1n << 256n) - 1n
const MAX_UINT96 = (1n << 96n) - 1n
const MAX_UINT48 = (1n << 48n) - 1n

export function parseAddress(value: string): Address {
  return getAddress(value)
}

function parseBigint(value: string): bigint {
  try {
    // Only accept base-10 integers for CLI args.
    if (!/^\d+$/.test(value)) throw new Error('not a base-10 integer')
    return BigInt(value)
  } catch {
    throw new Error(`Invalid integer: ${value}`)
  }
}

export function parseUint256(value: string): bigint {
  const n = parseBigint(value)
  if (n < 0n || n > MAX_UINT256) throw new Error(`Invalid uint256: ${value}`)
  return n
}

export function parseUint96(value: string): bigint {
  const n = parseBigint(value)
  if (n < 0n || n > MAX_UINT96) throw new Error(`Invalid uint96: ${value}`)
  return n
}

export function parseUint48(value: string): bigint {
  const n = parseBigint(value)
  if (n < 0n || n > MAX_UINT48) throw new Error(`Invalid uint48: ${value}`)
  return n
}

export function parseBytes32Hex(value: string): Hex {
  const hex = value.startsWith('0x') ? value : `0x${value}`
  if (!isHex(hex) || hex.length !== 66) throw new Error(`Invalid bytes32 hex: ${value}`)
  return hex as Hex
}

