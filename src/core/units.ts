import { formatUnits, parseUnits } from 'viem'

import type { TokenMeta } from './types'

export function formatTokenAmount(value: bigint, meta: TokenMeta): string {
  if (meta.decimals === 0) return value.toString()
  return formatUnits(value, meta.decimals)
}

export function parseTokenAmount(amount: string, meta: TokenMeta): bigint {
  if (meta.decimals === 0) {
    throw new Error('Token decimals are unknown; cannot parse token units')
  }
  // viem validates decimal format; this also rejects negative numbers.
  const parsed = parseUnits(amount, meta.decimals)
  if (parsed <= 0n) throw new Error('Token amount should be > 0')
  return parsed
}

export function tokenMetaFallback(): TokenMeta {
  return { symbol: 'Unknown', decimals: 0 }
}
