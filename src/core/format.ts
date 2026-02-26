export function formatPercent(numerator: bigint, denominator: bigint) {
  // Returns a "whole.frac" string with 2 decimals (no '%' suffix).
  if (denominator === 0n) return '0'
  const bp = (numerator * 10_000n) / denominator // basis points
  const whole = bp / 100n
  const frac = (bp % 100n).toString().padStart(2, '0')
  return `${whole}.${frac}`
}

export function groupBy<T, K>(items: readonly T[], keyFn: (item: T) => K): Map<K, T[]> {
  const out = new Map<K, T[]>()
  for (const item of items) {
    const key = keyFn(item)
    const list = out.get(key) ?? []
    list.push(item)
    out.set(key, list)
  }
  return out
}

