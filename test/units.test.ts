import { describe, expect, it } from 'vitest'

import { formatTokenAmount, parseTokenAmount } from '../src/core/units'

describe('units', () => {
  it('parses and formats token amounts', () => {
    const meta = { symbol: 'T', decimals: 18 }
    const wei = parseTokenAmount('1.5', meta)
    expect(wei).toBe(1_500_000_000_000_000_000n)
    expect(formatTokenAmount(wei, meta)).toBe('1.5')
  })

  it('rejects non-positive amounts', () => {
    const meta = { symbol: 'T', decimals: 18 }
    expect(() => parseTokenAmount('0', meta)).toThrow()
    expect(() => parseTokenAmount('-1', meta)).toThrow()
  })

  it('rejects token amount when decimals unknown', () => {
    const meta = { symbol: 'Unknown', decimals: 0 }
    expect(() => parseTokenAmount('1', meta)).toThrow()
  })
})
