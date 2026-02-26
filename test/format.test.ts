import { describe, expect, it } from 'vitest'

import { formatPercent, groupBy } from '../src/core/format'

describe('format', () => {
  it('formatPercent handles denominator=0', () => {
    expect(formatPercent(1n, 0n)).toBe('0')
  })

  it('formatPercent renders 2 decimals', () => {
    expect(formatPercent(1n, 2n)).toBe('50.00')
    expect(formatPercent(1n, 4n)).toBe('25.00')
  })

  it('groupBy groups items by key', () => {
    const items = [
      { collateral: 'a', v: 1 },
      { collateral: 'a', v: 2 },
      { collateral: 'b', v: 3 },
    ]

    const by = groupBy(items, (i) => i.collateral)
    expect(by.get('a')?.map((x) => x.v)).toEqual([1, 2])
    expect(by.get('b')?.map((x) => x.v)).toEqual([3])
  })
})

