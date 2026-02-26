import { describe, expect, it } from 'vitest'
import { getAddress } from 'viem'

import { parseAddress, parseBytes32Hex, parseHex, parseUint48, parseUint96, parseUint256 } from '../src/cli/parse'

describe('cli/parse', () => {
  it('parseAddress normalizes to checksum', () => {
    const raw = '0x9101eda106a443a0fa82375936d0d1680d5a64f5'
    expect(parseAddress(raw)).toBe(getAddress(raw))
  })

  it('parseUint256 accepts base-10 integers and rejects non-integers', () => {
    expect(parseUint256('0')).toBe(0n)
    expect(parseUint256('123')).toBe(123n)
    expect(() => parseUint256('-1')).toThrow()
    expect(() => parseUint256('1.5')).toThrow()
    expect(() => parseUint256('0x10')).toThrow()
    expect(() => parseUint256('abc')).toThrow()
  })

  it('parseUint96 and parseUint48 enforce bounds', () => {
    expect(parseUint96('0')).toBe(0n)
    expect(parseUint48('0')).toBe(0n)
    expect(() => parseUint96(String(2n ** 96n))).toThrow()
    expect(() => parseUint48(String(2n ** 48n))).toThrow()
  })

  it('parseBytes32Hex accepts with/without 0x prefix and validates length', () => {
    const noPrefix = '1'.repeat(64)
    expect(parseBytes32Hex(noPrefix)).toBe(`0x${noPrefix}`)
    expect(parseBytes32Hex(`0x${noPrefix}`)).toBe(`0x${noPrefix}`)
    expect(() => parseBytes32Hex('0x1')).toThrow()
  })

  it('parseHex accepts with/without 0x prefix', () => {
    expect(parseHex('0x1234')).toBe('0x1234')
    expect(parseHex('1234')).toBe('0x1234')
    expect(() => parseHex('0xZZ')).toThrow()
  })
})

