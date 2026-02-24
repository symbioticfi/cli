import { describe, expect, it } from 'vitest'
import { getAddress } from 'viem'

import { decodeSubnetwork, encodeSubnetwork } from '../src/core/subnetwork'

describe('subnetwork', () => {
  it('roundtrips address + subnetId', () => {
    const net = getAddress('0x9101eda106A443A0fA82375936D0D1680D5a64F5')
    const subnetwork0 = encodeSubnetwork({ net, subnetId: 0 })
    expect(subnetwork0).toHaveLength(66)
    expect(decodeSubnetwork(subnetwork0)).toEqual({ net, subnetId: 0n })

    const subnetwork1 = encodeSubnetwork({ net, subnetId: 1 })
    expect(decodeSubnetwork(subnetwork1)).toEqual({ net, subnetId: 1n })
  })

  it('rejects out-of-range subnetId', () => {
    const net = getAddress('0x9101eda106A443A0fA82375936D0D1680D5a64F5')
    expect(() => encodeSubnetwork({ net, subnetId: -1 })).toThrow()
    expect(() => encodeSubnetwork({ net, subnetId: 2n ** 96n })).toThrow()
  })
})

