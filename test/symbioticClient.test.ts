import { describe, expect, it, vi } from 'vitest'
import { getAddress, type Address } from 'viem'

import { CHAIN_CONFIGS } from '../src/config/chains'
import { ZERO_ADDRESS } from '../src/core/constants'
import { decodeSubnetwork } from '../src/core/subnetwork'
import { SymbioticClient } from '../src/core/symbiotic'
import type { NetInfo, StakeBySubnetwork, VaultInfo } from '../src/core/types'
import * as subnetwork from '../src/core/subnetwork'

function a(value: string): Address {
  return getAddress(value)
}

function makeVault(args: {
  vault: Address
  delegator: Address
  delegatorType: bigint
  delegatorNetwork?: Address
}): VaultInfo {
  return {
    vault: args.vault,
    collateral: a('0xcccccccccccccccccccccccccccccccccccccccc'),
    tvl: 0n,
    delegator: args.delegator,
    slasher: a('0xdddddddddddddddddddddddddddddddddddddddd'),
    delegatorType: args.delegatorType,
    slasherType: 0n,
    delegatorNetwork: args.delegatorNetwork,
  }
}

function makeClient(publicClient: { multicall: (args: any) => Promise<any[]> }) {
  return new SymbioticClient({
    chainKey: 'mainnet',
    chainId: 1,
    addresses: CHAIN_CONFIGS.mainnet.addresses,
    publicClient: publicClient as any,
    multicallBatchSize: 1_000,
    multicallConcurrency: 4,
  })
}

describe('SymbioticClient (call building + StakeBySubnetwork decoding)', () => {
  it('getVaultNetsByDelegator builds calls in net->subnet order and filters empty limits', async () => {
    const delegator = a('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    const netA = a('0x1000000000000000000000000000000000000000')
    const netB = a('0x2000000000000000000000000000000000000000')

    const publicClient = {
      multicall: vi.fn().mockResolvedValueOnce([0n, 5n, 0n, 0n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getNets').mockResolvedValueOnce([
      { net: netA, middleware: ZERO_ADDRESS } satisfies NetInfo,
      { net: netB, middleware: ZERO_ADDRESS } satisfies NetInfo,
    ])

    const res = await symb.getVaultNetsByDelegator(delegator)
    expect(res).toEqual([{ net: netA, limit: { 1: 5n } as StakeBySubnetwork }])

    expect(publicClient.multicall).toHaveBeenCalledTimes(1)
    const calls = publicClient.multicall.mock.calls[0]?.[0]?.contracts as any[]
    expect(calls).toHaveLength(4)
    for (const c of calls) {
      expect(c.address).toBe(delegator)
      expect(c.functionName).toBe('maxNetworkLimit')
      expect(Array.isArray(c.args)).toBe(true)
      expect(c.args).toHaveLength(1)
    }

    const decoded = calls.map((c) => decodeSubnetwork(c.args[0]))
    expect(decoded.map((d) => d.net)).toEqual([netA, netA, netB, netB])
    expect(decoded.map((d) => d.subnetId)).toEqual([0n, 1n, 0n, 1n])
  })

  it('getNetVaults chooses limit function by delegatorType and decodes StakeBySubnetwork', async () => {
    const network = a('0x1000000000000000000000000000000000000000')
    const v1 = makeVault({
      vault: a('0x0100000000000000000000000000000000000000'),
      delegator: a('0x1111111111111111111111111111111111111111'),
      delegatorType: 3n,
      delegatorNetwork: network,
    })
    const v2 = makeVault({
      vault: a('0x0200000000000000000000000000000000000000'),
      delegator: a('0x2222222222222222222222222222222222222222'),
      delegatorType: 1n,
    })

    const publicClient = {
      multicall: vi.fn().mockResolvedValueOnce([0n, 10n, 0n, 0n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getVaults').mockResolvedValueOnce([v1, v2])

    const res = await symb.getNetVaults(network)
    expect(res).toEqual([{ ...v1, limit: { 1: 10n } as StakeBySubnetwork }])

    const calls = publicClient.multicall.mock.calls[0]?.[0]?.contracts as any[]
    expect(calls).toHaveLength(4)
    expect(calls.slice(0, 2).map((c) => c.functionName)).toEqual(['maxNetworkLimit', 'maxNetworkLimit'])
    expect(calls.slice(2).map((c) => c.functionName)).toEqual(['networkLimit', 'networkLimit'])

    const decoded = calls.map((c) => decodeSubnetwork(c.args[0]))
    expect(decoded.map((d) => d.net)).toEqual([network, network, network, network])
    expect(decoded.map((d) => d.subnetId)).toEqual([0n, 1n, 0n, 1n])
  })

  it('getNetOpsVaults decodes stakes per op/vault and precomputes subnetworks once', async () => {
    const network = a('0x1000000000000000000000000000000000000000')
    const op1 = a('0x9000000000000000000000000000000000000001')
    const op2 = a('0x9000000000000000000000000000000000000002')

    const vault1 = { ...makeVault({ vault: a('0x0100000000000000000000000000000000000000'), delegator: a('0x1111111111111111111111111111111111111111'), delegatorType: 0n }), limit: { 0: 1n } as StakeBySubnetwork }
    const vault2 = { ...makeVault({ vault: a('0x0200000000000000000000000000000000000000'), delegator: a('0x2222222222222222222222222222222222222222'), delegatorType: 0n }), limit: { 1: 2n } as StakeBySubnetwork }

    const publicClient = {
      // op1 vault1 [5,0], op1 vault2 [0,0], op2 vault1 [0,0], op2 vault2 [0,7]
      multicall: vi.fn().mockResolvedValueOnce([5n, 0n, 0n, 0n, 0n, 0n, 0n, 7n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getNetVaults').mockResolvedValueOnce([vault1, vault2] as any)
    vi.spyOn(symb, 'getNetOps').mockResolvedValueOnce([op1, op2])

    const encodeSpy = vi.spyOn(subnetwork, 'encodeSubnetwork')
    const res = await symb.getNetOpsVaults(network)

    expect(encodeSpy).toHaveBeenCalledTimes(2)
    encodeSpy.mockRestore()

    expect(res).toEqual([
      { op: op1, vaults: [{ ...vault1, stake: { 0: 5n } as StakeBySubnetwork }] },
      { op: op2, vaults: [{ ...vault2, stake: { 1: 7n } as StakeBySubnetwork }] },
    ])

    const calls = publicClient.multicall.mock.calls[0]?.[0]?.contracts as any[]
    expect(calls).toHaveLength(8)
    for (const c of calls) expect(c.functionName).toBe('stake')
    const decoded = calls.map((c) => decodeSubnetwork(c.args[0]))
    expect(decoded.every((d) => d.net === network)).toBe(true)
  })

  it('getVaultNetsOpsFull decodes stakes per net/op and filters empty', async () => {
    const vaultInfo = makeVault({
      vault: a('0x0100000000000000000000000000000000000000'),
      delegator: a('0x1111111111111111111111111111111111111111'),
      delegatorType: 0n,
    })
    const netA = a('0x1000000000000000000000000000000000000000')
    const netB = a('0x2000000000000000000000000000000000000000')
    const op1 = a('0x9000000000000000000000000000000000000001')
    const op2 = a('0x9000000000000000000000000000000000000002')

    const publicClient = {
      // netA op1 [1,0], netA op2 [0,0], netB op1 [0,2], netB op2 [0,0]
      multicall: vi.fn().mockResolvedValueOnce([1n, 0n, 0n, 0n, 0n, 2n, 0n, 0n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getVaultNetsByDelegator').mockResolvedValueOnce([
      { net: netA, limit: { 0: 1n } as StakeBySubnetwork },
      { net: netB, limit: { 0: 1n } as StakeBySubnetwork },
    ])
    vi.spyOn(symb, 'getVaultOps').mockResolvedValueOnce([op1, op2])

    const encodeSpy = vi.spyOn(subnetwork, 'encodeSubnetwork')
    const res = await symb.getVaultNetsOpsFull(vaultInfo)
    expect(encodeSpy).toHaveBeenCalledTimes(4)
    encodeSpy.mockRestore()

    expect(res).toEqual([
      { net: netA, ops: [{ op: op1, stake: { 0: 1n } as StakeBySubnetwork }] },
      { net: netB, ops: [{ op: op1, stake: { 1: 2n } as StakeBySubnetwork }] },
    ])
  })

  it('getOpNetsVaults builds stake calls net->vault->subnet and reuses getNetVaults results', async () => {
    const operator = a('0x9000000000000000000000000000000000000001')
    const netA = a('0x1000000000000000000000000000000000000000')
    const netB = a('0x2000000000000000000000000000000000000000')

    const vault1 = { ...makeVault({ vault: a('0x0100000000000000000000000000000000000000'), delegator: a('0x1111111111111111111111111111111111111111'), delegatorType: 0n }), limit: { 0: 1n } as StakeBySubnetwork }
    const vault2 = { ...makeVault({ vault: a('0x0200000000000000000000000000000000000000'), delegator: a('0x2222222222222222222222222222222222222222'), delegatorType: 0n }), limit: { 0: 1n } as StakeBySubnetwork }
    const vault3 = { ...makeVault({ vault: a('0x0300000000000000000000000000000000000000'), delegator: a('0x3333333333333333333333333333333333333333'), delegatorType: 0n }), limit: { 0: 1n } as StakeBySubnetwork }

    const publicClient = {
      // netA vault1 [0,0], netB vault2 [1,0], netB vault3 [0,0]
      multicall: vi.fn().mockResolvedValueOnce([0n, 0n, 1n, 0n, 0n, 0n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getOpNets').mockResolvedValueOnce([
      { net: netA, middleware: ZERO_ADDRESS } satisfies NetInfo,
      { net: netB, middleware: ZERO_ADDRESS } satisfies NetInfo,
    ])

    const getNetVaultsSpy = vi.spyOn(symb, 'getNetVaults').mockImplementation(async (net) => {
      const n = getAddress(net)
      if (n === netA) return [vault1] as any
      if (n === netB) return [vault2, vault3] as any
      return []
    })

    const encodeSpy = vi.spyOn(subnetwork, 'encodeSubnetwork')
    const res = await symb.getOpNetsVaults(operator)
    expect(encodeSpy).toHaveBeenCalledTimes(4)
    encodeSpy.mockRestore()

    expect(getNetVaultsSpy).toHaveBeenCalledTimes(2)
    expect(res).toEqual([
      { net: netA, vaults: [] },
      { net: netB, vaults: [{ ...vault2, stake: { 0: 1n } as StakeBySubnetwork }] },
    ])
  })
})

