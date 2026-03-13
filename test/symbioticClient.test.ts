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
  delegatorOperator?: Address
}): VaultInfo {
  return {
    vault: args.vault,
    collateral: a('0xcccccccccccccccccccccccccccccccccccccccc'),
    tvl: 0n,
    delegator: args.delegator,
    slasher: a('0xdddddddddddddddddddddddddddddddddddddddd'),
    delegatorType: args.delegatorType,
    slasherType: 0n,
    delegatorOperator: args.delegatorOperator,
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
    expect(calls.slice(0, 2).map((c) => c.functionName)).toEqual([
      'maxNetworkLimit',
      'maxNetworkLimit',
    ])
    expect(calls.slice(2).map((c) => c.functionName)).toEqual(['networkLimit', 'networkLimit'])

    const decoded = calls.map((c) => decodeSubnetwork(c.args[0]))
    expect(decoded.map((d) => d.net)).toEqual([network, network, network, network])
    expect(decoded.map((d) => d.subnetId)).toEqual([0n, 1n, 0n, 1n])
  })

  it('getNetOpsVaults decodes stakes per op/vault and precomputes subnetworks once', async () => {
    const network = a('0x1000000000000000000000000000000000000000')
    const op1 = a('0x9000000000000000000000000000000000000001')
    const op2 = a('0x9000000000000000000000000000000000000002')

    const vault1 = {
      ...makeVault({
        vault: a('0x0100000000000000000000000000000000000000'),
        delegator: a('0x1111111111111111111111111111111111111111'),
        delegatorType: 0n,
      }),
      limit: { 0: 1n } as StakeBySubnetwork,
    }
    const vault2 = {
      ...makeVault({
        vault: a('0x0200000000000000000000000000000000000000'),
        delegator: a('0x2222222222222222222222222222222222222222'),
        delegatorType: 0n,
      }),
      limit: { 1: 2n } as StakeBySubnetwork,
    }

    const publicClient = {
      multicall: vi
        .fn()
        // optins: vault1 op1 true, vault1 op2 false, vault2 op1 false, vault2 op2 true
        .mockResolvedValueOnce([true, false, false, true])
        // stakes: vault1 op1 [5,0], vault2 op2 [0,7]
        .mockResolvedValueOnce([5n, 0n, 0n, 7n]),
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

    expect(publicClient.multicall).toHaveBeenCalledTimes(2)

    const optinCalls = publicClient.multicall.mock.calls[0]?.[0]?.contracts as any[]
    expect(optinCalls).toHaveLength(4)
    for (const c of optinCalls) expect(c.functionName).toBe('isOptedIn')

    const stakeCalls = publicClient.multicall.mock.calls[1]?.[0]?.contracts as any[]
    expect(stakeCalls).toHaveLength(4)
    for (const c of stakeCalls) expect(c.functionName).toBe('stake')

    const decoded = stakeCalls.map((c) => decodeSubnetwork(c.args[0]))
    expect(decoded.every((d) => d.net === network)).toBe(true)
  })

  it('getNetOpsVaults prunes operator-specific vaults to their pinned operator', async () => {
    const network = a('0x1000000000000000000000000000000000000000')
    const op1 = a('0x9000000000000000000000000000000000000001')
    const op2 = a('0x9000000000000000000000000000000000000002')

    const vaultGeneric = {
      ...makeVault({
        vault: a('0x0100000000000000000000000000000000000000'),
        delegator: a('0x1111111111111111111111111111111111111111'),
        delegatorType: 0n,
      }),
      limit: { 0: 1n } as StakeBySubnetwork,
    }
    const vaultOpSpecific = {
      ...makeVault({
        vault: a('0x0200000000000000000000000000000000000000'),
        delegator: a('0x2222222222222222222222222222222222222222'),
        delegatorType: 2n,
        delegatorOperator: op1,
      }),
      limit: { 0: 1n } as StakeBySubnetwork,
    }

    const publicClient = {
      multicall: vi
        .fn()
        // optins: vaultGeneric op1 true, vaultGeneric op2 false
        .mockResolvedValueOnce([true, false])
        // stakes: vaultGeneric op1 [5,0], vaultOpSpecific op1 [0,7]
        .mockResolvedValueOnce([5n, 0n, 0n, 7n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getNetVaults').mockResolvedValueOnce([vaultGeneric, vaultOpSpecific] as any)
    vi.spyOn(symb, 'getNetOps').mockResolvedValueOnce([op1, op2])

    const res = await symb.getNetOpsVaults(network)
    expect(res).toEqual([
      {
        op: op1,
        vaults: [
          { ...vaultGeneric, stake: { 0: 5n } as StakeBySubnetwork },
          { ...vaultOpSpecific, stake: { 1: 7n } as StakeBySubnetwork },
        ],
      },
      { op: op2, vaults: [] },
    ])

    expect(publicClient.multicall).toHaveBeenCalledTimes(2)

    const optinCalls = publicClient.multicall.mock.calls[0]?.[0]?.contracts as any[]
    expect(optinCalls).toHaveLength(2)
    expect(optinCalls.every((c) => c.functionName === 'isOptedIn')).toBe(true)

    const stakeCalls = publicClient.multicall.mock.calls[1]?.[0]?.contracts as any[]
    // 1 generic vault * 1 opted-in op * 2 subnetworks + 1 pinned vault * 1 op * 2 subnetworks = 4 calls
    expect(stakeCalls).toHaveLength(4)
    expect(stakeCalls.every((c) => c.functionName === 'stake')).toBe(true)
    expect(
      stakeCalls.some(
        (c) =>
          c.address === vaultOpSpecific.delegator && Array.isArray(c.args) && c.args[1] === op2,
      ),
    ).toBe(false)
  })

  it('getNetsFullCounts batches ops opt-ins + vault limits for all nets', async () => {
    const netA = a('0x1000000000000000000000000000000000000000')
    const netB = a('0x2000000000000000000000000000000000000000')

    const op1 = a('0x9000000000000000000000000000000000000001')
    const op2 = a('0x9000000000000000000000000000000000000002')

    const vault1 = makeVault({
      vault: a('0x0100000000000000000000000000000000000000'),
      delegator: a('0x1111111111111111111111111111111111111111'),
      delegatorType: 0n,
    })
    const vault2 = makeVault({
      vault: a('0x0200000000000000000000000000000000000000'),
      delegator: a('0x2222222222222222222222222222222222222222'),
      delegatorType: 3n,
      delegatorNetwork: netB,
    })

    const nets = [
      { net: netA, middleware: ZERO_ADDRESS } satisfies NetInfo,
      { net: netB, middleware: ZERO_ADDRESS } satisfies NetInfo,
    ]

    const publicClient = {
      multicall: vi
        .fn()
        // ops opt-ins:
        // netA: op1 true, op2 true
        // netB: op1 false, op2 true
        .mockResolvedValueOnce([true, true, false, true])
        // limits:
        // netA: vault1 [0,10] (selected)
        // netB: vault1 [0,0] (skipped), vault2 [5,0] (selected)
        .mockResolvedValueOnce([0n, 10n, 0n, 0n, 5n, 0n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getOps').mockResolvedValueOnce([op1, op2])
    vi.spyOn(symb, 'getVaults').mockResolvedValueOnce([vault1, vault2])

    const res = await symb.getNetsFullCounts(nets)
    expect(res).toEqual([
      { ops: 2, vaults: 1 },
      { ops: 1, vaults: 1 },
    ])

    expect(publicClient.multicall).toHaveBeenCalledTimes(2)

    const optinCalls = publicClient.multicall.mock.calls[0]?.[0]?.contracts as any[]
    expect(optinCalls).toHaveLength(4)
    expect(optinCalls.every((c) => c.functionName === 'isOptedIn')).toBe(true)

    const limitCalls = publicClient.multicall.mock.calls[1]?.[0]?.contracts as any[]
    expect(limitCalls).toHaveLength(6)
    expect(limitCalls.slice(0, 4).every((c) => c.functionName === 'networkLimit')).toBe(true)
    expect(limitCalls.slice(4).every((c) => c.functionName === 'maxNetworkLimit')).toBe(true)
    // Pinned-to-netB vault should not be queried against netA.
    expect(
      limitCalls.some((c) => c.address === vault2.delegator && c.functionName === 'networkLimit'),
    ).toBe(false)
  })

  it('getVaultNetsOpsFull decodes stakes per net/op and filters empty', async () => {
    const vault1 = makeVault({
      vault: a('0x0100000000000000000000000000000000000000'),
      delegator: a('0x1111111111111111111111111111111111111111'),
      delegatorType: 0n,
    })
    const vault2 = makeVault({
      vault: a('0x0200000000000000000000000000000000000000'),
      delegator: a('0x2222222222222222222222222222222222222222'),
      delegatorType: 0n,
    })

    const netA = a('0x1000000000000000000000000000000000000000')
    const netB = a('0x2000000000000000000000000000000000000000')
    const op1 = a('0x9000000000000000000000000000000000000001')
    const op2 = a('0x9000000000000000000000000000000000000002')

    const publicClient = {
      multicall: vi
        .fn()
        // limits:
        // v1 netA [0,5] (selected), v1 netB [0,0] (skipped),
        // v2 netA [0,0] (skipped), v2 netB [1,0] (selected)
        .mockResolvedValueOnce([0n, 5n, 0n, 0n, 0n, 0n, 1n, 0n])
        // optins: v1 op1 true, v1 op2 false, v2 op1 true, v2 op2 true
        .mockResolvedValueOnce([true, false, true, true])
        // stakes:
        // v1 netA op1 [0,10],
        // v2 netB op1 [0,0] (filtered), v2 netB op2 [5,0]
        .mockResolvedValueOnce([0n, 10n, 0n, 0n, 5n, 0n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getNets').mockResolvedValueOnce([
      { net: netA, middleware: ZERO_ADDRESS } satisfies NetInfo,
      { net: netB, middleware: ZERO_ADDRESS } satisfies NetInfo,
    ])
    vi.spyOn(symb, 'getOps').mockResolvedValueOnce([op1, op2])

    const encodeSpy = vi.spyOn(subnetwork, 'encodeSubnetwork')
    const res = await symb.getVaultsNetsOpsFull([vault1, vault2])
    expect(encodeSpy).toHaveBeenCalledTimes(4)
    encodeSpy.mockRestore()

    expect(publicClient.multicall).toHaveBeenCalledTimes(3)
    expect(res).toEqual([
      [{ net: netA, ops: [{ op: op1, stake: { 1: 10n } as StakeBySubnetwork }] }],
      [{ net: netB, ops: [{ op: op2, stake: { 0: 5n } as StakeBySubnetwork }] }],
    ])
  })

  it('getVaultNetsOpsFull delegates to getVaultsNetsOpsFull', async () => {
    const vaultInfo = makeVault({
      vault: a('0x0100000000000000000000000000000000000000'),
      delegator: a('0x1111111111111111111111111111111111111111'),
      delegatorType: 0n,
    })

    const publicClient = {
      multicall: vi.fn(),
    }
    const symb = makeClient(publicClient)
    const spy = vi
      .spyOn(symb, 'getVaultsNetsOpsFull')
      .mockResolvedValueOnce([[{ net: ZERO_ADDRESS, ops: [] }]])

    const res = await symb.getVaultNetsOpsFull(vaultInfo)
    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy).toHaveBeenCalledWith([vaultInfo])
    expect(res).toEqual([{ net: ZERO_ADDRESS, ops: [] }])
  })

  it('getOpNetsVaults builds calls net->vault->subnet and filters via vault opt-in + limits', async () => {
    const operator = a('0x9000000000000000000000000000000000000001')
    const netA = a('0x1000000000000000000000000000000000000000')
    const netB = a('0x2000000000000000000000000000000000000000')

    const vault1 = makeVault({
      vault: a('0x0100000000000000000000000000000000000000'),
      delegator: a('0x1111111111111111111111111111111111111111'),
      delegatorType: 0n,
    })
    const vault2 = makeVault({
      vault: a('0x0200000000000000000000000000000000000000'),
      delegator: a('0x2222222222222222222222222222222222222222'),
      delegatorType: 0n,
    })
    const vault3 = makeVault({
      vault: a('0x0300000000000000000000000000000000000000'),
      delegator: a('0x3333333333333333333333333333333333333333'),
      delegatorType: 0n,
    })

    const publicClient = {
      multicall: vi
        .fn()
        // optins: v1 false, v2 true, v3 true
        .mockResolvedValueOnce([false, true, true])
        // limits:
        // netA v2 [0,0], netA v3 [0,0], netB v2 [1,0] (selected), netB v3 [0,0]
        .mockResolvedValueOnce([0n, 0n, 0n, 0n, 1n, 0n, 0n, 0n])
        // stakes: netB v2 [1,0]
        .mockResolvedValueOnce([1n, 0n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getOpNets').mockResolvedValueOnce([
      { net: netA, middleware: ZERO_ADDRESS } satisfies NetInfo,
      { net: netB, middleware: ZERO_ADDRESS } satisfies NetInfo,
    ])
    vi.spyOn(symb, 'getVaults').mockResolvedValueOnce([vault1, vault2, vault3])

    const encodeSpy = vi.spyOn(subnetwork, 'encodeSubnetwork')
    const res = await symb.getOpNetsVaults(operator)
    // subnetworks are computed twice per net (limits pass + stakes pass)
    expect(encodeSpy).toHaveBeenCalledTimes(8)
    encodeSpy.mockRestore()

    expect(res).toEqual([
      { net: netA, vaults: [] },
      {
        net: netB,
        vaults: [
          {
            ...vault2,
            limit: { 0: 1n } as StakeBySubnetwork,
            stake: { 0: 1n } as StakeBySubnetwork,
          },
        ],
      },
    ])

    expect(publicClient.multicall).toHaveBeenCalledTimes(3)
    const optinCalls = publicClient.multicall.mock.calls[0]?.[0]?.contracts as any[]
    expect(optinCalls).toHaveLength(3)
    for (const c of optinCalls) expect(c.functionName).toBe('isOptedIn')

    const limitCalls = publicClient.multicall.mock.calls[1]?.[0]?.contracts as any[]
    expect(limitCalls).toHaveLength(8)
    for (const c of limitCalls) expect(c.functionName).toBe('networkLimit')
    expect(limitCalls.some((c) => c.address === vault1.delegator)).toBe(false)

    const stakeCalls = publicClient.multicall.mock.calls[2]?.[0]?.contracts as any[]
    expect(stakeCalls).toHaveLength(2)
    for (const c of stakeCalls) expect(c.functionName).toBe('stake')
  })

  it('getOpNetsVaults prunes operator-specific vaults pinned to other operators', async () => {
    const operator = a('0x9000000000000000000000000000000000000001')
    const other = a('0x9000000000000000000000000000000000000002')
    const netA = a('0x1000000000000000000000000000000000000000')

    const vaultGeneric = {
      ...makeVault({
        vault: a('0x0100000000000000000000000000000000000000'),
        delegator: a('0x1111111111111111111111111111111111111111'),
        delegatorType: 0n,
      }),
      limit: { 0: 1n } as StakeBySubnetwork,
    }
    const vaultPinnedOther = {
      ...makeVault({
        vault: a('0x0200000000000000000000000000000000000000'),
        delegator: a('0x2222222222222222222222222222222222222222'),
        delegatorType: 2n,
        delegatorOperator: other,
      }),
      limit: { 0: 1n } as StakeBySubnetwork,
    }

    const publicClient = {
      multicall: vi
        .fn()
        // optins: vaultGeneric opted in
        .mockResolvedValueOnce([true])
        // limits: vaultGeneric [1,0] (selected)
        .mockResolvedValueOnce([1n, 0n])
        // stakes: vaultGeneric [0,9]
        .mockResolvedValueOnce([0n, 9n]),
    }
    const symb = makeClient(publicClient)
    vi.spyOn(symb, 'getOpNets').mockResolvedValueOnce([
      { net: netA, middleware: ZERO_ADDRESS } satisfies NetInfo,
    ])
    vi.spyOn(symb, 'getVaults').mockResolvedValueOnce([vaultGeneric, vaultPinnedOther] as any)

    const res = await symb.getOpNetsVaults(operator)
    expect(res).toEqual([
      {
        net: netA,
        vaults: [
          {
            ...vaultGeneric,
            limit: { 0: 1n } as StakeBySubnetwork,
            stake: { 1: 9n } as StakeBySubnetwork,
          },
        ],
      },
    ])

    expect(publicClient.multicall).toHaveBeenCalledTimes(3)
    const calls = publicClient.multicall.mock.calls[2]?.[0]?.contracts as any[]
    expect(calls).toHaveLength(2)
    expect(calls.every((c) => c.address === vaultGeneric.delegator)).toBe(true)
  })
})
