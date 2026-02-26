import { getAddress, type Address, type Hex } from 'viem'
import type { Chain, PublicClient, Transport } from 'viem'

import type { ChainAddresses, ChainAddressKey, ChainKey } from '../config/chains'
import {
  DELEGATOR_TYPES_NAMES,
  SLASHER_TYPES_NAMES,
  SUBNETWORK_IDS,
  ZERO_ADDRESS,
} from './constants'
import {
  CuratorRegistryAbi,
  delegatorAbiByType,
  FeeRegistryAbi,
  FullRestakeDelegatorAbi,
  NetworkMiddlewareServiceAbi,
  NetworkRegistryAbi,
  NetworkRestakeDelegatorAbi,
  OperatorNetworkOptInServiceAbi,
  OperatorRegistryAbi,
  OperatorVaultOptInServiceAbi,
  ProtocolFeesAbi,
  VaultAbi,
  VaultFactoryAbi,
  VaultSnapshotRewardsAbi,
  VaultTokenizedAbi,
  VetoSlasherAbi,
} from './contracts'
import { TtlCache } from './cache'
import { multicallChunked } from './multicall'
import { encodeSubnetwork } from './subnetwork'
import type { NetInfo, StakeBySubnetwork, TokenMeta, VaultInfo } from './types'
import { tokenMetaFallback } from './units'

export type SymbioticClientOptions = {
  chainKey: ChainKey
  chainId: number
  addresses: ChainAddresses
  publicClient: PublicClient<Transport, Chain>
  multicallBatchSize?: number
  multicallConcurrency?: number
}

export class SymbioticClient {
  private readonly chainKey: ChainKey
  private readonly chainId: number
  private readonly addresses: ChainAddresses
  private readonly publicClient: PublicClient<Transport, Chain>
  private readonly multicallBatchSize: number
  private readonly multicallConcurrency: number

  private readonly tokenMetaCache = new TtlCache<Address, TokenMeta>(24 * 60 * 60 * 1000)
  private readonly netsCache = new TtlCache<string, NetInfo[]>(60 * 1000)
  private readonly opsCache = new TtlCache<string, Address[]>(60 * 1000)
  private readonly vaultsCache = new TtlCache<string, VaultInfo[]>(60 * 1000)

  constructor(opts: SymbioticClientOptions) {
    this.chainKey = opts.chainKey
    this.chainId = opts.chainId
    this.addresses = opts.addresses
    this.publicClient = opts.publicClient
    this.multicallBatchSize = opts.multicallBatchSize ?? 400
    this.multicallConcurrency = opts.multicallConcurrency ?? 4
  }

  getChainId() {
    return this.chainId
  }

  getAddresses() {
    return this.addresses
  }

  requireAddress(key: ChainAddressKey): Address {
    const address = this.addresses[key] as Address | undefined
    return this.requireAddressValue(key, address)
  }

  private requireAddressValue(name: string, address: Address | undefined): Address {
    if (!address) {
      throw new Error(
        `${name} address is not configured for chain ${this.chainKey}. Provide it via SYMB_ADDRESSES_JSON.`,
      )
    }
    return address
  }

  private async read<T>(args: {
    abi: any
    address: Address
    functionName: string
    args?: readonly unknown[]
  }): Promise<T> {
    return this.publicClient.readContract({
      address: args.address,
      abi: args.abi,
      functionName: args.functionName as any,
      args: args.args as any,
    }) as Promise<T>
  }

  private async mc(contracts: any[], allowFailure = false) {
    return multicallChunked(this.publicClient, contracts, {
      allowFailure,
      batchSize: this.multicallBatchSize,
      concurrency: this.multicallConcurrency,
    })
  }

  private subnetworksForNet(net: Address): Hex[] {
    const n = getAddress(net)
    return SUBNETWORK_IDS.map((subnetId) => encodeSubnetwork({ net: n, subnetId }))
  }

  private pinnedOperator(vault: Pick<VaultInfo, 'delegatorType' | 'delegatorOperator'>) {
    if ((vault.delegatorType === 2n || vault.delegatorType === 3n) && vault.delegatorOperator)
      return vault.delegatorOperator
    return undefined
  }

  private pinnedNetwork(vault: Pick<VaultInfo, 'delegatorType' | 'delegatorNetwork'>) {
    if (vault.delegatorType === 3n && vault.delegatorNetwork) return vault.delegatorNetwork
    return undefined
  }

  private buildLimitCallsForNet(net: Address, vaults: readonly VaultInfo[]) {
    const network = getAddress(net)
    const subnetworks = this.subnetworksForNet(network)

    const calls: any[] = []
    const eligible: VaultInfo[] = []

    for (const vault of vaults) {
      if (vault.delegator === ZERO_ADDRESS) continue

      const pinnedNet = this.pinnedNetwork(vault)
      if (pinnedNet && pinnedNet !== network) continue

      const functionName = vault.delegatorType === 3n ? 'maxNetworkLimit' : 'networkLimit'
      for (const subnetwork of subnetworks) {
        calls.push({
          address: vault.delegator,
          abi: FullRestakeDelegatorAbi,
          functionName,
          args: [subnetwork],
        })
      }
      eligible.push(vault)
    }

    return { calls, eligible }
  }

  private decodeStakeBySubnetwork(
    values: readonly bigint[],
    offset: number,
  ): {
    stake: StakeBySubnetwork
    hasValue: boolean
    nextOffset: number
  } {
    const stake: StakeBySubnetwork = {}
    let hasValue = false
    for (const subnetId of SUBNETWORK_IDS) {
      const value = values[offset++]!
      if (value > 0n) {
        stake[subnetId] = value
        hasValue = true
      }
    }
    return { stake, hasValue, nextOffset: offset }
  }

  private decodeStakeBySubnetworkHasValue(values: readonly bigint[], offset: number): boolean {
    for (let i = 0; i < SUBNETWORK_IDS.length; i++) {
      if ((values[offset + i] ?? 0n) > 0n) return true
    }
    return false
  }

  async getTokenMeta(token: Address): Promise<TokenMeta> {
    const t = getAddress(token)
    const cached = this.tokenMetaCache.get(t)
    if (cached) return cached

    const [sym, dec] = await this.mc(
      [
        {
          address: t,
          abi: VaultTokenizedAbi,
          functionName: 'symbol',
        },
        {
          address: t,
          abi: VaultTokenizedAbi,
          functionName: 'decimals',
        },
      ],
      true,
    )

    const symbol = sym?.status === 'success' ? (sym.result as string) : undefined
    const decimals =
      dec?.status === 'success'
        ? typeof dec.result === 'bigint'
          ? Number(dec.result)
          : typeof dec.result === 'number'
            ? dec.result
            : undefined
        : undefined

    const meta =
      symbol && Number.isFinite(decimals) ? { symbol, decimals: decimals! } : tokenMetaFallback()

    this.tokenMetaCache.set(t, meta)
    return meta
  }

  async getMiddleware(net: Address): Promise<Address> {
    const middleware = await this.read<Address>({
      abi: NetworkMiddlewareServiceAbi,
      address: this.requireAddress('middleware_service'),
      functionName: 'middleware',
      args: [net],
    })
    return getAddress(middleware)
  }

  async getNets(): Promise<NetInfo[]> {
    const cached = this.netsCache.get('nets')
    if (cached) return cached

    const total = await this.read<bigint>({
      abi: NetworkRegistryAbi,
      address: this.requireAddress('net_registry'),
      functionName: 'totalEntities',
    })

    const calls: any[] = []
    for (let i = 0n; i < total; i++) {
      calls.push({
        address: this.requireAddress('net_registry'),
        abi: NetworkRegistryAbi,
        functionName: 'entity',
        args: [i],
      })
    }

    const entities = await this.mc(calls)
    const nets = entities.map((net: any) => getAddress(net as Address))

    const middlewareCalls = nets.map((net) => ({
      address: this.requireAddress('middleware_service'),
      abi: NetworkMiddlewareServiceAbi,
      functionName: 'middleware',
      args: [net],
    }))

    const middlewareResults = await this.mc(middlewareCalls)
    const middlewares = middlewareResults.map((middleware: any) =>
      getAddress(middleware as Address),
    )

    const result: NetInfo[] = nets.map((net, i) => ({ net, middleware: middlewares[i]! }))
    this.netsCache.set('nets', result)
    return result
  }

  async getOps(): Promise<Address[]> {
    const cached = this.opsCache.get('ops')
    if (cached) return cached

    const total = await this.read<bigint>({
      abi: OperatorRegistryAbi,
      address: this.requireAddress('op_registry'),
      functionName: 'totalEntities',
    })

    const calls: any[] = []
    for (let i = 0n; i < total; i++) {
      calls.push({
        address: this.requireAddress('op_registry'),
        abi: OperatorRegistryAbi,
        functionName: 'entity',
        args: [i],
      })
    }
    const entities = await this.mc(calls)
    const ops = entities.map((op: any) => getAddress(op as Address))
    this.opsCache.set('ops', ops)
    return ops
  }

  async getOpNets(operator: Address): Promise<NetInfo[]> {
    const nets = await this.getNets()

    const optinCalls = nets.map((net) => ({
      address: this.requireAddress('op_net_opt_in'),
      abi: OperatorNetworkOptInServiceAbi,
      functionName: 'isOptedIn',
      args: [operator, net.net],
    }))
    const optins = await this.mc(optinCalls)
    return nets.filter((net, i) => Boolean(optins[i]))
  }

  async getNetOps(net: Address): Promise<Address[]> {
    const ops = await this.getOps()

    const calls = ops.map((op) => ({
      address: this.requireAddress('op_net_opt_in'),
      abi: OperatorNetworkOptInServiceAbi,
      functionName: 'isOptedIn',
      args: [op, net],
    }))
    const optins = await this.mc(calls)
    return ops.filter((op, i) => Boolean(optins[i]))
  }

  async getNetsFullCounts(
    nets?: readonly NetInfo[],
  ): Promise<Array<{ ops: number; vaults: number }>> {
    const netsList = nets ?? (await this.getNets())
    const ops = await this.getOps()
    const vaults = await this.getVaults()

    // Operators per net (N * O) but done as a single chunked multicall.
    const optinCalls: any[] = []
    for (const net of netsList) {
      for (const op of ops) {
        optinCalls.push({
          address: this.requireAddress('op_net_opt_in'),
          abi: OperatorNetworkOptInServiceAbi,
          functionName: 'isOptedIn',
          args: [op, net.net],
        })
      }
    }

    const optins = optinCalls.length ? await this.mc(optinCalls) : []
    const opsCounts: number[] = new Array(netsList.length).fill(0)

    if (ops.length) {
      for (let netIdx = 0; netIdx < netsList.length; netIdx++) {
        let count = 0
        const base = netIdx * ops.length
        for (let opIdx = 0; opIdx < ops.length; opIdx++) {
          if (optins[base + opIdx]) count++
        }
        opsCounts[netIdx] = count
      }
    }

    // Vaults per net: count vaults with at least one non-zero network limit for any subnetwork.
    const limitCalls: any[] = []
    const eligibleVaultsByNet: VaultInfo[][] = new Array(netsList.length)
    for (let netIdx = 0; netIdx < netsList.length; netIdx++) {
      const { calls, eligible } = this.buildLimitCallsForNet(netsList[netIdx]!.net, vaults)
      eligibleVaultsByNet[netIdx] = eligible
      limitCalls.push(...calls)
    }

    const limits = (await this.mc(limitCalls)) as bigint[]
    const vaultCounts: number[] = new Array(netsList.length).fill(0)

    let offset = 0
    for (let netIdx = 0; netIdx < netsList.length; netIdx++) {
      const eligible = eligibleVaultsByNet[netIdx] ?? []
      for (let vIdx = 0; vIdx < eligible.length; vIdx++) {
        if (this.decodeStakeBySubnetworkHasValue(limits, offset)) {
          vaultCounts[netIdx] = (vaultCounts[netIdx] ?? 0) + 1
        }
        offset += SUBNETWORK_IDS.length
      }
    }

    return netsList.map((_n, i) => ({ ops: opsCounts[i] ?? 0, vaults: vaultCounts[i] ?? 0 }))
  }

  async getVaults(): Promise<VaultInfo[]> {
    const cached = this.vaultsCache.get('vaults')
    if (cached) return cached

    const total = await this.read<bigint>({
      abi: VaultFactoryAbi,
      address: this.requireAddress('vault_factory'),
      functionName: 'totalEntities',
    })

    const entityCalls: any[] = []
    for (let i = 0n; i < total; i++) {
      entityCalls.push({
        address: this.requireAddress('vault_factory'),
        abi: VaultFactoryAbi,
        functionName: 'entity',
        args: [i],
      })
    }

    const vaultResults = await this.mc(entityCalls)
    const vaults = vaultResults.map((vault: any) => getAddress(vault as Address))

    const dataCalls: any[] = []
    for (const vault of vaults) {
      dataCalls.push({ address: vault, abi: VaultAbi, functionName: 'collateral' })
      dataCalls.push({ address: vault, abi: VaultAbi, functionName: 'activeStake' })
      dataCalls.push({ address: vault, abi: VaultAbi, functionName: 'delegator' })
      dataCalls.push({ address: vault, abi: VaultAbi, functionName: 'slasher' })
    }
    const data = await this.mc(dataCalls)

    const results: VaultInfo[] = []
    for (let i = 0; i < vaults.length; i++) {
      const offset = i * 4
      results.push({
        vault: vaults[i]!,
        collateral: getAddress(data[offset]! as Address),
        tvl: data[offset + 1]! as bigint,
        delegator: getAddress(data[offset + 2]! as Address),
        slasher: getAddress(data[offset + 3]! as Address),
        delegatorType: -1n,
        slasherType: -1n,
      })
    }

    // TYPE() reads
    const typeCalls: any[] = []
    const assignments: Array<{ idx: number; role: 'delegatorType' | 'slasherType' }> = []
    for (let idx = 0; idx < results.length; idx++) {
      const v = results[idx]!
      if (v.delegator !== ZERO_ADDRESS) {
        typeCalls.push({
          address: v.delegator,
          abi: NetworkRestakeDelegatorAbi,
          functionName: 'TYPE',
        })
        assignments.push({ idx, role: 'delegatorType' })
      }
      if (v.slasher !== ZERO_ADDRESS) {
        typeCalls.push({
          address: v.slasher,
          abi: NetworkRestakeDelegatorAbi,
          functionName: 'TYPE',
        })
        assignments.push({ idx, role: 'slasherType' })
      }
    }
    const typeResults = await this.mc(typeCalls)
    for (let i = 0; i < assignments.length; i++) {
      const { idx, role } = assignments[i]!
      results[idx]![role] = typeResults[i]! as bigint
    }

    // Delegator enrichment: resolve optional operator/network fields for specific delegator types.
    const enrichCalls: any[] = []
    const enrichAssign: Array<{ idx: number; role: 'delegatorOperator' | 'delegatorNetwork' }> = []
    for (let idx = 0; idx < results.length; idx++) {
      const v = results[idx]!
      if (v.delegator === ZERO_ADDRESS) continue

      if (v.delegatorType === 2n || v.delegatorType === 3n) {
        const abi = delegatorAbiByType(v.delegatorType)
        enrichCalls.push({
          address: v.delegator,
          abi,
          functionName: 'operator',
        })
        enrichAssign.push({ idx, role: 'delegatorOperator' })
      }
      if (v.delegatorType === 3n) {
        const abi = delegatorAbiByType(v.delegatorType)
        enrichCalls.push({ address: v.delegator, abi, functionName: 'network' })
        enrichAssign.push({ idx, role: 'delegatorNetwork' })
      }
    }

    if (enrichCalls.length) {
      const enrichResults = await this.mc(enrichCalls)
      for (let i = 0; i < enrichAssign.length; i++) {
        const { idx, role } = enrichAssign[i]!
        results[idx]![role] = getAddress(enrichResults[i]! as Address)
      }
    }

    this.vaultsCache.set('vaults', results)
    return results
  }

  async getVaultDelegator(vault: Address): Promise<Address> {
    const delegator = await this.read<Address>({
      abi: VaultAbi,
      address: vault,
      functionName: 'delegator',
    })
    return getAddress(delegator)
  }

  async getVaultCollateral(vault: Address): Promise<Address> {
    const collateral = await this.read<Address>({
      abi: VaultAbi,
      address: vault,
      functionName: 'collateral',
    })
    return getAddress(collateral)
  }

  async getVaultSlasher(vault: Address): Promise<Address> {
    const slasher = await this.read<Address>({
      abi: VaultAbi,
      address: vault,
      functionName: 'slasher',
    })
    return getAddress(slasher)
  }

  async getNetVaults(net: Address): Promise<(VaultInfo & { limit: StakeBySubnetwork })[]> {
    const vaults = await this.getVaults()
    const { calls: limitCalls, eligible } = this.buildLimitCallsForNet(net, vaults)
    const limits = (await this.mc(limitCalls)) as bigint[]
    const results: (VaultInfo & { limit: StakeBySubnetwork })[] = []

    let i = 0
    for (const vault of eligible) {
      const { stake: limit, hasValue, nextOffset } = this.decodeStakeBySubnetwork(limits, i)
      i = nextOffset
      if (hasValue) results.push({ ...vault, limit })
    }

    return results
  }

  async getNetOpsVaults(net: Address): Promise<
    Array<{
      op: Address
      vaults: Array<VaultInfo & { limit: StakeBySubnetwork; stake: StakeBySubnetwork }>
    }>
  > {
    const vaults = await this.getNetVaults(net)
    const ops = await this.getNetOps(net)

    const subnetworks = this.subnetworksForNet(net)
    const results = ops.map((op) => ({ op, vaults: [] as any[] }))
    const opIndex = new Map<Address, number>()
    for (let opIdx = 0; opIdx < ops.length; opIdx++) opIndex.set(ops[opIdx]!, opIdx)

    // Pass 1: Determine which operators are opted into each vault (bounded by ops opted into network).
    const candidateOpIndexesByVault: number[][] = Array.from({ length: vaults.length }, () => [])
    const optinCalls: any[] = []
    const optinPairs: Array<{ vaultIdx: number; opIdx: number }> = []

    for (let vaultIdx = 0; vaultIdx < vaults.length; vaultIdx++) {
      const vault = vaults[vaultIdx]!
      const pinnedOp = this.pinnedOperator(vault)
      if (pinnedOp) {
        const idx = opIndex.get(pinnedOp)
        if (idx !== undefined) candidateOpIndexesByVault[vaultIdx]!.push(idx)
        continue
      }

      for (let opIdx = 0; opIdx < ops.length; opIdx++) {
        optinCalls.push({
          address: this.requireAddress('op_vault_opt_in'),
          abi: OperatorVaultOptInServiceAbi,
          functionName: 'isOptedIn',
          args: [ops[opIdx]!, vault.vault],
        })
        optinPairs.push({ vaultIdx, opIdx })
      }
    }

    if (optinCalls.length) {
      const optins = await this.mc(optinCalls)
      for (let i = 0; i < optinPairs.length; i++) {
        if (!optins[i]) continue
        const { vaultIdx, opIdx } = optinPairs[i]!
        candidateOpIndexesByVault[vaultIdx]!.push(opIdx)
      }
    }

    // Pass 2: Stake calls only for (vault, op) pairs that are opted into the vault.
    const stakeCalls: any[] = []
    const stakePairs: Array<{ opIdx: number; vault: VaultInfo & { limit: StakeBySubnetwork } }> =
      []

    for (let vaultIdx = 0; vaultIdx < vaults.length; vaultIdx++) {
      const vault = vaults[vaultIdx]!
      const opIndexes = candidateOpIndexesByVault[vaultIdx] ?? []
      for (const opIdx of opIndexes) {
        const op = ops[opIdx]!
        for (const subnetwork of subnetworks) {
          stakeCalls.push({
            address: vault.delegator,
            abi: NetworkRestakeDelegatorAbi,
            functionName: 'stake',
            args: [subnetwork, op],
          })
        }
        stakePairs.push({ opIdx, vault })
      }
    }

    const stakes = (await this.mc(stakeCalls)) as bigint[]
    let stakeOffset = 0
    for (const pair of stakePairs) {
      const { stake, hasValue, nextOffset } = this.decodeStakeBySubnetwork(stakes, stakeOffset)
      stakeOffset = nextOffset
      if (hasValue) results[pair.opIdx]!.vaults.push({ ...pair.vault, stake })
    }

    return results
  }

  async getVaultOps(vault: Address): Promise<Address[]> {
    const ops = await this.getOps()

    const calls = ops.map((op) => ({
      address: this.requireAddress('op_vault_opt_in'),
      abi: OperatorVaultOptInServiceAbi,
      functionName: 'isOptedIn',
      args: [op, vault],
    }))
    const optins = await this.mc(calls)
    return ops.filter((op, i) => Boolean(optins[i]))
  }

  async getVaultNetsByDelegator(
    delegator: Address,
  ): Promise<Array<{ net: Address; limit: StakeBySubnetwork }>> {
    const nets = await this.getNets()

    const calls: any[] = []
    for (const net of nets) {
      const subnetworks = this.subnetworksForNet(net.net)
      for (const subnetwork of subnetworks) {
        calls.push({
          address: delegator,
          abi: FullRestakeDelegatorAbi,
          functionName: 'maxNetworkLimit',
          args: [subnetwork],
        })
      }
    }
    const results = (await this.mc(calls)) as bigint[]

    const out: Array<{ net: Address; limit: StakeBySubnetwork }> = []
    let i = 0
    for (const net of nets) {
      const { stake: limit, hasValue, nextOffset } = this.decodeStakeBySubnetwork(results, i)
      i = nextOffset
      if (hasValue) out.push({ net: net.net, limit })
    }

    return out
  }

  async getVaultNets(vault: Address): Promise<Array<{ net: Address; limit: StakeBySubnetwork }>> {
    const delegator = await this.getVaultDelegator(vault)
    return this.getVaultNetsByDelegator(delegator)
  }

  async getVaultNetsOps(vault: Address): Promise<Record<Address, Address[]>> {
    const vaultOps = await this.getVaultOps(vault)
    const vaultNets = await this.getVaultNets(vault)

    const calls: any[] = []
    const pairs: Array<{ net: Address; op: Address }> = []
    for (const net of vaultNets) {
      for (const op of vaultOps) {
        calls.push({
          address: this.requireAddress('op_net_opt_in'),
          abi: OperatorNetworkOptInServiceAbi,
          functionName: 'isOptedIn',
          args: [op, net.net],
        })
        pairs.push({ net: net.net, op })
      }
    }
    const optins = await this.mc(calls)

    const out: Record<Address, Address[]> = {} as any
    for (const net of vaultNets) out[net.net] = []
    for (let i = 0; i < pairs.length; i++) {
      if (optins[i]) out[pairs[i]!.net]!.push(pairs[i]!.op)
    }
    return out
  }

  async getVaultNetsOpsFull(
    vaultInfo: VaultInfo,
  ): Promise<Array<{ net: Address; ops: Array<{ op: Address; stake: StakeBySubnetwork }> }>> {
    const res = await this.getVaultsNetsOpsFull([vaultInfo])
    return res[0] ?? []
  }

  async getVaultsNetsOpsFull(
    vaultInfos: readonly VaultInfo[],
  ): Promise<Array<Array<{ net: Address; ops: Array<{ op: Address; stake: StakeBySubnetwork }> }>>> {
    if (vaultInfos.length === 0) return []

    const nets = await this.getNets()
    const ops = await this.getOps()

    // Precompute subnetworks once per net; used by both limit and stake call builders.
    const subnetworksByNet = new Map<Address, Hex[]>()
    for (const net of nets) subnetworksByNet.set(net.net, this.subnetworksForNet(net.net))
    const getSubnetworks = (net: Address) => {
      const cached = subnetworksByNet.get(net)
      if (cached) return cached
      const subnetworks = this.subnetworksForNet(net)
      subnetworksByNet.set(net, subnetworks)
      return subnetworks
    }

    // Pass 1: Determine which networks are relevant for each vault by reading maxNetworkLimit.
    const limitCalls: any[] = []
    const candidateNetsByVault: Address[][] = new Array(vaultInfos.length)
    for (let vIdx = 0; vIdx < vaultInfos.length; vIdx++) {
      const v = vaultInfos[vIdx]!
      if (v.delegator === ZERO_ADDRESS) {
        candidateNetsByVault[vIdx] = []
        continue
      }

      // OperatorNetworkSpecific delegators are bound to a single network.
      const pinnedNet = this.pinnedNetwork(v)
      if (pinnedNet) {
        candidateNetsByVault[vIdx] = [pinnedNet]
      } else {
        candidateNetsByVault[vIdx] = nets.map((n) => n.net)
      }
    }

    for (let vIdx = 0; vIdx < vaultInfos.length; vIdx++) {
      const v = vaultInfos[vIdx]!
      if (v.delegator === ZERO_ADDRESS) continue
      const candidateNets = candidateNetsByVault[vIdx] ?? []
      for (const net of candidateNets) {
        const subnetworks = getSubnetworks(net)
        for (const subnetwork of subnetworks) {
          limitCalls.push({
            address: v.delegator,
            abi: FullRestakeDelegatorAbi,
            functionName: 'maxNetworkLimit',
            args: [subnetwork],
          })
        }
      }
    }

    const limitResults = (await this.mc(limitCalls)) as bigint[]
    const netsByVault: Address[][] = new Array(vaultInfos.length)
    let limitOffset = 0

    for (let vIdx = 0; vIdx < vaultInfos.length; vIdx++) {
      if (vaultInfos[vIdx]!.delegator === ZERO_ADDRESS) {
        netsByVault[vIdx] = []
        continue
      }

      const selected: Address[] = []
      const candidateNets = candidateNetsByVault[vIdx] ?? []
      for (const net of candidateNets) {
        const hasValue = this.decodeStakeBySubnetworkHasValue(limitResults, limitOffset)
        limitOffset += SUBNETWORK_IDS.length
        if (hasValue) selected.push(net)
      }
      netsByVault[vIdx] = selected
    }

    // Pass 2: Determine which operators are opted into each vault.
    const opsByVault: Address[][] = new Array(vaultInfos.length)
    const optinCalls: any[] = []
    const optinVaultIndexes: number[] = []

    for (let vIdx = 0; vIdx < vaultInfos.length; vIdx++) {
      // No nets, no stakes, no point checking operators.
      if ((netsByVault[vIdx] ?? []).length === 0) {
        opsByVault[vIdx] = []
        continue
      }

      const v = vaultInfos[vIdx]!

      // Operator-specific delegators already constrain the operator set on-chain.
      const pinnedOp = this.pinnedOperator(v)
      if (pinnedOp) {
        opsByVault[vIdx] = [pinnedOp]
        continue
      }

      optinVaultIndexes.push(vIdx)
      for (const op of ops) {
        optinCalls.push({
          address: this.requireAddress('op_vault_opt_in'),
          abi: OperatorVaultOptInServiceAbi,
          functionName: 'isOptedIn',
          args: [op, v.vault],
        })
      }
    }

    const optins = await this.mc(optinCalls)
    let optinOffset = 0
    for (const vIdx of optinVaultIndexes) {
      const selected: Address[] = []
      for (let opIdx = 0; opIdx < ops.length; opIdx++) {
        if (optins[optinOffset++]) selected.push(ops[opIdx]!)
      }
      opsByVault[vIdx] = selected
    }

    // Pass 3: Stake lookups (net -> op -> subnetwork) for opted-in operators only.
    const stakeCalls: any[] = []
    for (let vIdx = 0; vIdx < vaultInfos.length; vIdx++) {
      const v = vaultInfos[vIdx]!
      if (v.delegator === ZERO_ADDRESS) continue

      const vaultNets = netsByVault[vIdx] ?? []
      const vaultOps = opsByVault[vIdx] ?? []
      for (const net of vaultNets) {
        const subnetworks = getSubnetworks(net)
        for (const op of vaultOps) {
          for (const subnetwork of subnetworks) {
            stakeCalls.push({
              address: v.delegator,
              abi: NetworkRestakeDelegatorAbi,
              functionName: 'stake',
              args: [subnetwork, op],
            })
          }
        }
      }
    }

    const stakes = (await this.mc(stakeCalls)) as bigint[]

    const out: Array<Array<{ net: Address; ops: Array<{ op: Address; stake: StakeBySubnetwork }> }>> =
      new Array(vaultInfos.length)

    let stakeOffset = 0
    for (let vIdx = 0; vIdx < vaultInfos.length; vIdx++) {
      const vaultNets = netsByVault[vIdx] ?? []
      const vaultOps = opsByVault[vIdx] ?? []

      const vaultOut = vaultNets.map((net) => ({
        net,
        ops: [] as Array<{ op: Address; stake: StakeBySubnetwork }>,
      }))

      for (let netIdx = 0; netIdx < vaultNets.length; netIdx++) {
        for (const op of vaultOps) {
          const { stake, hasValue, nextOffset } = this.decodeStakeBySubnetwork(stakes, stakeOffset)
          stakeOffset = nextOffset
          if (hasValue) vaultOut[netIdx]!.ops.push({ op, stake })
        }
      }

      out[vIdx] = vaultOut
    }

    return out
  }

  async getOpNetsVaults(op: Address): Promise<
    Array<{
      net: Address
      vaults: Array<VaultInfo & { limit: StakeBySubnetwork; stake: StakeBySubnetwork }>
    }>
  > {
    const nets = await this.getOpNets(op)
    const out = nets.map((n) => ({ net: n.net, vaults: [] as any[] }))
    if (nets.length === 0) return out

    // Pre-filter the vault universe to the operator's opted-in vaults (plus any pinned-to-operator vaults)
    // before doing per-network limit scans. This avoids scanning all vaults for each network.
    const allVaults = await this.getVaults()

    const genericVaults: VaultInfo[] = []
    for (const vault of allVaults) {
      if (vault.delegator === ZERO_ADDRESS) continue

      const pinnedOp = this.pinnedOperator(vault)
      if (pinnedOp && pinnedOp !== op) continue
      if (!pinnedOp) genericVaults.push(vault)
    }

    const optinCalls = genericVaults.map((vault) => ({
      address: this.requireAddress('op_vault_opt_in'),
      abi: OperatorVaultOptInServiceAbi,
      functionName: 'isOptedIn',
      args: [op, vault.vault],
    }))
    const optins = optinCalls.length ? await this.mc(optinCalls) : []

    const optedGenericVaults = new Set<Address>()
    for (let i = 0; i < genericVaults.length; i++) {
      if (optins[i]) optedGenericVaults.add(genericVaults[i]!.vault)
    }

    const vaultsForOp: VaultInfo[] = []
    for (const vault of allVaults) {
      if (vault.delegator === ZERO_ADDRESS) continue

      const pinnedOp = this.pinnedOperator(vault)
      if (pinnedOp && pinnedOp !== op) continue
      if (pinnedOp === op || optedGenericVaults.has(vault.vault)) vaultsForOp.push(vault)
    }

    // Pass 1: For each net, find vaults with non-zero limit (using the op-filtered vault set).
    const limitCalls: any[] = []
    const eligibleVaultsByNet: VaultInfo[][] = new Array(nets.length)

    for (let netIdx = 0; netIdx < nets.length; netIdx++) {
      const net = nets[netIdx]!.net
      const { calls, eligible } = this.buildLimitCallsForNet(net, vaultsForOp)
      eligibleVaultsByNet[netIdx] = eligible
      limitCalls.push(...calls)
    }

    const limitResults = (await this.mc(limitCalls)) as bigint[]
    const vaultsWithLimitByNet: Array<Array<VaultInfo & { limit: StakeBySubnetwork }>> = nets.map(
      () => [],
    )

    let limitOffset = 0
    for (let netIdx = 0; netIdx < nets.length; netIdx++) {
      const eligible = eligibleVaultsByNet[netIdx] ?? []
      for (const vault of eligible) {
        const { stake: limit, hasValue, nextOffset } = this.decodeStakeBySubnetwork(
          limitResults,
          limitOffset,
        )
        limitOffset = nextOffset
        if (hasValue) vaultsWithLimitByNet[netIdx]!.push({ ...vault, limit })
      }
    }

    // Pass 2: Stake lookups (net -> vault -> subnetwork) for vaults that have limits in that net.
    const stakeCalls: any[] = []
    const stakeVaultsByNet: Array<Array<VaultInfo & { limit: StakeBySubnetwork }>> = nets.map(
      () => [],
    )

    for (let netIdx = 0; netIdx < nets.length; netIdx++) {
      const net = nets[netIdx]!.net
      const subnetworks = this.subnetworksForNet(net)
      for (const vault of vaultsWithLimitByNet[netIdx] ?? []) {
        for (const subnetwork of subnetworks) {
          stakeCalls.push({
            address: vault.delegator,
            abi: NetworkRestakeDelegatorAbi,
            functionName: 'stake',
            args: [subnetwork, op],
          })
        }
        stakeVaultsByNet[netIdx]!.push(vault)
      }
    }

    const stakeResults = (await this.mc(stakeCalls)) as bigint[]
    let stakeOffset = 0

    for (let netIdx = 0; netIdx < nets.length; netIdx++) {
      const stakeVaults = stakeVaultsByNet[netIdx] ?? []
      for (const vault of stakeVaults) {
        const { stake, hasValue, nextOffset } = this.decodeStakeBySubnetwork(
          stakeResults,
          stakeOffset,
        )
        stakeOffset = nextOffset
        if (hasValue) out[netIdx]!.vaults.push({ ...vault, stake })
      }
    }

    return out
  }

  async isNet(address: Address): Promise<boolean> {
    return Boolean(
      await this.read<boolean>({
        abi: NetworkRegistryAbi,
        address: this.requireAddress('net_registry'),
        functionName: 'isEntity',
        args: [address],
      }),
    )
  }

  async isOp(address: Address): Promise<boolean> {
    return Boolean(
      await this.read<boolean>({
        abi: OperatorRegistryAbi,
        address: this.requireAddress('op_registry'),
        functionName: 'isEntity',
        args: [address],
      }),
    )
  }

  async isVault(address: Address): Promise<boolean> {
    return Boolean(
      await this.read<boolean>({
        abi: VaultFactoryAbi,
        address: this.requireAddress('vault_factory'),
        functionName: 'isEntity',
        args: [address],
      }),
    )
  }

  async isOptedInVault(operator: Address, vault: Address): Promise<boolean> {
    return Boolean(
      await this.read<boolean>({
        abi: OperatorVaultOptInServiceAbi,
        address: this.requireAddress('op_vault_opt_in'),
        functionName: 'isOptedIn',
        args: [operator, vault],
      }),
    )
  }

  async isOptedInNet(operator: Address, net: Address): Promise<boolean> {
    return Boolean(
      await this.read<boolean>({
        abi: OperatorNetworkOptInServiceAbi,
        address: this.requireAddress('op_net_opt_in'),
        functionName: 'isOptedIn',
        args: [operator, net],
      }),
    )
  }

  async getEntityType(entity: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: entity,
      functionName: 'TYPE',
    })
  }

  async getResolverSetEpochDelay(slasher: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VetoSlasherAbi,
      address: slasher,
      functionName: 'resolverSetEpochsDelay',
    })
  }

  async getResolver(slasher: Address, subnetwork: Hex): Promise<Address> {
    const resolver = await this.read<Address>({
      abi: VetoSlasherAbi,
      address: slasher,
      functionName: 'resolver',
      args: [subnetwork, '0x'],
    })
    return getAddress(resolver)
  }

  async getPendingResolver(slasher: Address, subnetwork: Hex): Promise<Address> {
    const MAX_UINT48 = (1n << 48n) - 1n
    const resolver = await this.read<Address>({
      abi: VetoSlasherAbi,
      address: slasher,
      functionName: 'resolverAt',
      args: [subnetwork, MAX_UINT48, '0x'],
    })
    return getAddress(resolver)
  }

  async getVaultEpochDuration(vault: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: vault,
      functionName: 'epochDuration',
    })
  }

  async getVaultCurrentEpoch(vault: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: vault,
      functionName: 'currentEpoch',
    })
  }

  async getVaultCurrentEpochStart(vault: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: vault,
      functionName: 'currentEpochStart',
    })
  }

  async getMaxNetworkLimit(delegator: Address, subnetwork: Hex): Promise<bigint> {
    return this.read<bigint>({
      abi: FullRestakeDelegatorAbi,
      address: delegator,
      functionName: 'maxNetworkLimit',
      args: [subnetwork],
    })
  }

  async getNetworkLimit(delegator: Address, subnetwork: Hex): Promise<bigint> {
    return this.read<bigint>({
      abi: FullRestakeDelegatorAbi,
      address: delegator,
      functionName: 'networkLimit',
      args: [subnetwork],
    })
  }

  async getOperatorNetworkLimit(
    delegator: Address,
    subnetwork: Hex,
    operator: Address,
  ): Promise<bigint> {
    return this.read<bigint>({
      abi: FullRestakeDelegatorAbi,
      address: delegator,
      functionName: 'operatorNetworkLimit',
      args: [subnetwork, operator],
    })
  }

  async getOperatorNetworkShares(
    delegator: Address,
    subnetwork: Hex,
    operator: Address,
  ): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: delegator,
      functionName: 'operatorNetworkShares',
      args: [subnetwork, operator],
    })
  }

  async getTotalOperatorNetworkShares(delegator: Address, subnetwork: Hex): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: delegator,
      functionName: 'totalOperatorNetworkShares',
      args: [subnetwork],
    })
  }

  async getStakeByDelegator(
    delegator: Address,
    subnetwork: Hex,
    operator: Address,
  ): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: delegator,
      functionName: 'stake',
      args: [subnetwork, operator],
    })
  }

  async getStake(vault: Address, subnetwork: Hex, operator: Address): Promise<bigint> {
    const delegator = await this.getVaultDelegator(vault)
    return this.getStakeByDelegator(delegator, subnetwork, operator)
  }

  async getAllowance(token: Address, owner: Address, spender: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultTokenizedAbi,
      address: token,
      functionName: 'allowance',
      args: [owner, spender],
    })
  }

  async getActiveBalance(vault: Address, account: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: vault,
      functionName: 'activeBalanceOf',
      args: [account],
    })
  }

  async getWithdrawals(vault: Address, epoch: bigint, account: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: vault,
      functionName: 'withdrawalsOf',
      args: [epoch, account],
    })
  }

  async getWithdrawalsClaimed(vault: Address, epoch: bigint, account: Address): Promise<boolean> {
    return Boolean(
      await this.read<boolean>({
      abi: VaultAbi,
      address: vault,
      functionName: 'isWithdrawalsClaimed',
      args: [epoch, account],
      }),
    )
  }

  async getOperatorNetworkOptInNonce(who: Address, where: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: OperatorNetworkOptInServiceAbi,
      address: this.requireAddress('op_net_opt_in'),
      functionName: 'nonces',
      args: [who, where],
    })
  }

  async getOperatorVaultOptInNonce(who: Address, where: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: OperatorVaultOptInServiceAbi,
      address: this.requireAddress('op_vault_opt_in'),
      functionName: 'nonces',
      args: [who, where],
    })
  }

  // Rewards (optional)
  async getCurator(vault: Address): Promise<Address> {
    const curator = await this.read<Address>({
      abi: CuratorRegistryAbi,
      address: this.requireAddress('curator_registry'),
      functionName: 'getCurator',
      args: [vault],
    })
    return getAddress(curator)
  }

  async getOperatorsFee(vault: Address, network: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: FeeRegistryAbi,
      address: this.requireAddress('fee_registry'),
      functionName: 'getOperatorsFee',
      args: [vault, network],
    })
  }

  async getCuratorFee(vault: Address, network: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: FeeRegistryAbi,
      address: this.requireAddress('fee_registry'),
      functionName: 'getCuratorFee',
      args: [vault, network],
    })
  }

  async protocolFee(rewardsType: bigint, network: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: ProtocolFeesAbi,
      address: this.requireAddress('rewards'),
      functionName: 'protocolFee',
      args: [rewardsType, network],
    })
  }

  async curatorFees(vault: Address, token: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultSnapshotRewardsAbi,
      address: this.requireAddress('rewards'),
      functionName: 'curatorFees',
      args: [vault, token],
    })
  }

  async lastUnclaimedReward(
    account: Address,
    vault: Address,
    network: Address,
    token: Address,
  ): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultSnapshotRewardsAbi,
      address: this.requireAddress('rewards'),
      functionName: 'lastUnclaimedReward',
      args: [account, vault, network, token],
    })
  }

  async lastUnclaimedOperatorReward(
    account: Address,
    vault: Address,
    network: Address,
    token: Address,
  ): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultSnapshotRewardsAbi,
      address: this.requireAddress('rewards'),
      functionName: 'lastUnclaimedOperatorReward',
      args: [account, vault, network, token],
    })
  }

  delegatorTypeName(type: bigint) {
    return DELEGATOR_TYPES_NAMES[Number(type)] ?? 'Unknown'
  }

  slasherTypeName(type: bigint) {
    return SLASHER_TYPES_NAMES[Number(type)] ?? 'Unknown'
  }
}
