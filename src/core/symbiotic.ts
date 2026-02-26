import { getAddress, type Address, type Hex } from 'viem'
import type { Chain, PublicClient, Transport } from 'viem'

import type { ChainAddresses, ChainAddressKey, ChainKey } from '../config/chains'
import { DELEGATOR_TYPES_NAMES, SLASHER_TYPES_NAMES, SUBNETWORK_IDS, ZERO_ADDRESS } from './constants'
import {
  CuratorRegistryAbi,
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
        `${name} address is not configured for chain ${this.chainKey}. Provide it via --addresses-file or SYMB_ADDRESSES_JSON.`,
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
    const network = getAddress(net)
    return SUBNETWORK_IDS.map((subnetId) => encodeSubnetwork({ net: network, subnetId }))
  }

  private decodeStakeBySubnetwork(values: readonly bigint[], offset: number): {
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
      symbol && Number.isFinite(decimals)
        ? { symbol, decimals: decimals! }
        : tokenMetaFallback()

    this.tokenMetaCache.set(t, meta)
    return meta
  }

  async getMiddleware(net: Address): Promise<Address> {
    const middleware = await this.read<Address>({
      abi: NetworkMiddlewareServiceAbi,
      address: this.requireAddress('middleware_service'),
      functionName: 'middleware',
      args: [getAddress(net)],
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
    const middlewares = middlewareResults.map((middleware: any) => getAddress(middleware as Address))

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
    const op = getAddress(operator)
    const nets = await this.getNets()

    const optinCalls = nets.map((net) => ({
      address: this.requireAddress('op_net_opt_in'),
      abi: OperatorNetworkOptInServiceAbi,
      functionName: 'isOptedIn',
      args: [op, net.net],
    }))
    const optins = await this.mc(optinCalls)
    return nets.filter((net, i) => Boolean(optins[i]))
  }

  async getNetOps(net: Address): Promise<Address[]> {
    const network = getAddress(net)
    const ops = await this.getOps()

    const calls = ops.map((op) => ({
      address: this.requireAddress('op_net_opt_in'),
      abi: OperatorNetworkOptInServiceAbi,
      functionName: 'isOptedIn',
      args: [op, network],
    }))
    const optins = await this.mc(calls)
    return ops.filter((op, i) => Boolean(optins[i]))
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
        typeCalls.push({ address: v.delegator, abi: NetworkRestakeDelegatorAbi, functionName: 'TYPE' })
        assignments.push({ idx, role: 'delegatorType' })
      }
      if (v.slasher !== ZERO_ADDRESS) {
        typeCalls.push({ address: v.slasher, abi: NetworkRestakeDelegatorAbi, functionName: 'TYPE' })
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
        enrichCalls.push({ address: v.delegator, abi: NetworkRestakeDelegatorAbi, functionName: 'operator' })
        enrichAssign.push({ idx, role: 'delegatorOperator' })
      }
      if (v.delegatorType === 3n) {
        enrichCalls.push({ address: v.delegator, abi: NetworkRestakeDelegatorAbi, functionName: 'network' })
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
      address: getAddress(vault),
      functionName: 'delegator',
    })
    return getAddress(delegator)
  }

  async getVaultCollateral(vault: Address): Promise<Address> {
    const collateral = await this.read<Address>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'collateral',
    })
    return getAddress(collateral)
  }

  async getVaultSlasher(vault: Address): Promise<Address> {
    const slasher = await this.read<Address>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'slasher',
    })
    return getAddress(slasher)
  }

  async getNetVaults(net: Address): Promise<(VaultInfo & { limit: StakeBySubnetwork })[]> {
    const network = getAddress(net)
    const vaults = await this.getVaults()
    const eligible = vaults.filter((v) => {
      if (v.delegator === ZERO_ADDRESS) return false
      if (v.delegatorType === 3n && v.delegatorNetwork && v.delegatorNetwork !== network) return false
      return true
    })

    const limitCalls: any[] = []
    const subnetworks = this.subnetworksForNet(network)
    for (const vault of eligible) {
      const functionName = vault.delegatorType === 3n ? 'maxNetworkLimit' : 'networkLimit'
      for (const subnetwork of subnetworks) {
        limitCalls.push({
          address: vault.delegator,
          abi: FullRestakeDelegatorAbi,
          functionName,
          args: [subnetwork],
        })
      }
    }

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

  async getNetOpsVaults(net: Address): Promise<Array<{ op: Address; vaults: Array<VaultInfo & { limit: StakeBySubnetwork; stake: StakeBySubnetwork }> }>> {
    const network = getAddress(net)
    const vaults = await this.getNetVaults(network)
    const ops = await this.getNetOps(network)

    const stakeCalls: any[] = []
    const subnetworks = this.subnetworksForNet(network)
    for (const op of ops) {
      for (const vault of vaults) {
        for (const subnetwork of subnetworks) {
          stakeCalls.push({
            address: vault.delegator,
            abi: NetworkRestakeDelegatorAbi,
            functionName: 'stake',
            args: [subnetwork, op],
          })
        }
      }
    }

    const stakes = (await this.mc(stakeCalls)) as bigint[]
    const results = ops.map((op) => ({ op, vaults: [] as any[] }))

    let i = 0
    for (let opIdx = 0; opIdx < ops.length; opIdx++) {
      for (const vault of vaults) {
        const { stake, hasValue, nextOffset } = this.decodeStakeBySubnetwork(stakes, i)
        i = nextOffset
        if (hasValue) results[opIdx]!.vaults.push({ ...vault, stake })
      }
    }

    return results
  }

  async getVaultOps(vault: Address): Promise<Address[]> {
    const v = getAddress(vault)
    const ops = await this.getOps()

    const calls = ops.map((op) => ({
      address: this.requireAddress('op_vault_opt_in'),
      abi: OperatorVaultOptInServiceAbi,
      functionName: 'isOptedIn',
      args: [op, v],
    }))
    const optins = await this.mc(calls)
    return ops.filter((op, i) => Boolean(optins[i]))
  }

  async getVaultNetsByDelegator(delegator: Address): Promise<Array<{ net: Address; limit: StakeBySubnetwork }>> {
    const nets = await this.getNets()
    const d = getAddress(delegator)

    const calls: any[] = []
    for (const net of nets) {
      const subnetworks = this.subnetworksForNet(net.net)
      for (const subnetwork of subnetworks) {
        calls.push({
          address: d,
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
    const v = getAddress(vault)
    const delegator = await this.getVaultDelegator(v)
    return this.getVaultNetsByDelegator(delegator)
  }

  async getVaultNetsOps(vault: Address): Promise<Record<Address, Address[]>> {
    const v = getAddress(vault)
    const vaultOps = await this.getVaultOps(v)
    const vaultNets = await this.getVaultNets(v)

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

  async getVaultNetsOpsFull(vaultInfo: VaultInfo): Promise<Array<{ net: Address; ops: Array<{ op: Address; stake: StakeBySubnetwork }> }>> {
    const nets = await this.getVaultNetsByDelegator(vaultInfo.delegator)
    const ops = await this.getVaultOps(vaultInfo.vault)

    const calls: any[] = []
    for (const net of nets) {
      const subnetworks = this.subnetworksForNet(net.net)
      for (const op of ops) {
        for (const subnetwork of subnetworks) {
          calls.push({
            address: vaultInfo.delegator,
            abi: NetworkRestakeDelegatorAbi,
            functionName: 'stake',
            args: [subnetwork, op],
          })
        }
      }
    }

    const stakes = (await this.mc(calls)) as bigint[]
    const out = nets.map((n) => ({ net: n.net, ops: [] as Array<{ op: Address; stake: StakeBySubnetwork }> }))

    let i = 0
    for (let netIdx = 0; netIdx < nets.length; netIdx++) {
      for (const op of ops) {
        const { stake, hasValue, nextOffset } = this.decodeStakeBySubnetwork(stakes, i)
        i = nextOffset
        if (hasValue) out[netIdx]!.ops.push({ op, stake })
      }
    }

    return out
  }

  async getOpNetsVaults(op: Address): Promise<Array<{ net: Address; vaults: Array<VaultInfo & { limit: StakeBySubnetwork; stake: StakeBySubnetwork }> }>> {
    const operator = getAddress(op)
    const nets = await this.getOpNets(operator)

    // Avoid re-fetching vault list per-network by letting getNetVaults use the cached vault list.
    const netVaults = new Map<Address, Awaited<ReturnType<SymbioticClient['getNetVaults']>>>()
    const stakeCalls: any[] = []

    for (const net of nets) {
      const vaults = await this.getNetVaults(net.net)
      netVaults.set(net.net, vaults)
      const subnetworks = this.subnetworksForNet(net.net)
      for (const vault of vaults) {
        for (const subnetwork of subnetworks) {
          stakeCalls.push({
            address: vault.delegator,
            abi: NetworkRestakeDelegatorAbi,
            functionName: 'stake',
            args: [subnetwork, operator],
          })
        }
      }
    }

    const stakes = (await this.mc(stakeCalls)) as bigint[]
    const out = nets.map((n) => ({ net: n.net, vaults: [] as any[] }))

    let i = 0
    for (let netIdx = 0; netIdx < nets.length; netIdx++) {
      const netAddr = nets[netIdx]!.net
      const vaults = netVaults.get(netAddr) ?? []
      for (const vault of vaults) {
        const { stake, hasValue, nextOffset } = this.decodeStakeBySubnetwork(stakes, i)
        i = nextOffset
        if (hasValue) out[netIdx]!.vaults.push({ ...vault, stake })
      }
    }

    return out
  }

  async isNet(address: Address): Promise<boolean> {
    const isNet = await this.read<boolean>({
      abi: NetworkRegistryAbi,
      address: this.requireAddress('net_registry'),
      functionName: 'isEntity',
      args: [getAddress(address)],
    })
    return Boolean(isNet)
  }

  async isOp(address: Address): Promise<boolean> {
    const isOp = await this.read<boolean>({
      abi: OperatorRegistryAbi,
      address: this.requireAddress('op_registry'),
      functionName: 'isEntity',
      args: [getAddress(address)],
    })
    return Boolean(isOp)
  }

  async isVault(address: Address): Promise<boolean> {
    const isVault = await this.read<boolean>({
      abi: VaultFactoryAbi,
      address: this.requireAddress('vault_factory'),
      functionName: 'isEntity',
      args: [getAddress(address)],
    })
    return Boolean(isVault)
  }

  async isOptedInVault(operator: Address, vault: Address): Promise<boolean> {
    const res = await this.read<boolean>({
      abi: OperatorVaultOptInServiceAbi,
      address: this.requireAddress('op_vault_opt_in'),
      functionName: 'isOptedIn',
      args: [getAddress(operator), getAddress(vault)],
    })
    return Boolean(res)
  }

  async isOptedInNet(operator: Address, net: Address): Promise<boolean> {
    const res = await this.read<boolean>({
      abi: OperatorNetworkOptInServiceAbi,
      address: this.requireAddress('op_net_opt_in'),
      functionName: 'isOptedIn',
      args: [getAddress(operator), getAddress(net)],
    })
    return Boolean(res)
  }

  async getEntityType(entity: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: getAddress(entity),
      functionName: 'TYPE',
    })
  }

  async getResolverSetEpochDelay(slasher: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VetoSlasherAbi,
      address: getAddress(slasher),
      functionName: 'resolverSetEpochsDelay',
    })
  }

  async getResolver(slasher: Address, subnetwork: Hex): Promise<Address> {
    const resolver = await this.read<Address>({
      abi: VetoSlasherAbi,
      address: getAddress(slasher),
      functionName: 'resolver',
      args: [subnetwork, '0x'],
    })
    return getAddress(resolver)
  }

  async getPendingResolver(slasher: Address, subnetwork: Hex): Promise<Address> {
    const MAX_UINT48 = (1n << 48n) - 1n
    const resolver = await this.read<Address>({
      abi: VetoSlasherAbi,
      address: getAddress(slasher),
      functionName: 'resolverAt',
      args: [subnetwork, MAX_UINT48, '0x'],
    })
    return getAddress(resolver)
  }

  async getVaultEpochDuration(vault: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'epochDuration',
    })
  }

  async getVaultCurrentEpoch(vault: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'currentEpoch',
    })
  }

  async getVaultCurrentEpochStart(vault: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'currentEpochStart',
    })
  }

  async getMaxNetworkLimit(delegator: Address, subnetwork: Hex): Promise<bigint> {
    return this.read<bigint>({
      abi: FullRestakeDelegatorAbi,
      address: getAddress(delegator),
      functionName: 'maxNetworkLimit',
      args: [subnetwork],
    })
  }

  async getNetworkLimit(delegator: Address, subnetwork: Hex): Promise<bigint> {
    return this.read<bigint>({
      abi: FullRestakeDelegatorAbi,
      address: getAddress(delegator),
      functionName: 'networkLimit',
      args: [subnetwork],
    })
  }

  async getOperatorNetworkLimit(delegator: Address, subnetwork: Hex, operator: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: FullRestakeDelegatorAbi,
      address: getAddress(delegator),
      functionName: 'operatorNetworkLimit',
      args: [subnetwork, getAddress(operator)],
    })
  }

  async getOperatorNetworkShares(delegator: Address, subnetwork: Hex, operator: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: getAddress(delegator),
      functionName: 'operatorNetworkShares',
      args: [subnetwork, getAddress(operator)],
    })
  }

  async getTotalOperatorNetworkShares(delegator: Address, subnetwork: Hex): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: getAddress(delegator),
      functionName: 'totalOperatorNetworkShares',
      args: [subnetwork],
    })
  }

  async getStakeByDelegator(delegator: Address, subnetwork: Hex, operator: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: NetworkRestakeDelegatorAbi,
      address: getAddress(delegator),
      functionName: 'stake',
      args: [subnetwork, getAddress(operator)],
    })
  }

  async getStake(vault: Address, subnetwork: Hex, operator: Address): Promise<bigint> {
    const delegator = await this.getVaultDelegator(vault)
    return this.getStakeByDelegator(delegator, subnetwork, operator)
  }

  async getAllowance(token: Address, owner: Address, spender: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultTokenizedAbi,
      address: getAddress(token),
      functionName: 'allowance',
      args: [getAddress(owner), getAddress(spender)],
    })
  }

  async getActiveBalance(vault: Address, account: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'activeBalanceOf',
      args: [getAddress(account)],
    })
  }

  async getWithdrawals(vault: Address, epoch: bigint, account: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'withdrawalsOf',
      args: [epoch, getAddress(account)],
    })
  }

  async getWithdrawalsClaimed(vault: Address, epoch: bigint, account: Address): Promise<boolean> {
    const res = await this.read<boolean>({
      abi: VaultAbi,
      address: getAddress(vault),
      functionName: 'isWithdrawalsClaimed',
      args: [epoch, getAddress(account)],
    })
    return Boolean(res)
  }

  async getOperatorNetworkOptInNonce(who: Address, where: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: OperatorNetworkOptInServiceAbi,
      address: this.requireAddress('op_net_opt_in'),
      functionName: 'nonces',
      args: [getAddress(who), getAddress(where)],
    })
  }

  async getOperatorVaultOptInNonce(who: Address, where: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: OperatorVaultOptInServiceAbi,
      address: this.requireAddress('op_vault_opt_in'),
      functionName: 'nonces',
      args: [getAddress(who), getAddress(where)],
    })
  }

  // RewardsV2 (optional)
  async getCurator(vault: Address): Promise<Address> {
    const curator = await this.read<Address>({
      abi: CuratorRegistryAbi,
      address: this.requireAddress('curator_registry'),
      functionName: 'getCurator',
      args: [getAddress(vault)],
    })
    return getAddress(curator)
  }

  async getOperatorsFee(vault: Address, network: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: FeeRegistryAbi,
      address: this.requireAddress('fee_registry'),
      functionName: 'getOperatorsFee',
      args: [getAddress(vault), getAddress(network)],
    })
  }

  async getCuratorFee(vault: Address, network: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: FeeRegistryAbi,
      address: this.requireAddress('fee_registry'),
      functionName: 'getCuratorFee',
      args: [getAddress(vault), getAddress(network)],
    })
  }

  async protocolFee(rewardsType: bigint, network: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: ProtocolFeesAbi,
      address: this.requireAddress('rewards'),
      functionName: 'protocolFee',
      args: [rewardsType, getAddress(network)],
    })
  }

  async curatorFees(vault: Address, token: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultSnapshotRewardsAbi,
      address: this.requireAddress('rewards'),
      functionName: 'curatorFees',
      args: [getAddress(vault), getAddress(token)],
    })
  }

  async lastUnclaimedReward(account: Address, vault: Address, network: Address, token: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultSnapshotRewardsAbi,
      address: this.requireAddress('rewards'),
      functionName: 'lastUnclaimedReward',
      args: [getAddress(account), getAddress(vault), getAddress(network), getAddress(token)],
    })
  }

  async lastUnclaimedOperatorReward(account: Address, vault: Address, network: Address, token: Address): Promise<bigint> {
    return this.read<bigint>({
      abi: VaultSnapshotRewardsAbi,
      address: this.requireAddress('rewards'),
      functionName: 'lastUnclaimedOperatorReward',
      args: [getAddress(account), getAddress(vault), getAddress(network), getAddress(token)],
    })
  }

  delegatorTypeName(type: bigint) {
    return DELEGATOR_TYPES_NAMES[Number(type)] ?? 'Unknown'
  }

  slasherTypeName(type: bigint) {
    return SLASHER_TYPES_NAMES[Number(type)] ?? 'Unknown'
  }
}
