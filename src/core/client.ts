import { readFile } from 'node:fs/promises'

import { z } from 'zod'
import {
  createPublicClient,
  getAddress,
  http,
  type Chain,
  type PublicClient,
  type Transport,
} from 'viem'

import { readEnv } from '../config/env'
import { CHAIN_CONFIGS, resolveChainKey, type ChainAddresses, type ChainKey } from '../config/chains'

export type ResolvedClientConfig = {
  chainKey: ChainKey
  chainId: number
  viemChain: Chain
  rpcUrl: string
  addresses: ChainAddresses
  timeoutMs: number
  retries: number
}

export type ResolveClientConfigArgs = {
  chain: string
  rpc?: string
  provider?: string
  addressesFile?: string
  timeoutMs?: number
  retries?: number
}

const addressesSchema = z
  .object({
    op_registry: z.string(),
    net_registry: z.string(),
    op_vault_opt_in: z.string(),
    op_net_opt_in: z.string(),
    middleware_service: z.string(),
    vault_factory: z.string(),
  })
  .partial()

function normalizeAddresses(
  defaults: ChainAddresses,
  override: z.infer<typeof addressesSchema> | undefined,
): ChainAddresses {
  const merged = { ...defaults, ...(override ?? {}) }
  return {
    op_registry: getAddress(merged.op_registry),
    net_registry: getAddress(merged.net_registry),
    op_vault_opt_in: getAddress(merged.op_vault_opt_in),
    op_net_opt_in: getAddress(merged.op_net_opt_in),
    middleware_service: getAddress(merged.middleware_service),
    vault_factory: getAddress(merged.vault_factory),
  }
}

async function readAddressesOverrideFromFile(filePath: string) {
  const raw = await readFile(filePath, 'utf8')
  return addressesSchema.parse(JSON.parse(raw))
}

function readAddressesOverrideFromEnv(envValue: string) {
  return addressesSchema.parse(JSON.parse(envValue))
}

export async function resolveClientConfig(args: ResolveClientConfigArgs): Promise<ResolvedClientConfig> {
  const env = readEnv()

  const chainKey = resolveChainKey(args.chain)
  const base = CHAIN_CONFIGS[chainKey]

  const timeoutMs = args.timeoutMs ?? 60_000
  const retries = args.retries ?? 3

  const rpcUrl =
    args.rpc ??
    args.provider ??
    env.SYMB_RPC_URL ??
    base.defaultRpcUrl

  const override =
    args.addressesFile
      ? await readAddressesOverrideFromFile(args.addressesFile)
      : env.SYMB_ADDRESSES_JSON
        ? readAddressesOverrideFromEnv(env.SYMB_ADDRESSES_JSON)
        : undefined

  const addresses = normalizeAddresses(base.addresses, override)

  return {
    chainKey,
    chainId: base.chainId,
    viemChain: base.viemChain,
    rpcUrl,
    addresses,
    timeoutMs,
    retries,
  }
}

export function createSymbioticPublicClient(config: ResolvedClientConfig): PublicClient<Transport, Chain> {
  return createPublicClient({
    chain: config.viemChain,
    transport: http(config.rpcUrl, {
      timeout: config.timeoutMs,
      retryCount: config.retries,
    }),
  })
}

export async function assertChainId(client: PublicClient, expectedChainId: number) {
  const actual = await client.getChainId()
  if (actual !== expectedChainId) {
    throw new Error(`Mismatch between specified chain ID (${expectedChainId}) and provider's chain ID (${actual})`)
  }
}
