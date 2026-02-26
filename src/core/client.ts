import { readFile } from 'node:fs/promises'

import { z } from 'zod'
import {
  createPublicClient,
  fallback,
  getAddress,
  http,
  type Address,
  type Chain,
  type PublicClient,
  type Transport,
} from 'viem'

import { readEnv } from '../config/env'
import {
  ALL_ADDRESS_KEYS,
  CHAIN_CONFIGS,
  CORE_ADDRESS_KEYS,
  resolveChainKey,
  type ChainAddresses,
  type ChainAddressKey,
  type ChainKey,
} from '../config/chains'

export type ResolvedClientConfig = {
  chainKey: ChainKey
  chainId: number
  viemChain: Chain
  rpcUrl: string
  rpcUrls: readonly string[]
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

type AddressesOverride = Partial<Record<ChainAddressKey, string>>

const addressesSchema: z.ZodType<AddressesOverride> = z.object(
  Object.fromEntries(ALL_ADDRESS_KEYS.map((k) => [k, z.string().optional()])) as z.ZodRawShape,
)

function normalizeAddresses(
  defaults: ChainAddresses,
  override: z.infer<typeof addressesSchema> | undefined,
): ChainAddresses {
  const merged = { ...defaults, ...(override ?? {}) } as Partial<Record<ChainAddressKey, string | Address>>

  const out: Partial<Record<ChainAddressKey, Address>> = {}
  for (const key of ALL_ADDRESS_KEYS) {
    const v = merged[key]
    if (v === undefined) continue
    out[key] = getAddress(v)
  }

  // Ensure required (core) addresses always exist.
  for (const key of CORE_ADDRESS_KEYS) {
    if (!out[key]) {
      throw new Error(`Missing required address: ${key}`)
    }
  }

  return out as ChainAddresses
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

  const rpcUrl = args.rpc ?? args.provider ?? env.SYMB_RPC_URL
  const rpcUrls = rpcUrl ? [rpcUrl] : base.defaultRpcUrls

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
    rpcUrl: rpcUrls[0]!,
    rpcUrls,
    addresses,
    timeoutMs,
    retries,
  }
}

export function createSymbioticPublicClient(config: ResolvedClientConfig): PublicClient<Transport, Chain> {
  return createPublicClient({
    chain: config.viemChain,
    transport: createViemTransport(config),
  })
}

export function createViemTransport(config: ResolvedClientConfig): Transport {
  const urls = [...config.rpcUrls]
  if (urls.length === 1) {
    return http(urls[0]!, {
      timeout: config.timeoutMs,
      retryCount: config.retries,
    })
  }

  return fallback(
    urls.map((url, i) =>
      http(url, {
        // Inner HTTP transport retries are disabled by `fallback` (retryCount: 0).
        timeout: config.timeoutMs,
        key: `http-${i}`,
        name: `HTTP ${i}`,
      }),
    ),
    {
      retryCount: config.retries,
    },
  )
}

export async function assertChainId(client: PublicClient, expectedChainId: number) {
  const actual = await client.getChainId()
  if (actual !== expectedChainId) {
    throw new Error(`Mismatch between specified chain ID (${expectedChainId}) and provider's chain ID (${actual})`)
  }
}
