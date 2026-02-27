import {
  createPublicClient,
  fallback,
  http,
  type Chain,
  type PublicClient,
  type Transport,
} from 'viem'

import { readEnv } from '../config/env'
import {
  CHAIN_CONFIGS,
  resolveChainKey,
  type ChainAddresses,
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
  timeoutMs?: number
  retries?: number
}

export async function resolveClientConfig(args: ResolveClientConfigArgs): Promise<ResolvedClientConfig> {
  const env = readEnv()

  const chainKey = resolveChainKey(args.chain)
  const base = CHAIN_CONFIGS[chainKey]

  const timeoutMs = args.timeoutMs ?? 60_000
  const retries = args.retries ?? 3

  const rpcUrl = args.rpc ?? env.SYMB_RPC_URL
  const rpcUrls = rpcUrl ? [rpcUrl] : base.defaultRpcUrls

  const addresses: ChainAddresses = base.addresses

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
