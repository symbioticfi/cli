import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { CHAIN_CONFIGS } from '../src/config/chains'
import { resolveClientConfig } from '../src/core/client'

const ENV_KEYS = ['SYMB_RPC_URL'] as const

describe('resolveClientConfig', () => {
  const oldEnv: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> = {}

  beforeEach(() => {
    for (const k of ENV_KEYS) {
      oldEnv[k] = process.env[k]
      delete process.env[k]
    }
  })

  afterEach(() => {
    for (const k of ENV_KEYS) {
      const v = oldEnv[k]
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  })

  it('uses chain default RPC URLs when no override', async () => {
    const cfg = await resolveClientConfig({ chain: 'mainnet' })
    expect(cfg.rpcUrls).toEqual(CHAIN_CONFIGS.mainnet.defaultRpcUrls)
    expect(cfg.rpcUrl).toBe(CHAIN_CONFIGS.mainnet.defaultRpcUrls[0])
  })

  it('prefers --rpc over env', async () => {
    process.env.SYMB_RPC_URL = 'https://env.example'

    const a = await resolveClientConfig({ chain: 'mainnet' })
    expect(a.rpcUrls).toEqual(['https://env.example'])
    expect(a.rpcUrl).toBe('https://env.example')

    const b = await resolveClientConfig({ chain: 'mainnet', rpc: 'https://rpc.example' })
    expect(b.rpcUrls).toEqual(['https://rpc.example'])
    expect(b.rpcUrl).toBe('https://rpc.example')
  })

  it('uses chain default addresses', async () => {
    const cfg = await resolveClientConfig({ chain: 'mainnet' })
    expect(cfg.addresses).toEqual(CHAIN_CONFIGS.mainnet.addresses)
  })
})
