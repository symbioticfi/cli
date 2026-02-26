import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { getAddress } from 'viem'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { CHAIN_CONFIGS } from '../src/config/chains'
import { resolveClientConfig } from '../src/core/client'

const ENV_KEYS = ['SYMB_RPC_URL', 'SYMB_ADDRESSES_JSON'] as const

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

  it('prefers --rpc over --provider over env', async () => {
    process.env.SYMB_RPC_URL = 'https://env.example'

    const a = await resolveClientConfig({ chain: 'mainnet' })
    expect(a.rpcUrls).toEqual(['https://env.example'])
    expect(a.rpcUrl).toBe('https://env.example')

    const b = await resolveClientConfig({ chain: 'mainnet', provider: 'https://provider.example' })
    expect(b.rpcUrls).toEqual(['https://provider.example'])
    expect(b.rpcUrl).toBe('https://provider.example')

    const c = await resolveClientConfig({
      chain: 'mainnet',
      provider: 'https://provider.example',
      rpc: 'https://rpc.example',
    })
    expect(c.rpcUrls).toEqual(['https://rpc.example'])
    expect(c.rpcUrl).toBe('https://rpc.example')
  })

  it('merges addresses override from env', async () => {
    const override = {
      curator_registry: '0x1111111111111111111111111111111111111111',
      fee_registry: '0x2222222222222222222222222222222222222222',
      rewards: '0x3333333333333333333333333333333333333333',
    }
    process.env.SYMB_ADDRESSES_JSON = JSON.stringify(override)

    const cfg = await resolveClientConfig({ chain: 'hoodi' })
    expect(cfg.addresses.op_registry).toBe(CHAIN_CONFIGS.hoodi.addresses.op_registry)
    expect(cfg.addresses.curator_registry).toBe(getAddress(override.curator_registry))
    expect(cfg.addresses.fee_registry).toBe(getAddress(override.fee_registry))
    expect(cfg.addresses.rewards).toBe(getAddress(override.rewards))
  })

  it('allows overrides to replace existing addresses', async () => {
    const override = {
      op_registry: '0x4444444444444444444444444444444444444444',
    }
    process.env.SYMB_ADDRESSES_JSON = JSON.stringify(override)

    const cfg = await resolveClientConfig({ chain: 'mainnet' })
    expect(cfg.addresses.op_registry).toBe(getAddress(override.op_registry))
    expect(cfg.addresses.net_registry).toBe(CHAIN_CONFIGS.mainnet.addresses.net_registry)
  })

  it('prefers addressesFile over SYMB_ADDRESSES_JSON', async () => {
    process.env.SYMB_ADDRESSES_JSON = JSON.stringify({
      op_registry: '0x5555555555555555555555555555555555555555',
    })

    const dir = await mkdtemp(join(tmpdir(), 'symb-cli-test-'))
    const filePath = join(dir, 'addresses.json')
    await writeFile(
      filePath,
      JSON.stringify({
        op_registry: '0x6666666666666666666666666666666666666666',
      }),
      'utf8',
    )

    const cfg = await resolveClientConfig({ chain: 'mainnet', addressesFile: filePath })
    expect(cfg.addresses.op_registry).toBe(getAddress('0x6666666666666666666666666666666666666666'))
  })

  it('throws on invalid address override', async () => {
    process.env.SYMB_ADDRESSES_JSON = JSON.stringify({ op_registry: 'not-an-address' })
    await expect(resolveClientConfig({ chain: 'mainnet' })).rejects.toThrow()
  })
})
