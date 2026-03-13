import { describe, expect, it } from 'vitest'

import { multicallChunked } from '../src/core/multicall'

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

describe('multicallChunked', () => {
  it('returns empty array for empty input', async () => {
    let calls = 0
    const client = {
      multicall: async () => {
        calls++
        return []
      },
    } as any

    const res = await multicallChunked(client, [], { batchSize: 10 })
    expect(res).toEqual([])
    expect(calls).toBe(0)
  })

  it('preserves ordering across chunks even when requests resolve out-of-order', async () => {
    const batchSize = 500
    const total = 1_200
    const contracts = Array.from({ length: total }, (_, id) => ({ id })) as any[]

    let calls = 0
    const client = {
      multicall: async (args: { contracts: any[]; batchSize?: number }) => {
        calls++
        // Ensure we always pass the conservative calldata cap through.
        expect(args.batchSize).toBe(16_383)

        const firstId = args.contracts[0]?.id as number
        const chunkIndex = Math.floor(firstId / batchSize)
        // Delay later chunks less to force out-of-order completion.
        await sleep((3 - chunkIndex) * 2)
        return args.contracts.map((c) => c.id)
      },
    } as any

    const res = await multicallChunked(client, contracts, { batchSize, concurrency: 2 })
    expect(res).toHaveLength(total)
    for (let i = 0; i < total; i++) expect(res[i]).toBe(i)
    expect(calls).toBe(Math.ceil(total / batchSize))
  })
})
