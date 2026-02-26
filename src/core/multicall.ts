import type { Abi, Chain, ContractFunctionParameters, PublicClient, Transport } from 'viem'

type MulticallContract = ContractFunctionParameters<Abi, 'view' | 'pure'>

// 2^14 - 1 bytes: conservative calldata chunk cap that tends to work across public RPCs.
const DEFAULT_MULTICALL_CALLDATA_BATCH_SIZE_BYTES = 16_383

export type MulticallChunkedOptions = {
  allowFailure?: boolean
  batchSize?: number
  concurrency?: number
}

async function mapWithConcurrency<T, U>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<U>,
): Promise<U[]> {
  const results: U[] = new Array(items.length)
  let nextIndex = 0

  const workerCount = Math.max(1, Math.min(concurrency, items.length))
  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (true) {
        const current = nextIndex++
        if (current >= items.length) break
        const item = items[current]!
        results[current] = await fn(item, current)
      }
    }),
  )

  return results
}

export async function multicallChunked(
  client: PublicClient<Transport, Chain>,
  contracts: readonly MulticallContract[],
  opts: MulticallChunkedOptions = {},
): Promise<any[]> {
  const allowFailure = opts.allowFailure ?? false
  const batchSize = opts.batchSize ?? 500
  const concurrency = opts.concurrency ?? 4

  if (contracts.length === 0) return []

  const out: any[] = new Array(contracts.length)
  const chunkCount = Math.ceil(contracts.length / batchSize)
  const chunkIndexes = Array.from({ length: chunkCount }, (_, i) => i)

  await mapWithConcurrency(chunkIndexes, concurrency, async (chunkIndex) => {
    const start = chunkIndex * batchSize
    const end = Math.min(start + batchSize, contracts.length)
    const chunk = contracts.slice(start, end)

    const results = await client.multicall({
      contracts: chunk,
      allowFailure,
      batchSize: DEFAULT_MULTICALL_CALLDATA_BATCH_SIZE_BYTES,
    })

    for (let i = 0; i < results.length; i++) {
      out[start + i] = results[i]
    }
  })

  return out
}
