import type { Abi, Chain, ContractFunctionParameters, PublicClient, Transport } from 'viem'

type MulticallContract = ContractFunctionParameters<Abi, 'view' | 'pure'>

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

  const chunks: MulticallContract[][] = []
  for (let i = 0; i < contracts.length; i += batchSize) {
    chunks.push(contracts.slice(i, i + batchSize))
  }

  const chunkResults = await mapWithConcurrency(chunks, concurrency, async (chunk) => {
    return client.multicall({
      contracts: chunk,
      allowFailure,
    })
  })

  return chunkResults.flat() as any[]
}
