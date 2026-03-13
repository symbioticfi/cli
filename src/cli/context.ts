import type { Command } from 'commander'

import { assertChainId, createSymbioticPublicClient, resolveClientConfig } from '../core/client'
import { SymbioticClient } from '../core/symbiotic'
import type { ResolvedClientConfig } from '../core/client'
import type { Chain, PublicClient, Transport } from 'viem'

export type GlobalOptions = {
  chain: string
  rpc?: string
  json?: boolean
  quiet?: boolean
  batchSize?: number
  concurrency?: number
  timeoutMs?: number
  retries?: number
}

export type CliContext = {
  resolved: ResolvedClientConfig
  publicClient: PublicClient<Transport, Chain>
  symb: SymbioticClient
  json: boolean
  quiet: boolean
}

export function createContextGetter(program: Command) {
  let ctxPromise: Promise<CliContext> | undefined

  return async function getCtx(): Promise<CliContext> {
    if (ctxPromise) return ctxPromise

    ctxPromise = (async () => {
      const opts = program.opts<GlobalOptions>()
      const resolved = await resolveClientConfig({
        chain: opts.chain,
        rpc: opts.rpc,
        timeoutMs: opts.timeoutMs,
        retries: opts.retries,
      })

      const publicClient = createSymbioticPublicClient(resolved)
      await assertChainId(publicClient, resolved.chainId)

      const symb = new SymbioticClient({
        chainKey: resolved.chainKey,
        chainId: resolved.chainId,
        addresses: resolved.addresses,
        publicClient,
        multicallBatchSize: opts.batchSize,
        multicallConcurrency: opts.concurrency,
      })

      return {
        resolved,
        publicClient,
        symb,
        json: Boolean(opts.json),
        quiet: Boolean(opts.quiet),
      }
    })()

    return ctxPromise
  }
}
