import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress } from '../cli/parse'
import { runCliAction } from '../cli/run'
import { printIndented, printJson, printLine } from '../core/output'
import { formatTokenAmount } from '../core/units'

function groupByCollateral<T extends { collateral: string }>(items: T[]) {
  const out = new Map<string, T[]>()
  for (const item of items) {
    const list = out.get(item.collateral) ?? []
    list.push(item)
    out.set(item.collateral, list)
  }
  return out
}

export function registerNetworkReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('isnet')
    .description('Check if address is network.')
    .argument('<address>', 'an address to check')
    .action((address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const isNet = await ctx.symb.isNet(parseAddress(address))
        if (ctx.json) return printJson({ isNet })
        printLine(String(isNet))
      }),
    )

  program
    .command('middleware')
    .description('Get network middleware address.')
    .argument('<network_address>', 'an address of the network to get a middleware for')
    .action((networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const middleware = await ctx.symb.getMiddleware(parseAddress(networkAddress))
        if (ctx.json) return printJson({ middleware })
        printLine(middleware)
      }),
    )

  program
    .command('nets')
    .description('List all networks.')
    .option('--full', 'Show full data', false)
    .action((opts: { full?: boolean }) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const nets = await ctx.symb.getNets()

        if (ctx.json) {
          if (!opts.full) return printJson({ nets })

          const full = []
          for (const net of nets) {
            const opVaults = await ctx.symb.getNetOpsVaults(net.net)
            const vaultSet = new Set(opVaults.flatMap((op) => op.vaults.map((v) => v.vault)))
            full.push({ ...net, ops: opVaults.length, vaults: vaultSet.size })
          }
          return printJson({ nets: full })
        }

        printLine(`All networks [${nets.length} total]:`)

        let fullData: Array<{ ops: number; vaults: number }> | undefined
        if (opts.full) {
          fullData = []
          for (const net of nets) {
            const opVaults = await ctx.symb.getNetOpsVaults(net.net)
            const vaultSet = new Set(opVaults.flatMap((op) => op.vaults.map((v) => v.vault)))
            fullData.push({ ops: opVaults.length, vaults: vaultSet.size })
          }
        }

        for (let i = 0; i < nets.length; i++) {
          const net = nets[i]!
          printIndented(`Network: ${net.net}`, 2)
          printIndented(`Middleware: ${net.middleware}`, 4)
          if (opts.full) {
            const f = fullData?.[i]
            printIndented(`Operators: ${f?.ops ?? 0} total`, 4)
            printIndented(`Vaults: ${f?.vaults ?? 0} total`, 4)
          }
          printLine('')
        }
      }),
    )

  program
    .command('netops')
    .description('List all operators opted in network.')
    .argument('<network_address>', 'an address of the network to get operators for')
    .action((networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const net = parseAddress(networkAddress)
        const ops = await ctx.symb.getNetOps(net)

        if (ctx.json) return printJson({ network: net, operators: ops })

        printLine(`Network: ${net}`)
        printLine(`Operators [${ops.length} total]:`)
        for (const op of ops) printIndented(`Operator: ${op}`, 2)
      }),
    )

  program
    .command('netstakes')
    .description('Show stakes of all operators in network.')
    .argument('<network_address>', 'an address of the network to get a whole stake data for')
    .action((networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const net = parseAddress(networkAddress)

        const middleware = await ctx.symb.getMiddleware(net)
        const opsVaults = await ctx.symb.getNetOpsVaults(net)

        if (ctx.json) return printJson({ network: net, middleware, operators: opsVaults })

        printLine(`Network: ${net}`)
        printLine(`Middleware: ${middleware}`)
        printLine(`Operators [${opsVaults.length} total]:`)

        const totalStakes = new Map<string, bigint>()

        for (const op of opsVaults) {
          printIndented(`Operator: ${op.op}`, 2)

          const byCollateral = groupByCollateral(op.vaults)
          let totalOpStakeStr = ''

          for (const [collateral, vaults] of byCollateral.entries()) {
            const tokenMeta = await ctx.symb.getTokenMeta(parseAddress(collateral))
            printIndented(`Collateral: ${collateral} (${tokenMeta.symbol})`, 4)

            let stakesSum = 0n
            for (const vault of vaults) {
              printIndented(`Vault: ${vault.vault}`, 6)
              printIndented(
                `Type: ${ctx.symb.delegatorTypeName(vault.delegatorType)} / ${ctx.symb.slasherTypeName(vault.slasherType)}`,
                8,
              )
              const stake = Object.values(vault.stake).reduce((a, b) => a + b, 0n)
              printIndented(`Stake: ${formatTokenAmount(stake, tokenMeta)}`, 8)
              stakesSum += stake
            }

            totalOpStakeStr += `${formatTokenAmount(stakesSum, tokenMeta)} ${tokenMeta.symbol} + `
            totalStakes.set(collateral, (totalStakes.get(collateral) ?? 0n) + stakesSum)
          }

          if (totalOpStakeStr) {
            printIndented(`Total stake: ${totalOpStakeStr.slice(0, -3)}`, 4)
          } else {
            printIndented('Total stake: 0', 4)
          }
          printLine('')
        }

        printLine('Total stakes:')
        for (const [collateral, stake] of totalStakes.entries()) {
          const meta = await ctx.symb.getTokenMeta(parseAddress(collateral))
          printIndented(`Collateral ${collateral} (${meta.symbol}): ${formatTokenAmount(stake, meta)}`, 2)
        }
      }),
    )
}

