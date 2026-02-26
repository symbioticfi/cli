import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg } from '../cli/argParsers'
import { runCliAction } from '../cli/run'
import { SUBNETWORK_IDS } from '../core/constants'
import { groupBy } from '../core/format'
import { printIndented, printJson, printLine } from '../core/output'
import { startSpinner } from '../core/spinner'
import { encodeSubnetwork } from '../core/subnetwork'
import { formatTokenAmount } from '../core/units'

export function registerNetworkReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('is')
    .description('Get whether address is a network.')
    .argument('<address>', 'an address to check', parseAddressArg)
    .action((address: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const isNet = await ctx.symb.isNet(address)
        if (ctx.json) return printJson({ isNet })
        printLine(String(isNet))
      }),
    )

  program
    .command('middleware')
    .description('Get network middleware address.')
    .argument(
      '<network_address>',
      'an address of the network to get a middleware for',
      parseAddressArg,
    )
    .action((networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const middleware = await ctx.symb.getMiddleware(networkAddress)
        if (ctx.json) return printJson({ middleware })
        printLine(middleware)
      }),
    )

  const listCmd = program
    .command('list')
    .description('Get all networks.')
    .option('--full', 'Show full data', false)
    .action((opts: { full?: boolean }) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const spinner = startSpinner(ctx, 'Fetching networks...')
        const nets = await (async () => {
          try {
            return await ctx.symb.getNets()
          } finally {
            spinner?.stop()
          }
        })()

        if (ctx.json) {
          if (!opts.full) return printJson({ nets })

          const counts = await ctx.symb.getNetsFullCounts(nets)
          return printJson({
            nets: nets.map((net, i) => ({
              ...net,
              ops: counts[i]?.ops ?? 0,
              vaults: counts[i]?.vaults ?? 0,
            })),
          })
        }

        printLine(`All networks [${nets.length} total]:`)

        let fullData: Array<{ ops: number; vaults: number }> | undefined
        if (opts.full) {
          const fullSpinner = startSpinner(
            ctx,
            'Fetching full network data (this can take a while)...',
          )
          try {
            fullData = await ctx.symb.getNetsFullCounts(nets)
          } finally {
            fullSpinner?.stop()
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

  listCmd.alias('ls')

  program
    .command('ops')
    .description('Get all operators opted in network.')
    .argument(
      '<network_address>',
      'an address of the network to get operators for',
      parseAddressArg,
    )
    .action((networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const spinner = startSpinner(ctx, 'Fetching network operators...')
        const ops = await (async () => {
          try {
            return await ctx.symb.getNetOps(networkAddress)
          } finally {
            spinner?.stop()
          }
        })()

        if (ctx.json) return printJson({ network: networkAddress, operators: ops })

        printLine(`Network: ${networkAddress}`)
        printLine(`Operators [${ops.length} total]:`)
        for (const op of ops) printIndented(`Operator: ${op}`, 2)
      }),
    )

  program
    .command('stakes')
    .description('Get stakes of all operators in network.')
    .argument(
      '<network_address>',
      'an address of the network to get a whole stake data for',
      parseAddressArg,
    )
    .action((networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const spinner = startSpinner(ctx, 'Fetching network stakes (this can take a while)...')
        const [middleware, opsVaults] = await (async () => {
          try {
            return await Promise.all([
              ctx.symb.getMiddleware(networkAddress),
              ctx.symb.getNetOpsVaults(networkAddress),
            ])
          } finally {
            spinner?.stop()
          }
        })()

        if (ctx.json)
          return printJson({ network: networkAddress, middleware, operators: opsVaults })

        printLine(`Network: ${networkAddress}`)
        printLine(`Middleware: ${middleware}`)
        printLine(`Operators [${opsVaults.length} total]:`)

        const totalStakes = new Map<Address, bigint>()

        for (const op of opsVaults) {
          printIndented(`Operator: ${op.op}`, 2)

          const byCollateral = groupBy(op.vaults, (v) => v.collateral)
          const totalOpStakeParts: string[] = []

          for (const [collateral, vaults] of byCollateral.entries()) {
            const tokenMeta = await ctx.symb.getTokenMeta(collateral)
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

            totalOpStakeParts.push(`${formatTokenAmount(stakesSum, tokenMeta)} ${tokenMeta.symbol}`)
            totalStakes.set(collateral, (totalStakes.get(collateral) ?? 0n) + stakesSum)
          }

          if (totalOpStakeParts.length) {
            printIndented(`Total stake: ${totalOpStakeParts.join(' + ')}`, 4)
          } else {
            printIndented('Total stake: 0', 4)
          }
          printLine('')
        }

        printLine('Total stakes:')
        for (const [collateral, stake] of totalStakes.entries()) {
          const meta = await ctx.symb.getTokenMeta(collateral)
          printIndented(
            `Collateral ${collateral} (${meta.symbol}): ${formatTokenAmount(stake, meta)}`,
            2,
          )
        }
      }),
    )

  program
    .command('max-network-limit')
    .description("Get a maximum network limit at the vault's delegator.")
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const net = networkAddress
        const delegator = await ctx.symb.getVaultDelegator(vaultAddress)

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const limit = await ctx.symb.getMaxNetworkLimit(delegator, subnetwork)
          results.push({ subnetId, subnetwork, maxNetworkLimit: limit })
        }

        if (ctx.json) return printJson({ vault, network: net, delegator, results })

        printLine('')
        for (const r of results) {
          printLine(
            `Maximum network limit for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.maxNetworkLimit}`,
          )
          printLine('')
        }
      }),
    )

  program
    .command('resolver')
    .description('Get a current resolver for a subnetwork in a vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const net = networkAddress

        const slasher = await ctx.symb.getVaultSlasher(vault)
        const slasherType = await ctx.symb.getEntityType(slasher)
        if (slasherType !== 1n) {
          if (ctx.json) return printJson({ error: 'It is not a VetoSlasher.' })
          printLine('It is not a VetoSlasher.')
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const resolver = await ctx.symb.getResolver(slasher, subnetwork)
          results.push({ subnetId, subnetwork, resolver })
        }

        if (ctx.json) return printJson({ vault, network: net, slasher, results })

        printLine('')
        for (const r of results) {
          printLine(`Resolver for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.resolver}`)
          printLine('')
        }
      }),
    )

  program
    .command('pending-resolver')
    .description('Get a pending resolver for a subnetwork in a vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const net = networkAddress

        const slasher = await ctx.symb.getVaultSlasher(vault)
        const slasherType = await ctx.symb.getEntityType(slasher)
        if (slasherType !== 1n) {
          if (ctx.json) return printJson({ error: 'It is not a VetoSlasher.' })
          printLine('It is not a VetoSlasher.')
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const resolver = await ctx.symb.getResolver(slasher, subnetwork)
          const pending = await ctx.symb.getPendingResolver(slasher, subnetwork)
          results.push({
            subnetId,
            subnetwork,
            resolver,
            pendingResolver: pending,
            hasPending: resolver !== pending,
          })
        }

        if (ctx.json) return printJson({ vault, network: net, slasher, results })

        printLine('')
        for (const r of results) {
          if (!r.hasPending) {
            printLine(
              `There is no pending resolver for subnetwork = ${r.subnetwork} at vault ${vault}`,
            )
          } else {
            printLine(
              `Pending resolver for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.pendingResolver}`,
            )
          }
          printLine('')
        }
      }),
    )
}
