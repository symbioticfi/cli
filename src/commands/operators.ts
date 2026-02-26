import type { Command } from 'commander'
import { formatUnits, type Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg } from '../cli/argParsers'
import { runCliAction } from '../cli/run'
import { SUBNETWORK_IDS } from '../core/constants'
import { formatPercent, groupBy } from '../core/format'
import { printIndented, printJson, printLine } from '../core/output'
import { startSpinner } from '../core/spinner'
import { encodeSubnetwork } from '../core/subnetwork'
import { formatTokenAmount } from '../core/units'

export function registerOperatorReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('isop')
    .description('Check if address is operator.')
    .argument('<address>', 'an address to check', parseAddressArg)
    .action((address: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const isOp = await ctx.symb.isOp(address)
        if (ctx.json) return printJson({ isOp })
        printLine(String(isOp))
      }),
    )

  program
    .command('ops')
    .description('List all operators.')
    .action(() =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const spinner = startSpinner(ctx, 'Fetching operators...')
        const ops = await (async () => {
          try {
            return await ctx.symb.getOps()
          } finally {
            spinner?.stop()
          }
        })()
        if (ctx.json) return printJson({ operators: ops })

        printLine(`All operators [${ops.length} total]:`)
        for (const op of ops) printIndented(`Operator: ${op}`, 2)
      }),
    )

  program
    .command('op-vault-net-stake')
    .description(
      'Get operator stake in vault for network (includes shares for NetworkRestakeDelegator).',
    )
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((operatorAddress: Address, vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const op = operatorAddress
        const vault = vaultAddress
        const net = networkAddress

        const spinner = startSpinner(ctx, 'Fetching stake...')
        const { delegator, delegatorType, collateral, tokenMeta, perSubnet } = await (async () => {
          try {
            const delegator = await ctx.symb.getVaultDelegator(vault)
            const delegatorType = await ctx.symb.getEntityType(delegator)
            const collateral = await ctx.symb.getVaultCollateral(vault)
            const tokenMeta = await ctx.symb.getTokenMeta(collateral)

            const perSubnet = []
            for (const subnetId of SUBNETWORK_IDS) {
              const subnetwork = encodeSubnetwork({ net, subnetId })
              const stake = await ctx.symb.getStakeByDelegator(delegator, subnetwork, op)

              let shares:
                | {
                    operatorNetworkShares: bigint
                    totalOperatorNetworkShares: bigint
                    percent: string
                  }
                | undefined
              if (delegatorType === 0n) {
                const operatorNetworkShares = await ctx.symb.getOperatorNetworkShares(
                  delegator,
                  subnetwork,
                  op,
                )
                const totalOperatorNetworkShares = await ctx.symb.getTotalOperatorNetworkShares(
                  delegator,
                  subnetwork,
                )
                shares = {
                  operatorNetworkShares,
                  totalOperatorNetworkShares,
                  percent: formatPercent(operatorNetworkShares, totalOperatorNetworkShares),
                }
              }

              perSubnet.push({
                subnetId,
                subnetwork,
                stake,
                stakeFormatted: formatTokenAmount(stake, tokenMeta),
                shares,
              })
            }

            return { delegator, delegatorType, collateral, tokenMeta, perSubnet }
          } finally {
            spinner?.stop()
          }
        })()

        if (ctx.json)
          return printJson({
            operator: op,
            vault,
            network: net,
            collateral,
            tokenMeta,
            delegator,
            delegatorType,
            perSubnet,
          })

        printLine(`Operator stake in vault = ${vault}`)
        printLine('')

        for (const row of perSubnet) {
          if (row.shares) {
            printLine(
              `for subnetwork = ${row.subnetwork} is ${row.stakeFormatted} ${tokenMeta.symbol}\nwhich is ${row.shares.percent}% (${row.shares.operatorNetworkShares} / ${row.shares.totalOperatorNetworkShares} in shares) of network stake`,
            )
          } else {
            printLine(
              `for subnetwork = ${row.subnetwork} is ${row.stakeFormatted} ${tokenMeta.symbol}`,
            )
          }
          printLine('')
        }
      }),
    )

  program
    .command('opnets')
    .description('List all networks where operator is opted in.')
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .action((operatorAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const op = operatorAddress
        const spinner = startSpinner(ctx, 'Fetching operator networks...')
        const nets = await (async () => {
          try {
            return await ctx.symb.getOpNets(op)
          } finally {
            spinner?.stop()
          }
        })()
        if (ctx.json) return printJson({ operator: op, networks: nets.map((n) => n.net) })

        printLine(`Operator: ${op}`)
        printLine(`Networks [${nets.length} total]:`)
        for (const net of nets) printLine(`  Network: ${net.net}`)
      }),
    )

  program
    .command('opstakes')
    .description('Show operator stakes in all networks.')
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .action((operatorAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const op = operatorAddress
        const spinner = startSpinner(ctx, 'Fetching operator stakes (this can take a while)...')
        const netsVaults = await (async () => {
          try {
            return await ctx.symb.getOpNetsVaults(op)
          } finally {
            spinner?.stop()
          }
        })()

        if (ctx.json) return printJson({ operator: op, networks: netsVaults })

        printLine(`Operator: ${op}`)
        printLine(`Networks [${netsVaults.length} total]:`)

        const totalStakes = new Map<Address, bigint>()

        for (const net of netsVaults) {
          printIndented(`Network: ${net.net}`, 2)

          const byCollateral = groupBy(net.vaults, (v) => v.collateral)
          const totalNetStakeParts: string[] = []

          for (const [collateral, vaults] of byCollateral.entries()) {
            const meta = await ctx.symb.getTokenMeta(collateral)
            printIndented(`Collateral: ${collateral} (${meta.symbol})`, 4)

            let stakesSum = 0n
            for (const vault of vaults) {
              printIndented(`Vault: ${vault.vault}`, 6)
              printIndented(
                `Type: ${ctx.symb.delegatorTypeName(vault.delegatorType)} / ${ctx.symb.slasherTypeName(vault.slasherType)}`,
                8,
              )
              const stake = Object.values(vault.stake).reduce((a, b) => a + b, 0n)
              printIndented(`Stake: ${formatTokenAmount(stake, meta)}`, 8)
              stakesSum += stake
            }

            totalNetStakeParts.push(`${formatTokenAmount(stakesSum, meta)} ${meta.symbol}`)
            totalStakes.set(collateral, (totalStakes.get(collateral) ?? 0n) + stakesSum)
          }

          if (totalNetStakeParts.length) {
            printIndented(`Total stake: ${totalNetStakeParts.join(' + ')}`, 4)
          } else {
            printIndented('Total stake: 0', 4)
          }
          printLine('')
        }

        printLine('Total stakes:')
        for (const [collateral, stake] of totalStakes.entries()) {
          const meta = await ctx.symb.getTokenMeta(collateral)
          printIndented(
            `Collateral ${collateral} (${meta.symbol}): ${formatUnits(stake, meta.decimals)}`,
            2,
          )
        }
      }),
    )

  program
    .command('check-opt-in-vault')
    .description('Check if operator is opted in to a vault.')
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((operatorAddress: Address, vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const op = operatorAddress
        const vault = vaultAddress
        const opted = await ctx.symb.isOptedInVault(op, vault)
        if (ctx.json) return printJson({ operator: op, vault, optedIn: opted })

        printLine(
          opted
            ? `Operator = ${op} IS opted in to vault = ${vault}`
            : `Operator = ${op} IS NOT opted in to vault = ${vault}`,
        )
      }),
    )

  program
    .command('check-opt-in-network')
    .description('Check if operator is opted in to a network.')
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((operatorAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const op = operatorAddress
        const net = networkAddress
        const opted = await ctx.symb.isOptedInNet(op, net)
        if (ctx.json) return printJson({ operator: op, network: net, optedIn: opted })

        printLine(
          opted
            ? `Operator = ${op} IS opted in to network = ${net}`
            : `Operator = ${op} IS NOT opted in to network = ${net}`,
        )
      }),
    )
}
