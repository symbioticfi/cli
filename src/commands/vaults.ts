import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg } from '../cli/argParsers'
import { runCliAction } from '../cli/run'
import { printIndented, printJson, printLine } from '../core/output'
import { formatTokenAmount } from '../core/units'

export function registerVaultReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('isvault')
    .description('Check if address is vault.')
    .argument('<address>', 'an address to check', parseAddressArg)
    .action((address: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const isVault = await ctx.symb.isVault(address)
        if (ctx.json) return printJson({ isVault })
        printLine(String(isVault))
      }),
    )

  program
    .command('vaults')
    .description('List all vaults.')
    .option('--full', 'Show full data', false)
    .action((opts: { full?: boolean }) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vaults = await ctx.symb.getVaults()

        if (ctx.json) {
          if (!opts.full) return printJson({ vaults })
          const full = []
          for (const v of vaults) {
            const vaultData = await ctx.symb.getVaultNetsOpsFull(v)
            full.push({ ...v, full: vaultData })
          }
          return printJson({ vaults: full })
        }

        printLine(`All vaults [${vaults.length} total]:`)

        for (const v of vaults) {
          printIndented(`Vault: ${v.vault}`, 2)

          const collateralMeta = await ctx.symb.getTokenMeta(v.collateral)
          printIndented(`Collateral: ${v.collateral} (${collateralMeta.symbol})`, 4)
          printIndented(
            `Delegator: ${v.delegator} (${ctx.symb.delegatorTypeName(v.delegatorType)})`,
            4,
          )
          printIndented(`Slasher: ${v.slasher} (${ctx.symb.slasherTypeName(v.slasherType)})`, 4)
          printIndented(
            `TVL: ${formatTokenAmount(v.tvl, collateralMeta)} ${collateralMeta.symbol}`,
            4,
          )
          printLine('')

          if (opts.full) {
            const vaultData = await ctx.symb.getVaultNetsOpsFull(v)
            const totalDelegated = vaultData
              .flatMap((n) => n.ops)
              .flatMap((o) => Object.values(o.stake))
              .reduce((a, b) => a + b, 0n)

            printIndented(`Networks [${vaultData.length} total]:`, 4)
            printIndented(
              `Total delegated: ${formatTokenAmount(totalDelegated, collateralMeta)} ${collateralMeta.symbol}`,
              4,
            )

            for (const netData of vaultData) {
              const delegatedToNet = netData.ops
                .flatMap((o) => Object.values(o.stake))
                .reduce((a, b) => a + b, 0n)
              printIndented(`Network: ${netData.net}`, 6)
              printIndented(`Operators [${netData.ops.length} total]`, 6)
              printIndented(
                `Delegated to network: ${formatTokenAmount(delegatedToNet, collateralMeta)} ${collateralMeta.symbol}`,
                6,
              )
              printLine('')
            }
            printLine('')
          }
        }
      }),
    )

  program
    .command('vaultops')
    .description('List all operators opted into the given vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const ops = await ctx.symb.getVaultOps(vaultAddress)
        if (ctx.json) return printJson({ vault: vaultAddress, operators: ops })

        printLine(`Vault: ${vaultAddress}`)
        printLine(`Operators [${ops.length} total]:`)
        for (const op of ops) printIndented(`Operator: ${op}`, 2)
      }),
    )

  program
    .command('vaultnets')
    .description('List all networks associated with the given vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const nets = await ctx.symb.getVaultNets(vaultAddress)
        if (ctx.json) return printJson({ vault: vaultAddress, networks: nets })

        printLine(`Vault: ${vaultAddress}`)
        printLine(`Networks [${nets.length} total]:`)
        for (const net of nets) printIndented(`Network: ${net.net}`, 2)
      }),
    )

  program
    .command('vaultnetsops')
    .description('List all operators and their associated networks for the given vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const netsOps = await ctx.symb.getVaultNetsOps(vaultAddress)
        if (ctx.json) return printJson({ vault: vaultAddress, netsOps })

        const entries = Object.entries(netsOps) as Array<[Address, Address[]]>
        printLine(`Vault: ${vaultAddress}`)
        printLine(`Networks [${entries.length} total]:`)
        printLine('')

        for (const [net, ops] of entries) {
          printIndented(`Network: ${net}`, 2)
          printIndented(`Operators [${ops.length} total]:`, 2)
          for (const op of ops) printIndented(`Operator: ${op}`, 4)
          printLine('')
        }
      }),
    )
}
