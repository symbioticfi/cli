import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseUint256 } from '../cli/parse'
import { runCliAction } from '../cli/run'
import { printJson, printLine } from '../core/output'
import { formatTokenAmount } from '../core/units'

export function registerStakerReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('active-balance-of')
    .description('Get an active balance of a given account at a particular vault.')
    .argument('<vault_address>', 'vault address')
    .argument('<address>', 'account address')
    .action((vaultAddress, address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const account = parseAddress(address)

        const token = await ctx.symb.getVaultCollateral(vault)
        const meta = await ctx.symb.getTokenMeta(token)
        const activeBalanceWei = await ctx.symb.getActiveBalance(vault, account)

        if (ctx.json) return printJson({ vault, account, activeBalanceWei, activeBalance: formatTokenAmount(activeBalanceWei, meta), symbol: meta.symbol })

        printLine(`${activeBalanceWei} (${formatTokenAmount(activeBalanceWei, meta)} ${meta.symbol})`)
      }),
    )

  program
    .command('withdrawals-of')
    .description("Get some epoch's withdrawals of a given account at a particular vault.")
    .argument('<vault_address>', 'vault address')
    .argument('<epoch>', 'epoch')
    .argument('<address>', 'account address')
    .action((vaultAddress, epoch, address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const ep = parseUint256(epoch)
        const account = parseAddress(address)

        const token = await ctx.symb.getVaultCollateral(vault)
        const meta = await ctx.symb.getTokenMeta(token)
        const withdrawalsWei = await ctx.symb.getWithdrawals(vault, ep, account)

        if (ctx.json)
          return printJson({
            vault,
            epoch: ep,
            account,
            withdrawalsWei,
            withdrawals: formatTokenAmount(withdrawalsWei, meta),
            symbol: meta.symbol,
          })

        printLine(`${withdrawalsWei} (${formatTokenAmount(withdrawalsWei, meta)} ${meta.symbol})`)
      }),
    )

  program
    .command('withdrawals-claimed')
    .description(
      "Check if some epoch's withdrawals of a given account at a particular vault are claimed.",
    )
    .argument('<vault_address>', 'vault address')
    .argument('<epoch>', 'epoch')
    .argument('<address>', 'account address')
    .action((vaultAddress, epoch, address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const ep = parseUint256(epoch)
        const account = parseAddress(address)

        const claimed = await ctx.symb.getWithdrawalsClaimed(vault, ep, account)
        if (ctx.json) return printJson({ vault, epoch: ep, account, claimed })
        printLine(String(claimed))
      }),
    )
}
