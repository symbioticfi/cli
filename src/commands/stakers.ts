import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg, parseUint256Arg } from '../cli/argParsers'
import { runCliAction } from '../cli/run'
import { printJson, printLine } from '../core/output'
import { formatTokenAmount } from '../core/units'

export function registerStakerReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('active-balance')
    .description('Get an active balance of a given account at a particular vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<address>', 'account address', parseAddressArg)
    .action((vaultAddress: Address, address: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const account = address

        const token = await ctx.symb.getVaultCollateral(vault)
        const meta = await ctx.symb.getTokenMeta(token)
        const activeBalanceWei = await ctx.symb.getActiveBalance(vault, account)

        if (ctx.json)
          return printJson({
            vault,
            account,
            activeBalanceWei,
            activeBalance: formatTokenAmount(activeBalanceWei, meta),
            symbol: meta.symbol,
          })

        printLine(
          `${activeBalanceWei} (${formatTokenAmount(activeBalanceWei, meta)} ${meta.symbol})`,
        )
      }),
    )

  program
    .command('withdrawals')
    .description("Get some epoch's withdrawals of a given account at a particular vault.")
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<epoch>', 'epoch', parseUint256Arg)
    .argument('<address>', 'account address', parseAddressArg)
    .action((vaultAddress: Address, epoch: bigint, address: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const ep = epoch
        const account = address

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
      "Get whether some epoch's withdrawals of a given account at a particular vault are claimed.",
    )
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<epoch>', 'epoch', parseUint256Arg)
    .argument('<address>', 'account address', parseAddressArg)
    .action((vaultAddress: Address, epoch: bigint, address: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const ep = epoch
        const account = address

        const claimed = await ctx.symb.getWithdrawalsClaimed(vault, ep, account)
        if (ctx.json) return printJson({ vault, epoch: ep, account, claimed })
        printLine(String(claimed))
      }),
    )
}
