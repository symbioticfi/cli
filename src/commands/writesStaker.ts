import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg, parseUint256Arg } from '../cli/argParsers'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { ZERO_ADDRESS } from '../core/constants'
import { VaultAbi } from '../core/contracts'
import { printLine } from '../core/output'
import { formatUnixTimestampSeconds } from '../core/time'
import { runWriteTx } from '../core/tx'
import { formatTokenAmount, parseTokenAmount } from '../core/units'

import { withWriteOptions, type WriteOptions } from './writeOptions'

export function registerStakerWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program
      .command('withdraw')
      .description('Withdraw from the vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<amount>', 'amount of tokens to withdraw (token units, e.g. 1.5)')
      .argument(
        '[claimer]',
        'address that needs to claim the withdrawal',
        parseAddressArg,
        ZERO_ADDRESS,
      ),
  ).action((vault: Address, amount: string, claimer: Address, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()

      await withSigningAccount(opts, async ({ account, address: signer }) => {
        const claimAddr = claimer === ZERO_ADDRESS ? signer : claimer
        const token = await ctx.symb.getVaultCollateral(vault)
        const meta = await ctx.symb.getTokenMeta(token)
        const weiAmount = parseTokenAmount(amount, meta)

        const confirmMessage = `Withdraw ${amount} ${meta.symbol} from vault = ${vault} (claimer = ${claimAddr})?`

        const epochDuration = await ctx.symb.getVaultEpochDuration(vault)
        const currentEpoch = await ctx.symb.getVaultCurrentEpoch(vault)
        const currentEpochStart = await ctx.symb.getVaultCurrentEpochStart(vault)
        const nextEpoch = currentEpoch + 1n
        const nextEpochEnd = currentEpochStart + 2n * epochDuration

        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: VaultAbi,
          address: vault,
          functionName: 'withdraw',
          args: [claimAddr, weiAmount],
          dryRun: opts.dryRun,
          yes: opts.yes,
          confirmMessage,
          successMessage: `Successfully withdrew ${amount} ${meta.symbol} from vault = ${vault} with claimer = ${claimAddr}\nIt will be claimable after epoch ${nextEpoch} ends (${formatUnixTimestampSeconds(nextEpochEnd)})`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('claim')
      .description('Claim a withdrawal for some epoch at the vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<epoch>', 'epoch', parseUint256Arg)
      .argument('[recipient]', 'recipient address', parseAddressArg, ZERO_ADDRESS),
  ).action((vault: Address, ep: bigint, recipient: Address, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()

      await withSigningAccount(opts, async ({ account, address: signer }) => {
        const recipientAddr = recipient === ZERO_ADDRESS ? signer : recipient

        const currentEpoch = await ctx.symb.getVaultCurrentEpoch(vault)
        if (ep >= currentEpoch) {
          printLine(`Epoch ${ep} isn't claimable yet`)
          return
        }

        const withdrawalsWei = await ctx.symb.getWithdrawals(vault, ep, signer)
        if (withdrawalsWei === 0n) {
          printLine(`No withdrawals for epoch ${ep}`)
          return
        }

        const withdrawalsClaimed = await ctx.symb.getWithdrawalsClaimed(vault, ep, signer)
        if (withdrawalsClaimed) {
          printLine(`Already claimed withdrawals for epoch ${ep}`)
          return
        }

        const token = await ctx.symb.getVaultCollateral(vault)
        const meta = await ctx.symb.getTokenMeta(token)
        const withdrawals = formatTokenAmount(withdrawalsWei, meta)

        const confirmMessage = `Claim ${withdrawals} ${meta.symbol} from vault = ${vault} to recipient = ${recipientAddr} for epoch = ${ep}?`

        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: VaultAbi,
          address: vault,
          functionName: 'claim',
          args: [recipientAddr, ep],
          dryRun: opts.dryRun,
          yes: opts.yes,
          confirmMessage,
          successMessage: `Successfully claimed ${withdrawals} ${meta.symbol} from vault = ${vault} to recipient = ${recipientAddr} for epoch = ${ep}`,
        })
      })
    }),
  )
}
