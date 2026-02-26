import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseUint256 } from '../cli/parse'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { confirmOrExit } from '../core/confirm'
import { ZERO_ADDRESS } from '../core/constants'
import { VaultAbi } from '../core/contracts'
import { printLine } from '../core/output'
import { formatUnixTimestampSeconds } from '../core/time'
import { runWriteTx } from '../core/tx'
import { formatTokenAmount, parseTokenAmount } from '../core/units'

import { withWriteOptions } from './writeOptions'

type WriteOpts = {
  privateKey?: string
  ledger?: boolean
  ledgerAddress?: string
  ledgerPath?: string
  yes?: boolean
  dryRun?: boolean
}

export function registerStakerWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program
      .command('withdraw')
      .description('Withdraw from the vault.')
      .argument('<vault_address>', 'vault address')
      .argument('<amount>', 'amount of tokens to withdraw (token units, e.g. 1.5)')
      .argument('[claimer]', 'address that needs to claim the withdrawal', ZERO_ADDRESS),
  ).action((vaultAddress, amount, claimer, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const claimerRaw = parseAddress(claimer)

      await withSigningAccount(opts, async ({ account, address: signer }) => {
        const claimAddr = claimerRaw === ZERO_ADDRESS ? signer : claimerRaw
        const token = await ctx.symb.getVaultCollateral(vault)
        const meta = await ctx.symb.getTokenMeta(token)
        const weiAmount = parseTokenAmount(amount, meta)

        if (claimAddr !== signer) {
          const ok = await confirmOrExit({
            yes: opts.yes,
            message: `Are you sure you want to withdraw ${amount} ${meta.symbol} from vault = ${vault} with claimer = ${claimAddr}?`,
          })
          if (!ok) return
        }

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
          successMessage: `Successfully withdrew ${amount} ${meta.symbol} from vault = ${vault} with claimer = ${claimAddr}\nIt will be claimable after epoch ${nextEpoch} ends (${formatUnixTimestampSeconds(nextEpochEnd)})`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('claim')
      .description('Claim a withdrawal for some epoch at the vault.')
      .argument('<vault_address>', 'vault address')
      .argument('<epoch>', 'epoch')
      .argument('[recipient]', 'recipient address', ZERO_ADDRESS),
  ).action((vaultAddress, epoch, recipient, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const ep = parseUint256(epoch)
      const recipientRaw = parseAddress(recipient)

      await withSigningAccount(opts, async ({ account, address: signer }) => {
        const recipientAddr = recipientRaw === ZERO_ADDRESS ? signer : recipientRaw

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

        if (recipientAddr !== signer) {
          const ok = await confirmOrExit({
            yes: opts.yes,
            message: `Are you sure you want to claim ${withdrawals} ${meta.symbol} from vault = ${vault} to recipient = ${recipientAddr}?`,
          })
          if (!ok) return
        }

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
          successMessage: `Successfully claimed ${withdrawals} ${meta.symbol} from vault = ${vault} to recipient = ${recipientAddr} for epoch = ${ep}`,
        })
      })
    }),
  )
}
