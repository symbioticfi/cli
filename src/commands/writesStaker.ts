import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseUint256 } from '../cli/parse'
import { resolveSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { confirmOrExit } from '../core/confirm'
import { ZERO_ADDRESS } from '../core/constants'
import { VaultAbi, VaultTokenizedAbi } from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { formatUnixTimestampSeconds } from '../core/time'
import { createWalletClientForAccount, sendWriteRequest, simulateWriteRequest } from '../core/tx'
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
      .command('deposit')
      .description('Deposit to the vault.')
      .argument('<vault_address>', 'vault address')
      .argument('<amount>', 'amount of tokens to deposit (token units, e.g. 1.5)')
      .argument('[on_behalf_of]', 'address to deposit on behalf of', ZERO_ADDRESS),
  ).action((vaultAddress, amount, onBehalfOf, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const onBehalfOfRaw = parseAddress(onBehalfOf)

      const { account, address: signer, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const onBehalf = onBehalfOfRaw === ZERO_ADDRESS ? signer : onBehalfOfRaw
        const token = await ctx.symb.getVaultCollateral(vault)
        const meta = await ctx.symb.getTokenMeta(token)
        const weiAmount = parseTokenAmount(amount, meta)

        if (onBehalf !== signer) {
          const ok = await confirmOrExit({
            yes: opts.yes,
            message: `Are you sure you want to deposit ${amount} ${meta.symbol} to vault = ${vault} on behalf of ${onBehalf}?`,
          })
          if (!ok) return
        }

        const allowance = await ctx.symb.getAllowance(token, signer, vault)
        if (allowance < weiAmount) {
          printLine('Need to approve the vault to spend the tokens')
          const approveReq = await simulateWriteRequest({
            publicClient: ctx.publicClient,
            account,
            abi: VaultTokenizedAbi,
            address: token,
            functionName: 'approve',
            args: [vault, weiAmount],
          })

          if (opts.dryRun) {
            if (!ctx.json) printLine('Simulated approve successfully.')
          } else {
            const hash = await sendWriteRequest({ walletClient, request: approveReq })
            printLine(`Transaction sent: ${hash}, waiting...`)
            await ctx.publicClient.waitForTransactionReceipt({ hash })
            if (!ctx.json) printLine(`Successfully approved ${amount} ${meta.symbol} for deposit to vault = ${vault}`)
          }
        }

        if (!ctx.json) printLine('Depositing...')

        const depositReq = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: VaultAbi,
          address: vault,
          functionName: 'deposit',
          args: [onBehalf, weiAmount],
        })

        if (opts.dryRun) {
          if (ctx.json) return printJson({ dryRun: true })
          printLine('Simulated deposit successfully.')
          return
        }

        const hash = await sendWriteRequest({ walletClient, request: depositReq })
        printLine(`Transaction sent: ${hash}, waiting...`)
        await ctx.publicClient.waitForTransactionReceipt({ hash })

        if (ctx.json) return printJson({ hash })
        printLine(`Successfully deposited ${amount} ${meta.symbol} to vault = ${vault} on behalf of ${onBehalf}`)
      } finally {
        await close()
      }
    }),
  )

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

      const { account, address: signer, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

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

        const req = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: VaultAbi,
          address: vault,
          functionName: 'withdraw',
          args: [claimAddr, weiAmount],
        })

        if (opts.dryRun) {
          if (ctx.json) return printJson({ dryRun: true })
          printLine('Simulated withdraw successfully.')
          return
        }

        const hash = await sendWriteRequest({ walletClient, request: req })
        printLine(`Transaction sent: ${hash}, waiting...`)
        await ctx.publicClient.waitForTransactionReceipt({ hash })

        if (ctx.json) return printJson({ hash })
        printLine(
          `Successfully withdrew ${amount} ${meta.symbol} from vault = ${vault} with claimer = ${claimAddr}\nIt will be claimable after epoch ${nextEpoch} ends (${formatUnixTimestampSeconds(nextEpochEnd)})`,
        )
      } finally {
        await close()
      }
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

      const { account, address: signer, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

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

        const req = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: VaultAbi,
          address: vault,
          functionName: 'claim',
          args: [recipientAddr, ep],
        })

        if (opts.dryRun) {
          if (ctx.json) return printJson({ dryRun: true })
          printLine('Simulated claim successfully.')
          return
        }

        const hash = await sendWriteRequest({ walletClient, request: req })
        printLine(`Transaction sent: ${hash}, waiting...`)
        await ctx.publicClient.waitForTransactionReceipt({ hash })

        if (ctx.json) return printJson({ hash })
        printLine(
          `Successfully claimed ${withdrawals} ${meta.symbol} from vault = ${vault} to recipient = ${recipientAddr} for epoch = ${ep}`,
        )
      } finally {
        await close()
      }
    }),
  )
}
