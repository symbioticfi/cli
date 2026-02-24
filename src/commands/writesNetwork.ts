import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseUint256, parseUint96 } from '../cli/parse'
import { resolveSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { confirmOrExit } from '../core/confirm'
import { NetworkRegistryAbi, NetworkRestakeDelegatorAbi, VetoSlasherAbi } from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { encodeSubnetwork } from '../core/subnetwork'
import { formatUnixTimestampSeconds } from '../core/time'
import { createWalletClientForAccount, sendWriteRequest, simulateWriteRequest } from '../core/tx'

import { withWriteOptions } from './writeOptions'

type WriteOpts = {
  privateKey?: string
  ledger?: boolean
  ledgerAddress?: string
  ledgerPath?: string
  yes?: boolean
  dryRun?: boolean
}

export function registerNetworkWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program
      .command('register-network')
      .description('Register the signer as a network.'),
  ).action((opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const { account, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: NetworkRegistryAbi,
          address: ctx.resolved.addresses.net_registry,
          functionName: 'registerNetwork',
        })

        if (opts.dryRun) {
          if (ctx.json) return printJson({ dryRun: true })
          printLine('Simulated successfully.')
          return
        }

        const hash = await sendWriteRequest({ walletClient, request })
        printLine(`Transaction sent: ${hash}, waiting...`)
        await ctx.publicClient.waitForTransactionReceipt({ hash })

        if (ctx.json) return printJson({ hash })
        printLine('Successfully registered as a network')
      } finally {
        await close()
      }
    }),
  )

  withWriteOptions(
    program
      .command('set-max-network-limit')
      .description("Set a maximum network limit at the vault's delegator.")
      .argument('<vault_address>', 'vault address')
      .argument('<max_limit>', 'maximum amount of stake a network is ready to get from the vault (wei)')
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', '0'),
  ).action((vaultAddress, maxLimit, subnetworkId, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const max = parseUint256(maxLimit)
      const subnetId = parseUint96(subnetworkId)

      const { account, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const delegator = await ctx.symb.getVaultDelegator(vault)

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: NetworkRestakeDelegatorAbi,
          address: delegator,
          functionName: 'setMaxNetworkLimit',
          args: [subnetId, max],
        })

        if (opts.dryRun) {
          if (ctx.json) return printJson({ dryRun: true })
          printLine('Simulated successfully.')
          return
        }

        const hash = await sendWriteRequest({ walletClient, request })
        printLine(`Transaction sent: ${hash}, waiting...`)
        await ctx.publicClient.waitForTransactionReceipt({ hash })

        if (ctx.json) return printJson({ hash })
        printLine(`Successfully set max limit = ${max} in vault = ${vault}`)
      } finally {
        await close()
      }
    }),
  )

  withWriteOptions(
    program
      .command('set-resolver')
      .description('Set a resolver for a subnetwork at VetoSlasher.')
      .argument('<vault_address>', 'vault address')
      .argument('<resolver>', 'resolver address')
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', '0'),
  ).action((vaultAddress, resolverAddress, subnetworkId, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const resolver = parseAddress(resolverAddress)
      const subnetId = parseUint96(subnetworkId)

      const { account, address: signer, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const slasher = await ctx.symb.getVaultSlasher(vault)
        const slasherType = await ctx.symb.getEntityType(slasher)
        if (slasherType !== 1n) {
          if (ctx.json) return printJson({ error: 'It is not a VetoSlasher.' })
          printLine('It is not a VetoSlasher.')
          return
        }

        const subnetwork = encodeSubnetwork({ net: signer, subnetId })
        const currentResolver = await ctx.symb.getResolver(slasher, subnetwork)
        const pendingResolver = await ctx.symb.getPendingResolver(slasher, subnetwork)

        const currentEpochStart = await ctx.symb.getVaultCurrentEpochStart(vault)
        const resolverSetEpochsDelay = await ctx.symb.getResolverSetEpochDelay(slasher)
        const epochDuration = await ctx.symb.getVaultEpochDuration(vault)
        const newTimestamp = currentEpochStart + resolverSetEpochsDelay * epochDuration

        if (currentResolver !== pendingResolver) {
          const ok = await confirmOrExit({
            yes: opts.yes,
            message: `You have a pending set resolver request for ${pendingResolver}.\nAre you sure you want to remove the existing request and create a new one with a new set timestamp = ${formatUnixTimestampSeconds(newTimestamp)}?`,
          })
          if (!ok) return
        }

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: VetoSlasherAbi,
          address: slasher,
          functionName: 'setResolver',
          args: [subnetId, resolver, '0x'],
        })

        if (opts.dryRun) {
          if (ctx.json) return printJson({ dryRun: true })
          printLine('Simulated successfully.')
          return
        }

        const hash = await sendWriteRequest({ walletClient, request })
        printLine(`Transaction sent: ${hash}, waiting...`)
        await ctx.publicClient.waitForTransactionReceipt({ hash })

        if (ctx.json) return printJson({ hash })
        printLine(`Successfully set resolver = ${resolver} for subnetwork = ${subnetwork} at vault = ${vault}`)
      } finally {
        await close()
      }
    }),
  )
}
