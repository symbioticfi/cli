import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseUint256, parseUint96 } from '../cli/parse'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { confirmOrExit } from '../core/confirm'
import { NetworkRegistryAbi, NetworkRestakeDelegatorAbi, VetoSlasherAbi } from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { encodeSubnetwork } from '../core/subnetwork'
import { formatUnixTimestampSeconds } from '../core/time'
import { runWriteTx } from '../core/tx'

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
      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: NetworkRegistryAbi,
          address: ctx.resolved.addresses.net_registry,
          functionName: 'registerNetwork',
          dryRun: opts.dryRun,
          successMessage: 'Successfully registered as a network',
        })
      })
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

      const delegator = await ctx.symb.getVaultDelegator(vault)

      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: NetworkRestakeDelegatorAbi,
          address: delegator,
          functionName: 'setMaxNetworkLimit',
          args: [subnetId, max],
          dryRun: opts.dryRun,
          successMessage: `Successfully set max limit = ${max} in vault = ${vault}`,
        })
      })
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

      await withSigningAccount(opts, async ({ account, address: signer }) => {
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

        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: VetoSlasherAbi,
          address: slasher,
          functionName: 'setResolver',
          args: [subnetId, resolver, '0x'],
          dryRun: opts.dryRun,
          successMessage: `Successfully set resolver = ${resolver} for subnetwork = ${subnetwork} at vault = ${vault}`,
        })
      })
    }),
  )
}
