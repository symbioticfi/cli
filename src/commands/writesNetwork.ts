import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg, parseUint256Arg, parseUint96Arg } from '../cli/argParsers'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { NetworkRegistryAbi, NetworkRestakeDelegatorAbi, VetoSlasherAbi } from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { encodeSubnetwork } from '../core/subnetwork'
import { formatUnixTimestampSeconds } from '../core/time'
import { runWriteTx } from '../core/tx'

import { withWriteOptions, type WriteOptions } from './writeOptions'

export function registerNetworkWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program.command('register-network').description('Register the signer as a network.'),
  ).action((opts: WriteOptions) =>
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
          yes: opts.yes,
          successMessage: 'Successfully registered as a network',
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-max-network-limit')
      .description("Set a maximum network limit at the vault's delegator.")
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument(
        '<max_limit>',
        'maximum amount of stake a network is ready to get from the vault (wei)',
        parseUint256Arg,
      )
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', parseUint96Arg, 0n),
  ).action((vaultAddress: Address, maxLimit: bigint, subnetworkId: bigint, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = vaultAddress
      const max = maxLimit
      const subnetId = subnetworkId

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
          yes: opts.yes,
          successMessage: `Successfully set max limit = ${max} in vault = ${vault}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-resolver')
      .description('Set a resolver for a subnetwork at VetoSlasher.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<resolver>', 'resolver address', parseAddressArg)
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', parseUint96Arg, 0n),
  ).action(
    (vaultAddress: Address, resolverAddress: Address, subnetworkId: bigint, opts: WriteOptions) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const resolver = resolverAddress
        const subnetId = subnetworkId

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

          const confirmMessage =
            currentResolver !== pendingResolver
              ? `You have a pending set resolver request for ${pendingResolver}.\nThis will replace it with ${resolver}.\nNew resolver set timestamp: ${formatUnixTimestampSeconds(newTimestamp)}\nProceed?`
              : `Set resolver = ${resolver} for subnetwork = ${subnetwork} at vault = ${vault}?`

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
            yes: opts.yes,
            confirmMessage,
            successMessage: `Successfully set resolver = ${resolver} for subnetwork = ${subnetwork} at vault = ${vault}`,
          })
        })
      }),
  )
}
