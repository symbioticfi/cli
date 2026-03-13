import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { defaultedArg, parseAddressArg, parseUint48Arg } from '../cli/argParsers'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import {
  OperatorNetworkOptInServiceAbi,
  OperatorRegistryAbi,
  OperatorVaultOptInServiceAbi,
} from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { formatUnixTimestampSeconds } from '../core/time'
import { runWriteTx } from '../core/tx'
import {
  buildOperatorNetworkOptInTypedData,
  buildOperatorNetworkOptOutTypedData,
  buildOperatorVaultOptInTypedData,
  buildOperatorVaultOptOutTypedData,
} from '../core/signing/typedData'

import {
  withSigningOptions,
  withWriteOptions,
  type SigningOptions,
  type WriteOptions,
} from './writeOptions'

const DEFAULT_SIG_DURATION_SECONDS = 7n * 24n * 60n * 60n

export function registerOperatorWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program.command('register').description('Register the signer as an operator.'),
  ).action((opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: OperatorRegistryAbi,
          address: ctx.resolved.addresses.op_registry,
          functionName: 'registerOperator',
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: 'Successfully registered as an operator',
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('opt-in-vault')
      .description('Opt-in to a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg),
  ).action((vault: Address, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: OperatorVaultOptInServiceAbi,
          address: ctx.resolved.addresses.op_vault_opt_in,
          functionName: 'optIn',
          args: [vault],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully opted in to vault = ${vault}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('opt-out-vault')
      .description('Opt-out from a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg),
  ).action((vault: Address, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: OperatorVaultOptInServiceAbi,
          address: ctx.resolved.addresses.op_vault_opt_in,
          functionName: 'optOut',
          args: [vault],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully opted out from vault = ${vault}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('opt-in-net')
      .description('Opt-in to a network.')
      .argument('<network_address>', 'network address', parseAddressArg),
  ).action((net: Address, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: OperatorNetworkOptInServiceAbi,
          address: ctx.resolved.addresses.op_net_opt_in,
          functionName: 'optIn',
          args: [net],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully opted in to network = ${net}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('opt-out-net')
      .description('Opt-out from a network.')
      .argument('<network_address>', 'network address', parseAddressArg),
  ).action((net: Address, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: OperatorNetworkOptInServiceAbi,
          address: ctx.resolved.addresses.op_net_opt_in,
          functionName: 'optOut',
          args: [net],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully opted out from network = ${net}`,
        })
      })
    }),
  )

  withSigningOptions(
    program
      .command('opt-in-vault-sig')
      .description('Get a signature for opt-in to a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .addArgument(
        defaultedArg(
          '[duration]',
          'seconds until expiry',
          parseUint48Arg,
          DEFAULT_SIG_DURATION_SECONDS,
        ),
      ),
  ).action((vault: Address, dur: bigint, opts: SigningOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()

      await withSigningAccount(opts, async ({ account, address: who }) => {
        if (typeof account === 'string') {
          throw new Error('The --from option cannot be used for signature commands.')
        }
        const verifyingContract = ctx.resolved.addresses.op_vault_opt_in

        const nonce = await ctx.symb.getOperatorVaultOptInNonce(who, vault)
        const deadline = BigInt(Math.floor(Date.now() / 1000)) + dur

        const typedData = buildOperatorVaultOptInTypedData({
          chainId: ctx.resolved.chainId,
          verifyingContract,
          who,
          where: vault,
          nonce,
          deadline,
        })

        const signTypedData = account.signTypedData
        if (!signTypedData)
          throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, vault, nonce, deadline, signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Vault: ${vault}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      })
    }),
  )

  withSigningOptions(
    program
      .command('opt-out-vault-sig')
      .description('Get a signature for opt-out from a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .addArgument(
        defaultedArg(
          '[duration]',
          'seconds until expiry',
          parseUint48Arg,
          DEFAULT_SIG_DURATION_SECONDS,
        ),
      ),
  ).action((vault: Address, dur: bigint, opts: SigningOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()

      await withSigningAccount(opts, async ({ account, address: who }) => {
        if (typeof account === 'string') {
          throw new Error('The --from option cannot be used for signature commands.')
        }
        const verifyingContract = ctx.resolved.addresses.op_vault_opt_in

        const nonce = await ctx.symb.getOperatorVaultOptInNonce(who, vault)
        const deadline = BigInt(Math.floor(Date.now() / 1000)) + dur

        const typedData = buildOperatorVaultOptOutTypedData({
          chainId: ctx.resolved.chainId,
          verifyingContract,
          who,
          where: vault,
          nonce,
          deadline,
        })

        const signTypedData = account.signTypedData
        if (!signTypedData)
          throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, vault, nonce, deadline, signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Vault: ${vault}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      })
    }),
  )

  withSigningOptions(
    program
      .command('opt-in-net-sig')
      .description('Get a signature for opt-in to a network.')
      .argument('<network_address>', 'network address', parseAddressArg)
      .addArgument(
        defaultedArg(
          '[duration]',
          'seconds until expiry',
          parseUint48Arg,
          DEFAULT_SIG_DURATION_SECONDS,
        ),
      ),
  ).action((net: Address, dur: bigint, opts: SigningOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()

      await withSigningAccount(opts, async ({ account, address: who }) => {
        if (typeof account === 'string') {
          throw new Error('The --from option cannot be used for signature commands.')
        }
        const verifyingContract = ctx.resolved.addresses.op_net_opt_in

        const nonce = await ctx.symb.getOperatorNetworkOptInNonce(who, net)
        const deadline = BigInt(Math.floor(Date.now() / 1000)) + dur

        const typedData = buildOperatorNetworkOptInTypedData({
          chainId: ctx.resolved.chainId,
          verifyingContract,
          who,
          where: net,
          nonce,
          deadline,
        })

        const signTypedData = account.signTypedData
        if (!signTypedData)
          throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, network: net, nonce, deadline, signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Network: ${net}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      })
    }),
  )

  withSigningOptions(
    program
      .command('opt-out-net-sig')
      .description('Get a signature for opt-out from a network.')
      .argument('<network_address>', 'network address', parseAddressArg)
      .addArgument(
        defaultedArg(
          '[duration]',
          'seconds until expiry',
          parseUint48Arg,
          DEFAULT_SIG_DURATION_SECONDS,
        ),
      ),
  ).action((net: Address, dur: bigint, opts: SigningOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()

      await withSigningAccount(opts, async ({ account, address: who }) => {
        if (typeof account === 'string') {
          throw new Error('The --from option cannot be used for signature commands.')
        }
        const verifyingContract = ctx.resolved.addresses.op_net_opt_in

        const nonce = await ctx.symb.getOperatorNetworkOptInNonce(who, net)
        const deadline = BigInt(Math.floor(Date.now() / 1000)) + dur

        const typedData = buildOperatorNetworkOptOutTypedData({
          chainId: ctx.resolved.chainId,
          verifyingContract,
          who,
          where: net,
          nonce,
          deadline,
        })

        const signTypedData = account.signTypedData
        if (!signTypedData)
          throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, network: net, nonce, deadline, signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Network: ${net}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      })
    }),
  )
}
