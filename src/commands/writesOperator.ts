import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseUint48 } from '../cli/parse'
import { resolveSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import {
  OperatorNetworkOptInServiceAbi,
  OperatorRegistryAbi,
  OperatorVaultOptInServiceAbi,
} from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { formatUnixTimestampSeconds } from '../core/time'
import { createWalletClientForAccount, sendWriteRequest, simulateWriteRequest } from '../core/tx'
import {
  buildOperatorNetworkOptInTypedData,
  buildOperatorNetworkOptOutTypedData,
  buildOperatorVaultOptInTypedData,
  buildOperatorVaultOptOutTypedData,
} from '../core/signing/typedData'

import { withSigningOptions, withWriteOptions } from './writeOptions'

type SignOpts = {
  privateKey?: string
  ledger?: boolean
  ledgerAddress?: string
  ledgerPath?: string
}

type WriteOpts = SignOpts & {
  yes?: boolean
  dryRun?: boolean
}

const DEFAULT_SIG_DURATION_SECONDS = String(7 * 24 * 60 * 60)

export function registerOperatorWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program
      .command('register-operator')
      .description('Register the signer as an operator.'),
  ).action((opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const { account, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: OperatorRegistryAbi,
          address: ctx.resolved.addresses.op_registry,
          functionName: 'registerOperator',
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
        printLine('Successfully registered as an operator')
      } finally {
        await close()
      }
    }),
  )

  withWriteOptions(
    program
      .command('opt-in-vault')
      .description('Opt-in to a vault.')
      .argument('<vault_address>', 'vault address'),
  ).action((vaultAddress, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const { account, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: OperatorVaultOptInServiceAbi,
          address: ctx.resolved.addresses.op_vault_opt_in,
          functionName: 'optIn',
          args: [vault],
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
        printLine(`Successfully opted in to vault = ${vault}`)
      } finally {
        await close()
      }
    }),
  )

  withWriteOptions(
    program
      .command('opt-out-vault')
      .description('Opt-out from a vault.')
      .argument('<vault_address>', 'vault address'),
  ).action((vaultAddress, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const { account, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: OperatorVaultOptInServiceAbi,
          address: ctx.resolved.addresses.op_vault_opt_in,
          functionName: 'optOut',
          args: [vault],
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
        printLine(`Successfully opted out from vault = ${vault}`)
      } finally {
        await close()
      }
    }),
  )

  withWriteOptions(
    program
      .command('opt-in-network')
      .description('Opt-in to a network.')
      .argument('<network_address>', 'network address'),
  ).action((networkAddress, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const net = parseAddress(networkAddress)
      const { account, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: OperatorNetworkOptInServiceAbi,
          address: ctx.resolved.addresses.op_net_opt_in,
          functionName: 'optIn',
          args: [net],
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
        printLine(`Successfully opted in to network = ${net}`)
      } finally {
        await close()
      }
    }),
  )

  withWriteOptions(
    program
      .command('opt-out-network')
      .description('Opt-out from a network.')
      .argument('<network_address>', 'network address'),
  ).action((networkAddress, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const net = parseAddress(networkAddress)
      const { account, close } = await resolveSigningAccount(opts)
      try {
        const walletClient = createWalletClientForAccount(ctx.resolved, account)

        const request = await simulateWriteRequest({
          publicClient: ctx.publicClient,
          account,
          abi: OperatorNetworkOptInServiceAbi,
          address: ctx.resolved.addresses.op_net_opt_in,
          functionName: 'optOut',
          args: [net],
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
        printLine(`Successfully opted out from network = ${net}`)
      } finally {
        await close()
      }
    }),
  )

  withSigningOptions(
    program
      .command('opt-in-vault-signature')
      .description('Get a signature for opt-in to a vault.')
      .argument('<vault_address>', 'vault address')
      .argument('[duration]', 'seconds until expiry (default 7 days)', DEFAULT_SIG_DURATION_SECONDS),
  ).action((vaultAddress, duration, opts: SignOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const dur = parseUint48(duration)

      const { account, address: who, close } = await resolveSigningAccount(opts)
      try {
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
        if (!signTypedData) throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, vault, nonce, deadline: deadline.toString(), signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Vault: ${vault}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      } finally {
        await close()
      }
    }),
  )

  withSigningOptions(
    program
      .command('opt-out-vault-signature')
      .description('Get a signature for opt-out from a vault.')
      .argument('<vault_address>', 'vault address')
      .argument('[duration]', 'seconds until expiry (default 7 days)', DEFAULT_SIG_DURATION_SECONDS),
  ).action((vaultAddress, duration, opts: SignOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const dur = parseUint48(duration)

      const { account, address: who, close } = await resolveSigningAccount(opts)
      try {
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
        if (!signTypedData) throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, vault, nonce, deadline: deadline.toString(), signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Vault: ${vault}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      } finally {
        await close()
      }
    }),
  )

  withSigningOptions(
    program
      .command('opt-in-network-signature')
      .description('Get a signature for opt-in to a network.')
      .argument('<network_address>', 'network address')
      .argument('[duration]', 'seconds until expiry (default 7 days)', DEFAULT_SIG_DURATION_SECONDS),
  ).action((networkAddress, duration, opts: SignOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const net = parseAddress(networkAddress)
      const dur = parseUint48(duration)

      const { account, address: who, close } = await resolveSigningAccount(opts)
      try {
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
        if (!signTypedData) throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, network: net, nonce, deadline: deadline.toString(), signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Network: ${net}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      } finally {
        await close()
      }
    }),
  )

  withSigningOptions(
    program
      .command('opt-out-network-signature')
      .description('Get a signature for opt-out from a network.')
      .argument('<network_address>', 'network address')
      .argument('[duration]', 'seconds until expiry (default 7 days)', DEFAULT_SIG_DURATION_SECONDS),
  ).action((networkAddress, duration, opts: SignOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const net = parseAddress(networkAddress)
      const dur = parseUint48(duration)

      const { account, address: who, close } = await resolveSigningAccount(opts)
      try {
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
        if (!signTypedData) throw new Error('This signer does not support EIP-712 typed data signing.')
        const signature = await signTypedData(typedData as any)

        if (ctx.json) {
          return printJson({ operator: who, network: net, nonce, deadline: deadline.toString(), signature })
        }

        printLine('')
        printLine(`Operator: ${who}`)
        printLine(`Network: ${net}`)
        printLine(`Nonce: ${nonce}`)
        printLine(`Deadline: ${deadline} (${formatUnixTimestampSeconds(deadline)})`)
        printLine(`Success! Your signature is: ${signature}`)
      } finally {
        await close()
      }
    }),
  )
}
