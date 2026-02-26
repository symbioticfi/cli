import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg, parseUint256Arg, parseUint96Arg } from '../cli/argParsers'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { formatPercent } from '../core/format'
import {
  FullRestakeDelegatorAbi,
  NetworkRestakeDelegatorAbi,
  delegatorAbiByType,
} from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { encodeSubnetwork } from '../core/subnetwork'
import { runWriteTx } from '../core/tx'

import { withWriteOptions, type WriteOptions } from './writeOptions'

export function registerCuratorWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program
      .command('set-network-limit')
      .description("Set a network limit at the vault's delegator.")
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<network_address>', 'network address', parseAddressArg)
      .argument('<limit>', 'limit (wei)', parseUint256Arg)
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', parseUint96Arg, 0n),
  ).action((vault: Address, net: Address, lim: bigint, subnetId: bigint, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()

      const delegator = await ctx.symb.getVaultDelegator(vault)
      const delegatorType = await ctx.symb.getEntityType(delegator)
      if (![0n, 1n, 2n].includes(delegatorType)) {
        if (ctx.json) return printJson({ error: "Delegator doesn't have such functionality." })
        printLine("Delegator doesn't have such functionality.")
        return
      }

      await withSigningAccount(opts, async ({ account }) => {
        const subnetwork = encodeSubnetwork({ net, subnetId })
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: delegatorAbiByType(delegatorType),
          address: delegator,
          functionName: 'setNetworkLimit',
          args: [subnetwork, lim],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully set limit = ${lim} for subnetwork = ${subnetwork}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-operator-network-limit')
      .description("Set an operator-network limit at the vault's delegator.")
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<network_address>', 'network address', parseAddressArg)
      .argument('<operator_address>', 'operator address', parseAddressArg)
      .argument('<limit>', 'limit (wei)', parseUint256Arg)
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', parseUint96Arg, 0n),
  ).action(
    (
      vault: Address,
      net: Address,
      op: Address,
      lim: bigint,
      subnetId: bigint,
      opts: WriteOptions,
    ) =>
      runCliAction(async () => {
        const ctx = await getCtx()

        const delegator = await ctx.symb.getVaultDelegator(vault)
        const delegatorType = await ctx.symb.getEntityType(delegator)
        if (delegatorType !== 1n) {
          if (ctx.json) return printJson({ error: 'It is not a FullRestakeDelegator.' })
          printLine('It is not a FullRestakeDelegator.')
          return
        }

        await withSigningAccount(opts, async ({ account }) => {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          await runWriteTx({
            mode: ctx,
            resolved: ctx.resolved,
            publicClient: ctx.publicClient,
            account,
            abi: FullRestakeDelegatorAbi,
            address: delegator,
            functionName: 'setOperatorNetworkLimit',
            args: [subnetwork, op, lim],
            dryRun: opts.dryRun,
            yes: opts.yes,
            successMessage: `Successfully set limit = ${lim} for operator = ${op} in subnetwork = ${subnetwork}`,
          })
        })
      }),
  )

  withWriteOptions(
    program
      .command('set-operator-network-shares')
      .description("Set an operator-network shares at the vault's delegator.")
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<network_address>', 'network address', parseAddressArg)
      .argument('<operator_address>', 'operator address', parseAddressArg)
      .argument('<shares>', 'shares (uint256)', parseUint256Arg)
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', parseUint96Arg, 0n),
  ).action(
    (vault: Address, net: Address, op: Address, sh: bigint, subnetId: bigint, opts: WriteOptions) =>
      runCliAction(async () => {
        const ctx = await getCtx()

        const delegator = await ctx.symb.getVaultDelegator(vault)
        const delegatorType = await ctx.symb.getEntityType(delegator)
        if (delegatorType !== 0n) {
          if (ctx.json) return printJson({ error: 'It is not a NetworkRestakeDelegator.' })
          printLine('It is not a NetworkRestakeDelegator.')
          return
        }

        const subnetwork = encodeSubnetwork({ net, subnetId })
        const currentShares = await ctx.symb.getOperatorNetworkShares(delegator, subnetwork, op)
        const totalShares = await ctx.symb.getTotalOperatorNetworkShares(delegator, subnetwork)
        const newTotal = totalShares - currentShares + sh
        const percentage = formatPercent(sh, newTotal)

        const confirmMessage = `Set operator = ${op} to get ${percentage}% of the subnetwork = ${subnetwork} stake?`

        await withSigningAccount(opts, async ({ account }) => {
          await runWriteTx({
            mode: ctx,
            resolved: ctx.resolved,
            publicClient: ctx.publicClient,
            account,
            abi: NetworkRestakeDelegatorAbi,
            address: delegator,
            functionName: 'setOperatorNetworkShares',
            args: [subnetwork, op, sh],
            dryRun: opts.dryRun,
            yes: opts.yes,
            confirmMessage,
            successMessage: `Successfully set shares = ${sh} for operator = ${op} in subnetwork = ${subnetwork}`,
          })
        })
      }),
  )
}
