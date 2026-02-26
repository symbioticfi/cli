import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseUint256, parseUint96 } from '../cli/parse'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { confirmOrExit } from '../core/confirm'
import { formatPercent } from '../core/format'
import {
  FullRestakeDelegatorAbi,
  NetworkRestakeDelegatorAbi,
  OperatorNetworkSpecificDelegatorAbi,
  OperatorSpecificDelegatorAbi,
} from '../core/contracts'
import { printJson, printLine } from '../core/output'
import { encodeSubnetwork } from '../core/subnetwork'
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

function delegatorAbiByType(type: bigint) {
  if (type === 0n) return NetworkRestakeDelegatorAbi
  if (type === 1n) return FullRestakeDelegatorAbi
  if (type === 2n) return OperatorSpecificDelegatorAbi
  if (type === 3n) return OperatorNetworkSpecificDelegatorAbi
  return NetworkRestakeDelegatorAbi
}

export function registerCuratorWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  withWriteOptions(
    program
      .command('set-network-limit')
      .description("Set a network limit at the vault's delegator.")
      .argument('<vault_address>', 'vault address')
      .argument('<network_address>', 'network address')
      .argument('<limit>', 'limit (wei)')
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', '0'),
  ).action((vaultAddress, networkAddress, limit, subnetworkId, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const net = parseAddress(networkAddress)
      const lim = parseUint256(limit)
      const subnetId = parseUint96(subnetworkId)

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
          successMessage: `Successfully set limit = ${lim} for subnetwork = ${subnetwork}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-operator-network-limit')
      .description("Set an operator-network limit at the vault's delegator.")
      .argument('<vault_address>', 'vault address')
      .argument('<network_address>', 'network address')
      .argument('<operator_address>', 'operator address')
      .argument('<limit>', 'limit (wei)')
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', '0'),
  ).action((vaultAddress, networkAddress, operatorAddress, limit, subnetworkId, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const net = parseAddress(networkAddress)
      const op = parseAddress(operatorAddress)
      const lim = parseUint256(limit)
      const subnetId = parseUint96(subnetworkId)

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
          successMessage: `Successfully set limit = ${lim} for operator = ${op} in subnetwork = ${subnetwork}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-operator-network-shares')
      .description("Set an operator-network shares at the vault's delegator.")
      .argument('<vault_address>', 'vault address')
      .argument('<network_address>', 'network address')
      .argument('<operator_address>', 'operator address')
      .argument('<shares>', 'shares (uint256)')
      .argument('[subnetwork_id]', 'subnetwork id (default 0)', '0'),
  ).action((vaultAddress, networkAddress, operatorAddress, shares, subnetworkId, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const vault = parseAddress(vaultAddress)
      const net = parseAddress(networkAddress)
      const op = parseAddress(operatorAddress)
      const sh = parseUint256(shares)
      const subnetId = parseUint96(subnetworkId)

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

      const ok = await confirmOrExit({
        yes: opts.yes,
        message: `Are you sure you want to make operator = ${op} to get ${percentage}% of the subnetwork = ${subnetwork} stake?`,
      })
      if (!ok) return

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
          successMessage: `Successfully set shares = ${sh} for operator = ${op} in subnetwork = ${subnetwork}`,
        })
      })
    }),
  )
}
