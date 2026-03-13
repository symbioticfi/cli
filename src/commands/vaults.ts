import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { parseAddressArg } from '../cli/argParsers'
import { runCliAction } from '../cli/run'
import { SUBNETWORK_IDS } from '../core/constants'
import { printIndented, printJson, printLine } from '../core/output'
import { startSpinner } from '../core/spinner'
import { encodeSubnetwork } from '../core/subnetwork'
import { formatTokenAmount } from '../core/units'

export function registerVaultReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('is')
    .description('Get whether address is a vault.')
    .argument('<address>', 'an address to check', parseAddressArg)
    .action((address: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const isVault = await ctx.symb.isVault(address)
        if (ctx.json) return printJson({ isVault })
        printLine(String(isVault))
      }),
    )

  const listCmd = program
    .command('list')
    .description('Get all vaults.')
    .option('--full', 'Show full data', false)
    .action((opts: { full?: boolean }) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vaultsSpinner = startSpinner(ctx, 'Fetching vault list...')
        const vaults = await ctx.symb.getVaults()
        vaultsSpinner?.stop()

        if (ctx.json) {
          if (!opts.full) return printJson({ vaults })

          const vaultDatas = await ctx.symb.getVaultsNetsOpsFull(vaults)
          return printJson({
            vaults: vaults.map((v, i) => ({ ...v, full: vaultDatas[i] ?? [] })),
          })
        }

        printLine(`All vaults [${vaults.length} total]:`)

        const fullSpinner = opts.full
          ? startSpinner(ctx, 'Fetching full vault data (this can take a while)...')
          : undefined
        let vaultDatas: Awaited<ReturnType<CliContext['symb']['getVaultsNetsOpsFull']>> | undefined
        try {
          vaultDatas = opts.full ? await ctx.symb.getVaultsNetsOpsFull(vaults) : undefined
        } finally {
          fullSpinner?.stop()
        }

        for (let idx = 0; idx < vaults.length; idx++) {
          const v = vaults[idx]!
          const vaultData = opts.full ? (vaultDatas?.[idx] ?? []) : []
          printIndented(`Vault: ${v.vault}`, 2)

          const collateralMeta = await ctx.symb.getTokenMeta(v.collateral)
          printIndented(`Collateral: ${v.collateral} (${collateralMeta.symbol})`, 4)
          printIndented(
            `Delegator: ${v.delegator} (${ctx.symb.delegatorTypeName(v.delegatorType)})`,
            4,
          )
          printIndented(`Slasher: ${v.slasher} (${ctx.symb.slasherTypeName(v.slasherType)})`, 4)
          printIndented(
            `TVL: ${formatTokenAmount(v.tvl, collateralMeta)} ${collateralMeta.symbol}`,
            4,
          )
          printLine('')

          if (opts.full) {
            const totalDelegated = vaultData
              .flatMap((n) => n.ops)
              .flatMap((o) => Object.values(o.stake))
              .reduce((a, b) => a + b, 0n)

            printIndented(`Networks [${vaultData.length} total]:`, 4)
            printIndented(
              `Total delegated: ${formatTokenAmount(totalDelegated, collateralMeta)} ${collateralMeta.symbol}`,
              4,
            )

            for (const netData of vaultData) {
              const delegatedToNet = netData.ops
                .flatMap((o) => Object.values(o.stake))
                .reduce((a, b) => a + b, 0n)
              printIndented(`Network: ${netData.net}`, 6)
              printIndented(`Operators [${netData.ops.length} total]`, 6)
              printIndented(
                `Delegated to network: ${formatTokenAmount(delegatedToNet, collateralMeta)} ${collateralMeta.symbol}`,
                6,
              )
              printLine('')
            }
            printLine('')
          }
        }
      }),
    )

  listCmd.alias('ls')

  program
    .command('ops')
    .description('Get all operators opted into the given vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const spinner = startSpinner(ctx, 'Fetching vault operators...')
        const ops = await (async () => {
          try {
            return await ctx.symb.getVaultOps(vaultAddress)
          } finally {
            spinner?.stop()
          }
        })()
        if (ctx.json) return printJson({ vault: vaultAddress, operators: ops })

        printLine(`Vault: ${vaultAddress}`)
        printLine(`Operators [${ops.length} total]:`)
        for (const op of ops) printIndented(`Operator: ${op}`, 2)
      }),
    )

  program
    .command('nets')
    .description('Get all networks associated with the given vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const spinner = startSpinner(ctx, 'Fetching vault networks...')
        const nets = await (async () => {
          try {
            return await ctx.symb.getVaultNets(vaultAddress)
          } finally {
            spinner?.stop()
          }
        })()
        if (ctx.json) return printJson({ vault: vaultAddress, networks: nets })

        printLine(`Vault: ${vaultAddress}`)
        printLine(`Networks [${nets.length} total]:`)
        for (const net of nets) printIndented(`Network: ${net.net}`, 2)
      }),
    )

  program
    .command('netsops')
    .description('Get all operators and their associated networks for the given vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const spinner = startSpinner(ctx, 'Fetching vault networks + operators...')
        const netsOps = await (async () => {
          try {
            return await ctx.symb.getVaultNetsOps(vaultAddress)
          } finally {
            spinner?.stop()
          }
        })()
        if (ctx.json) return printJson({ vault: vaultAddress, netsOps })

        const entries = Object.entries(netsOps) as Array<[Address, Address[]]>
        printLine(`Vault: ${vaultAddress}`)
        printLine(`Networks [${entries.length} total]:`)
        printLine('')

        for (const [net, ops] of entries) {
          printIndented(`Network: ${net}`, 2)
          printIndented(`Operators [${ops.length} total]:`, 2)
          for (const op of ops) printIndented(`Operator: ${op}`, 4)
          printLine('')
        }
      }),
    )

  program
    .command('network-limit')
    .description("Get a network limit at the vault's delegator.")
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const net = networkAddress

        const delegator = await ctx.symb.getVaultDelegator(vault)
        const delegatorType = await ctx.symb.getEntityType(delegator)

        if (![0n, 1n, 2n].includes(delegatorType)) {
          if (ctx.json) return printJson({ error: "Delegator doesn't have such functionality." })
          printLine("Delegator doesn't have such functionality.")
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const limit = await ctx.symb.getNetworkLimit(delegator, subnetwork)
          results.push({ subnetId, subnetwork, networkLimit: limit })
        }

        if (ctx.json) return printJson({ vault, network: net, delegator, delegatorType, results })

        printLine('')
        for (const r of results) {
          printLine(
            `Network limit for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.networkLimit}`,
          )
          printLine('')
        }
      }),
    )

  program
    .command('operator-network-limit')
    .description("Get an operator-network limit at the vault's delegator.")
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address, operatorAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const net = networkAddress
        const op = operatorAddress

        const delegator = await ctx.symb.getVaultDelegator(vault)
        const delegatorType = await ctx.symb.getEntityType(delegator)
        if (delegatorType !== 1n) {
          if (ctx.json) return printJson({ error: 'It is not a FullRestakeDelegator.' })
          printLine('It is not a FullRestakeDelegator.')
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const limit = await ctx.symb.getOperatorNetworkLimit(delegator, subnetwork, op)
          results.push({ subnetId, subnetwork, operatorNetworkLimit: limit })
        }

        if (ctx.json) return printJson({ vault, network: net, operator: op, delegator, results })

        printLine('')
        for (const r of results) {
          printLine(
            `Operator-network limit for subnetwork = ${r.subnetwork} and operator = ${op} at vault ${vault} is ${r.operatorNetworkLimit}`,
          )
          printLine('')
        }
      }),
    )

  program
    .command('operator-network-shares')
    .description("Get operator-network shares at the vault's delegator.")
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address, operatorAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const net = networkAddress
        const op = operatorAddress

        const delegator = await ctx.symb.getVaultDelegator(vault)
        const delegatorType = await ctx.symb.getEntityType(delegator)
        if (delegatorType !== 0n) {
          if (ctx.json) return printJson({ error: 'It is not a NetworkRestakeDelegator.' })
          printLine('It is not a NetworkRestakeDelegator.')
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const shares = await ctx.symb.getOperatorNetworkShares(delegator, subnetwork, op)
          results.push({ subnetId, subnetwork, operatorNetworkShares: shares })
        }

        if (ctx.json) return printJson({ vault, network: net, operator: op, delegator, results })

        printLine('')
        for (const r of results) {
          printLine(
            `Operator-network shares for subnetwork = ${r.subnetwork} and operator = ${op} at vault ${vault} is ${r.operatorNetworkShares}`,
          )
          printLine('')
        }
      }),
    )

  program
    .command('total-operator-network-shares')
    .description("Get total operator-network shares at the vault's delegator.")
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = vaultAddress
        const net = networkAddress

        const delegator = await ctx.symb.getVaultDelegator(vault)
        const delegatorType = await ctx.symb.getEntityType(delegator)
        if (delegatorType !== 0n) {
          if (ctx.json) return printJson({ error: 'It is not a NetworkRestakeDelegator.' })
          printLine('It is not a NetworkRestakeDelegator.')
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const shares = await ctx.symb.getTotalOperatorNetworkShares(delegator, subnetwork)
          results.push({ subnetId, subnetwork, totalOperatorNetworkShares: shares })
        }

        if (ctx.json) return printJson({ vault, network: net, delegator, results })

        printLine('')
        for (const r of results) {
          printLine(
            `Total operator-network shares for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.totalOperatorNetworkShares}`,
          )
          printLine('')
        }
      }),
    )
}
