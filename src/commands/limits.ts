import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress } from '../cli/parse'
import { runCliAction } from '../cli/run'
import { SUBNETWORK_IDS } from '../core/constants'
import { printJson, printLine } from '../core/output'
import { encodeSubnetwork } from '../core/subnetwork'

export function registerLimitReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('max-network-limit')
    .description("Get a maximum network limit at the vault's delegator.")
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .action((vaultAddress, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const net = parseAddress(networkAddress)
        const delegator = await ctx.symb.getVaultDelegator(vault)

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const limit = await ctx.symb.getMaxNetworkLimit(delegator, subnetwork)
          results.push({ subnetId, subnetwork, maxNetworkLimit: limit })
        }

        if (ctx.json) return printJson({ vault, network: net, delegator, results })

        printLine('')
        for (const r of results) {
          printLine(
            `Maximum network limit for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.maxNetworkLimit}`,
          )
          printLine('')
        }
      }),
    )

  program
    .command('resolver')
    .description('Get a current resolver for a subnetwork in a vault.')
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .action((vaultAddress, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const net = parseAddress(networkAddress)

        const slasher = await ctx.symb.getVaultSlasher(vault)
        const slasherType = await ctx.symb.getEntityType(slasher)
        if (slasherType !== 1n) {
          if (ctx.json) return printJson({ error: 'It is not a VetoSlasher.' })
          printLine('It is not a VetoSlasher.')
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const resolver = await ctx.symb.getResolver(slasher, subnetwork)
          results.push({ subnetId, subnetwork, resolver })
        }

        if (ctx.json) return printJson({ vault, network: net, slasher, results })

        printLine('')
        for (const r of results) {
          printLine(`Resolver for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.resolver}`)
          printLine('')
        }
      }),
    )

  program
    .command('pending-resolver')
    .description('Get a pending resolver for a subnetwork in a vault.')
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .action((vaultAddress, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const net = parseAddress(networkAddress)

        const slasher = await ctx.symb.getVaultSlasher(vault)
        const slasherType = await ctx.symb.getEntityType(slasher)
        if (slasherType !== 1n) {
          if (ctx.json) return printJson({ error: 'It is not a VetoSlasher.' })
          printLine('It is not a VetoSlasher.')
          return
        }

        const results = []
        for (const subnetId of SUBNETWORK_IDS) {
          const subnetwork = encodeSubnetwork({ net, subnetId })
          const resolver = await ctx.symb.getResolver(slasher, subnetwork)
          const pending = await ctx.symb.getPendingResolver(slasher, subnetwork)
          results.push({ subnetId, subnetwork, resolver, pendingResolver: pending, hasPending: resolver !== pending })
        }

        if (ctx.json) return printJson({ vault, network: net, slasher, results })

        printLine('')
        for (const r of results) {
          if (!r.hasPending) {
            printLine(`There is no pending resolver for subnetwork = ${r.subnetwork} at vault ${vault}`)
          } else {
            printLine(`Pending resolver for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.pendingResolver}`)
          }
          printLine('')
        }
      }),
    )

  program
    .command('network-limit')
    .description("Get a network limit at the vault's delegator.")
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .action((vaultAddress, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const net = parseAddress(networkAddress)

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
          printLine(`Network limit for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.networkLimit}`)
          printLine('')
        }
      }),
    )

  program
    .command('operator-network-limit')
    .description("Get an operator-network limit at the vault's delegator.")
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .argument('<operator_address>', 'operator address')
    .action((vaultAddress, networkAddress, operatorAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const net = parseAddress(networkAddress)
        const op = parseAddress(operatorAddress)

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
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .argument('<operator_address>', 'operator address')
    .action((vaultAddress, networkAddress, operatorAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const net = parseAddress(networkAddress)
        const op = parseAddress(operatorAddress)

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
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .action((vaultAddress, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const net = parseAddress(networkAddress)

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
          printLine(`Total operator-network shares for subnetwork = ${r.subnetwork} at vault ${vault} is ${r.totalOperatorNetworkShares}`)
          printLine('')
        }
      }),
    )
}
