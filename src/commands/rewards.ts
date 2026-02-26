import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress } from '../cli/parse'
import { runCliAction } from '../cli/run'
import { printJson, printLine } from '../core/output'

function feeToPercentString(feePpm: bigint) {
  // 1_000_000 = 100.00%
  const bp = feePpm / 100n // 10_000 = 1.00%
  const whole = bp / 100n
  const frac = (bp % 100n).toString().padStart(2, '0')
  return `${whole}.${frac}%`
}

export function registerRewardsReadCommands(program: Command, getCtx: () => Promise<CliContext>) {
  program
    .command('curator')
    .description('Get the curator address for a vault (RewardsV2 CuratorRegistry).')
    .argument('<vault_address>', 'vault address')
    .action((vaultAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const curator = await ctx.symb.getCurator(vault)
        if (ctx.json) return printJson({ vault, curator })
        printLine(curator)
      }),
    )

  program
    .command('operators-fee')
    .description('Get effective operators fee (ppm) for a vault+network (RewardsV2 FeeRegistry).')
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .action((vaultAddress, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const network = parseAddress(networkAddress)
        const fee = await ctx.symb.getOperatorsFee(vault, network)
        if (ctx.json) return printJson({ vault, network, fee })
        printLine(`${fee} (${feeToPercentString(fee)})`)
      }),
    )

  program
    .command('curator-fee')
    .description('Get effective curator fee (ppm) for a vault+network (RewardsV2 FeeRegistry).')
    .argument('<vault_address>', 'vault address')
    .argument('<network_address>', 'network address')
    .action((vaultAddress, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const network = parseAddress(networkAddress)
        const fee = await ctx.symb.getCuratorFee(vault, network)
        if (ctx.json) return printJson({ vault, network, fee })
        printLine(`${fee} (${feeToPercentString(fee)})`)
      }),
    )

  program
    .command('rewards-protocol-fee')
    .description('Get protocol fee (ppm) for a rewards type and network (RewardsV2 Rewards).')
    .argument('<rewards_type>', 'vault-snapshot | cumulative-merkle | 0 | 1')
    .argument('<network_address>', 'network address')
    .action((rewardsType, networkAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const network = parseAddress(networkAddress)
        const type =
          rewardsType === 'vault-snapshot' || rewardsType === '0'
            ? 0n
            : rewardsType === 'cumulative-merkle' || rewardsType === '1'
              ? 1n
              : (() => {
                  throw new Error(`Invalid rewards type: ${rewardsType}`)
                })()

        const fee = await ctx.symb.protocolFee(type, network)
        if (ctx.json) return printJson({ rewardsType: type, network, fee })
        printLine(`${fee} (${feeToPercentString(fee)})`)
      }),
    )

  program
    .command('vault-snapshot-curator-fees')
    .description('Get claimable curator fees (amount) for a vault+token (RewardsV2 Rewards).')
    .argument('<vault_address>', 'vault address')
    .argument('<token>', 'ERC20 token address')
    .action((vaultAddress, tokenAddress) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const vault = parseAddress(vaultAddress)
        const token = parseAddress(tokenAddress)
        const fees = await ctx.symb.curatorFees(vault, token)
        if (ctx.json) return printJson({ vault, token, fees })
        printLine(fees.toString())
      }),
    )
}
