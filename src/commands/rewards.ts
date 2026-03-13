import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { defaultedArg, parseAddressArg, parseUint256Arg } from '../cli/argParsers'
import { parseUint256 } from '../cli/parse'
import { runCliAction } from '../cli/run'
import { printJson, printLine } from '../core/output'
import { startSpinner } from '../core/spinner'

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
    .description('Get the curator address for a vault.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .action((vaultAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const curator = await ctx.symb.getCurator(vaultAddress)
        if (ctx.json) return printJson({ vault: vaultAddress, curator })
        printLine(curator)
      }),
    )

  program
    .command('operators-fee')
    .description('Get effective operators fee (ppm) for a vault+network.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const fee = await ctx.symb.getOperatorsFee(vaultAddress, networkAddress)
        if (ctx.json) return printJson({ vault: vaultAddress, network: networkAddress, fee })
        printLine(`${fee} (${feeToPercentString(fee)})`)
      }),
    )

  program
    .command('curator-fee')
    .description('Get effective curator fee (ppm) for a vault+network.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((vaultAddress: Address, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const fee = await ctx.symb.getCuratorFee(vaultAddress, networkAddress)
        if (ctx.json) return printJson({ vault: vaultAddress, network: networkAddress, fee })
        printLine(`${fee} (${feeToPercentString(fee)})`)
      }),
    )

  program
    .command('protocol-fee')
    .description('Get protocol fee (ppm) for a rewards type and network.')
    .argument('<rewards_type>', 'vault-snapshot | cumulative-merkle | 0 | 1')
    .argument('<network_address>', 'network address', parseAddressArg)
    .action((rewardsType, networkAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const network = networkAddress
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
    .command('curator-fees')
    .description('Get claimable curator fees (amount) for a vault+token.')
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<token>', 'ERC20 token address', parseAddressArg)
    .action((vaultAddress: Address, tokenAddress: Address) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const fees = await ctx.symb.curatorFees(vaultAddress, tokenAddress)
        if (ctx.json) return printJson({ vault: vaultAddress, token: tokenAddress, fees })
        printLine(fees.toString())
      }),
    )

  program
    .command('vault-snapshot-rewards')
    .description('Get claimable vault snapshot rewards (amount) for a staker.')
    .argument('<staker_address>', 'staker address', parseAddressArg)
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .argument('<token>', 'ERC20 token address', parseAddressArg)
    .addArgument(
      defaultedArg(
        '[first_reward_to_claim]',
        'first reward index to claim',
        parseUint256Arg,
        0n,
      ),
    )
    .addArgument(
      defaultedArg(
        '[max_rewards]',
        'max rewards to claim',
        parseUint256Arg,
        1_000_000n,
      ),
    )
    .option('--last-unclaimed <n>', 'Override lastUnclaimedReward (uint256)')
    .action(
      (
        staker: Address,
        vault: Address,
        network: Address,
        token: Address,
        firstRewardToClaim: bigint,
        maxRewards: bigint,
        cmdOpts: { lastUnclaimed?: string },
      ) =>
        runCliAction(async () => {
          const ctx = await getCtx()
          const spinner = startSpinner(ctx, 'Computing claimable vault snapshot rewards...')
          const last =
            cmdOpts.lastUnclaimed !== undefined ? parseUint256(cmdOpts.lastUnclaimed) : undefined

          const res = await (async () => {
            try {
              return await ctx.symb.previewVaultSnapshotRewards({
                staker,
                vault,
                network,
                token,
                firstRewardToClaim,
                maxRewards,
                lastUnclaimedOverride: last,
              })
            } finally {
              spinner?.stop()
            }
          })()

          if (ctx.json) return printJson(res)
          printLine(res.amount.toString())
        }),
    )

  program
    .command('operator-fees')
    .description('Get claimable operator fees (amount) for an operator.')
    .argument('<operator_address>', 'operator address', parseAddressArg)
    .argument('<vault_address>', 'vault address', parseAddressArg)
    .argument('<network_address>', 'network address', parseAddressArg)
    .argument('<token>', 'ERC20 token address', parseAddressArg)
    .addArgument(
      defaultedArg(
        '[first_reward_to_claim]',
        'first reward index to claim',
        parseUint256Arg,
        0n,
      ),
    )
    .addArgument(
      defaultedArg(
        '[max_rewards]',
        'max rewards to claim',
        parseUint256Arg,
        1_000_000n,
      ),
    )
    .option('--last-unclaimed <n>', 'Override lastUnclaimedOperatorReward (uint256)')
    .action(
      (
        operator: Address,
        vault: Address,
        network: Address,
        token: Address,
        firstRewardToClaim: bigint,
        maxRewards: bigint,
        cmdOpts: { lastUnclaimed?: string },
      ) =>
        runCliAction(async () => {
          const ctx = await getCtx()
          const spinner = startSpinner(ctx, 'Computing claimable operator fees...')
          const last =
            cmdOpts.lastUnclaimed !== undefined ? parseUint256(cmdOpts.lastUnclaimed) : undefined

          const res = await (async () => {
            try {
              return await ctx.symb.previewOperatorFees({
                operator,
                vault,
                network,
                token,
                firstRewardToClaim,
                maxRewards,
                lastUnclaimedOverride: last,
              })
            } finally {
              spinner?.stop()
            }
          })()

          if (ctx.json) return printJson(res)
          printLine(res.amount.toString())
        }),
    )
}
