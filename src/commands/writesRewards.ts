import type { Command } from 'commander'
import type { Address } from 'viem'

import type { CliContext } from '../cli/context'
import { defaultedArg, parseAddressArg, parseUint256Arg } from '../cli/argParsers'
import { parseHex, parseUint256 } from '../cli/parse'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { CuratorRegistryAbi, FeeRegistryAbi, VaultSnapshotRewardsAbi } from '../core/contracts'
import { runWriteTx } from '../core/tx'

import { withWriteOptions, type WriteOptions } from './writeOptions'

const DEFAULT_FIRST_REWARD_TO_CLAIM = 0n
const DEFAULT_MAX_REWARDS = 1_000_000n

export function registerRewardsWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  // CuratorRegistry
  withWriteOptions(
    program
      .command('set-curator')
      .description('Set curator for a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<curator>', 'curator address', parseAddressArg),
  ).action((vault: Address, curator: Address, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const curatorRegistry = ctx.symb.requireAddress('curator_registry')

      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: CuratorRegistryAbi,
          address: curatorRegistry,
          functionName: 'setCurator',
          args: [vault, curator],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully set curator = ${curator} for vault = ${vault}`,
        })
      })
    }),
  )

  // FeeRegistry
  withWriteOptions(
    program
      .command('set-operators-fee')
      .description('Set default operators fee (ppm) for a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<fee>', 'fee in ppm (max 500000)', parseUint256Arg),
  ).action((vault: Address, f: bigint, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const feeRegistry = ctx.symb.requireAddress('fee_registry')

      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: FeeRegistryAbi,
          address: feeRegistry,
          functionName: 'setOperatorsFee',
          args: [vault, f],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully set operators fee = ${f} for vault = ${vault}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-operators-network-fee')
      .description('Set network-specific operators fee (ppm) for a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<network_address>', 'network address', parseAddressArg)
      .argument('<fee>', 'fee in ppm (max 500000)', parseUint256Arg)
      .option('--disable', 'Disable network-specific fee override', false),
  ).action(
    (vault: Address, network: Address, f: bigint, cmdOpts: WriteOptions & { disable?: boolean }) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const feeRegistry = ctx.symb.requireAddress('fee_registry')
        const enable = !cmdOpts.disable

        await withSigningAccount(cmdOpts, async ({ account }) => {
          await runWriteTx({
            mode: ctx,
            resolved: ctx.resolved,
            publicClient: ctx.publicClient,
            account,
            abi: FeeRegistryAbi,
            address: feeRegistry,
            functionName: 'setOperatorsNetworkFee',
            args: [vault, network, enable, f],
            dryRun: cmdOpts.dryRun,
            yes: cmdOpts.yes,
            successMessage: `Successfully set operators network fee = ${f} (enabled=${enable}) for vault = ${vault} network = ${network}`,
          })
        })
      }),
  )

  withWriteOptions(
    program
      .command('set-curator-fee')
      .description('Set default curator fee (ppm) for a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<fee>', 'fee in ppm (max 500000)', parseUint256Arg),
  ).action((vault: Address, f: bigint, opts: WriteOptions) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const feeRegistry = ctx.symb.requireAddress('fee_registry')

      await withSigningAccount(opts, async ({ account }) => {
        await runWriteTx({
          mode: ctx,
          resolved: ctx.resolved,
          publicClient: ctx.publicClient,
          account,
          abi: FeeRegistryAbi,
          address: feeRegistry,
          functionName: 'setCuratorFee',
          args: [vault, f],
          dryRun: opts.dryRun,
          yes: opts.yes,
          successMessage: `Successfully set curator fee = ${f} for vault = ${vault}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-curator-network-fee')
      .description('Set network-specific curator fee (ppm) for a vault.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<network_address>', 'network address', parseAddressArg)
      .argument('<fee>', 'fee in ppm (max 500000)', parseUint256Arg)
      .option('--disable', 'Disable network-specific fee override', false),
  ).action(
    (vault: Address, network: Address, f: bigint, cmdOpts: WriteOptions & { disable?: boolean }) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const feeRegistry = ctx.symb.requireAddress('fee_registry')
        const enable = !cmdOpts.disable

        await withSigningAccount(cmdOpts, async ({ account }) => {
          await runWriteTx({
            mode: ctx,
            resolved: ctx.resolved,
            publicClient: ctx.publicClient,
            account,
            abi: FeeRegistryAbi,
            address: feeRegistry,
            functionName: 'setCuratorNetworkFee',
            args: [vault, network, enable, f],
            dryRun: cmdOpts.dryRun,
            yes: cmdOpts.yes,
            successMessage: `Successfully set curator network fee = ${f} (enabled=${enable}) for vault = ${vault} network = ${network}`,
          })
        })
      }),
  )

  // Rewards (VaultSnapshot)
  withWriteOptions(
    program
      .command('claim-vault-snapshot-rewards')
      .description('Claim vault snapshot rewards for the signer.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<network_address>', 'network address', parseAddressArg)
      .argument('<token>', 'ERC20 token address', parseAddressArg)
      .argument('[recipient]', 'recipient address (default: signer)', parseAddressArg)
      .addArgument(
        defaultedArg(
          '[first_reward_to_claim]',
          'first reward index to claim',
          parseUint256Arg,
          DEFAULT_FIRST_REWARD_TO_CLAIM,
        ),
      )
      .addArgument(
        defaultedArg(
          '[max_rewards]',
          'max rewards to claim',
          parseUint256Arg,
          DEFAULT_MAX_REWARDS,
        ),
      )
      .option('--last-unclaimed <n>', 'Override lastUnclaimedReward (uint256)'),
  ).action(
    (
      vaultAddress: Address,
      networkAddress: Address,
      tokenAddress: Address,
      recipient: Address | undefined,
      firstRewardToClaim: bigint,
      maxRewards: bigint,
      cmdOpts: WriteOptions & { lastUnclaimed?: string },
    ) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const rewards = ctx.symb.requireAddress('rewards')
        const vault = vaultAddress
        const network = networkAddress
        const token = tokenAddress
        const first = firstRewardToClaim
        const max = maxRewards

        await withSigningAccount(cmdOpts, async ({ account, address: signer }) => {
          const to = recipient ?? signer
          const last =
            cmdOpts.lastUnclaimed !== undefined
              ? parseUint256(cmdOpts.lastUnclaimed)
              : await ctx.symb.lastUnclaimedReward(signer, vault, network, token)

          await runWriteTx({
            mode: ctx,
            resolved: ctx.resolved,
            publicClient: ctx.publicClient,
            account,
            abi: VaultSnapshotRewardsAbi,
            address: rewards,
            functionName: 'claimVaultSnapshotRewards',
            args: [to, network, token, vault, last, first, max, []],
            dryRun: cmdOpts.dryRun,
            yes: cmdOpts.yes,
            successMessage: 'Successfully claimed vault snapshot rewards.',
          })
        })
      }),
  )

  withWriteOptions(
    program
      .command('claim-operator-fees')
      .description('Claim vault snapshot operator fees for the signer.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<network_address>', 'network address', parseAddressArg)
      .argument('<token>', 'ERC20 token address', parseAddressArg)
      .argument('[recipient]', 'recipient address (default: signer)', parseAddressArg)
      .addArgument(
        defaultedArg(
          '[first_reward_to_claim]',
          'first reward index to claim',
          parseUint256Arg,
          DEFAULT_FIRST_REWARD_TO_CLAIM,
        ),
      )
      .addArgument(
        defaultedArg(
          '[max_rewards]',
          'max rewards to claim',
          parseUint256Arg,
          DEFAULT_MAX_REWARDS,
        ),
      )
      .option('--last-unclaimed <n>', 'Override lastUnclaimedOperatorReward (uint256)')
      .option('--extra-data <hex>', 'Extra data (abi-encoded hints) (optional)', '0x'),
  ).action(
    (
      vaultAddress: Address,
      networkAddress: Address,
      tokenAddress: Address,
      recipient: Address | undefined,
      firstRewardToClaim: bigint,
      maxRewards: bigint,
      cmdOpts: WriteOptions & { lastUnclaimed?: string; extraData?: string },
    ) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const rewards = ctx.symb.requireAddress('rewards')
        const vault = vaultAddress
        const network = networkAddress
        const token = tokenAddress
        const first = firstRewardToClaim
        const max = maxRewards
        const extraData = parseHex(cmdOpts.extraData ?? '0x')

        await withSigningAccount(cmdOpts, async ({ account, address: signer }) => {
          const to = recipient ?? signer
          const last =
            cmdOpts.lastUnclaimed !== undefined
              ? parseUint256(cmdOpts.lastUnclaimed)
              : await ctx.symb.lastUnclaimedOperatorReward(signer, vault, network, token)

          await runWriteTx({
            mode: ctx,
            resolved: ctx.resolved,
            publicClient: ctx.publicClient,
            account,
            abi: VaultSnapshotRewardsAbi,
            address: rewards,
            functionName: 'claimOperatorFees',
            args: [to, network, token, vault, last, first, max, extraData],
            dryRun: cmdOpts.dryRun,
            yes: cmdOpts.yes,
            successMessage: 'Successfully claimed operator fees.',
          })
        })
      }),
  )

  withWriteOptions(
    program
      .command('claim-curator-fees')
      .description('Claim vault snapshot curator fees for the signer curator.')
      .argument('<vault_address>', 'vault address', parseAddressArg)
      .argument('<token>', 'ERC20 token address', parseAddressArg)
      .argument('[recipient]', 'recipient address (default: signer)', parseAddressArg),
  ).action(
    (vault: Address, token: Address, recipient: Address | undefined, cmdOpts: WriteOptions) =>
      runCliAction(async () => {
        const ctx = await getCtx()
        const rewards = ctx.symb.requireAddress('rewards')

        await withSigningAccount(cmdOpts, async ({ account, address: signer }) => {
          const to = recipient ?? signer

          await runWriteTx({
            mode: ctx,
            resolved: ctx.resolved,
            publicClient: ctx.publicClient,
            account,
            abi: VaultSnapshotRewardsAbi,
            address: rewards,
            functionName: 'claimCuratorFees',
            args: [to, vault, token],
            dryRun: cmdOpts.dryRun,
            yes: cmdOpts.yes,
            successMessage: 'Successfully claimed curator fees.',
          })
        })
      }),
  )
}
