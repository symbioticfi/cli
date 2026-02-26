import type { Command } from 'commander'

import type { CliContext } from '../cli/context'
import { parseAddress, parseHex, parseUint256 } from '../cli/parse'
import { withSigningAccount } from '../cli/signing'
import { runCliAction } from '../cli/run'
import { CuratorRegistryAbi, FeeRegistryAbi, VaultSnapshotRewardsAbi } from '../core/contracts'
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

export function registerRewardsWriteCommands(program: Command, getCtx: () => Promise<CliContext>) {
  // CuratorRegistry
  withWriteOptions(
    program
      .command('set-curator')
      .description('Set curator for a vault (RewardsV2 CuratorRegistry).')
      .argument('<vault_address>', 'vault address')
      .argument('<curator>', 'curator address'),
  ).action((vaultAddress, curatorAddress, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const curatorRegistry = ctx.symb.requireAddress('curator_registry')
      const vault = parseAddress(vaultAddress)
      const curator = parseAddress(curatorAddress)

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
          successMessage: `Successfully set curator = ${curator} for vault = ${vault}`,
        })
      })
    }),
  )

  // FeeRegistry
  withWriteOptions(
    program
      .command('set-operators-fee')
      .description('Set default operators fee (ppm) for a vault (RewardsV2 FeeRegistry).')
      .argument('<vault_address>', 'vault address')
      .argument('<fee>', 'fee in ppm (max 500000)'),
  ).action((vaultAddress, fee, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const feeRegistry = ctx.symb.requireAddress('fee_registry')
      const vault = parseAddress(vaultAddress)
      const f = parseUint256(fee)

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
          successMessage: `Successfully set operators fee = ${f} for vault = ${vault}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-operators-network-fee')
      .description('Set network-specific operators fee (ppm) for a vault (RewardsV2 FeeRegistry).')
      .argument('<vault_address>', 'vault address')
      .argument('<network_address>', 'network address')
      .argument('<fee>', 'fee in ppm (max 500000)')
      .option('--disable', 'Disable network-specific fee override', false),
  ).action((vaultAddress, networkAddress, fee, cmdOpts: WriteOpts & { disable?: boolean }) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const feeRegistry = ctx.symb.requireAddress('fee_registry')
      const vault = parseAddress(vaultAddress)
      const network = parseAddress(networkAddress)
      const f = parseUint256(fee)
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
          successMessage: `Successfully set operators network fee = ${f} (enabled=${enable}) for vault = ${vault} network = ${network}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-curator-fee')
      .description('Set default curator fee (ppm) for a vault (RewardsV2 FeeRegistry).')
      .argument('<vault_address>', 'vault address')
      .argument('<fee>', 'fee in ppm (max 500000)'),
  ).action((vaultAddress, fee, opts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const feeRegistry = ctx.symb.requireAddress('fee_registry')
      const vault = parseAddress(vaultAddress)
      const f = parseUint256(fee)

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
          successMessage: `Successfully set curator fee = ${f} for vault = ${vault}`,
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('set-curator-network-fee')
      .description('Set network-specific curator fee (ppm) for a vault (RewardsV2 FeeRegistry).')
      .argument('<vault_address>', 'vault address')
      .argument('<network_address>', 'network address')
      .argument('<fee>', 'fee in ppm (max 500000)')
      .option('--disable', 'Disable network-specific fee override', false),
  ).action((vaultAddress, networkAddress, fee, cmdOpts: WriteOpts & { disable?: boolean }) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const feeRegistry = ctx.symb.requireAddress('fee_registry')
      const vault = parseAddress(vaultAddress)
      const network = parseAddress(networkAddress)
      const f = parseUint256(fee)
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
          successMessage: `Successfully set curator network fee = ${f} (enabled=${enable}) for vault = ${vault} network = ${network}`,
        })
      })
    }),
  )

  // Rewards (VaultSnapshot)
  withWriteOptions(
    program
      .command('claim-vault-snapshot-rewards')
      .description('Claim vault snapshot rewards for the signer (RewardsV2 Rewards).')
      .argument('<vault_address>', 'vault address')
      .argument('<network_address>', 'network address')
      .argument('<token>', 'ERC20 token address')
      .argument('[recipient]', 'recipient address (default: signer)')
      .argument('[first_reward_to_claim]', 'first reward index to claim (default 0)', '0')
      .argument('[max_rewards]', 'max rewards to claim (default 1000000)', '1000000')
      .option('--last-unclaimed <n>', 'Override lastUnclaimedReward (uint256)'),
  ).action((vaultAddress, networkAddress, tokenAddress, recipient, firstRewardToClaim, maxRewards, cmdOpts: WriteOpts & { lastUnclaimed?: string }) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const rewards = ctx.symb.requireAddress('rewards')
      const vault = parseAddress(vaultAddress)
      const network = parseAddress(networkAddress)
      const token = parseAddress(tokenAddress)
      const first = parseUint256(firstRewardToClaim)
      const max = parseUint256(maxRewards)

      await withSigningAccount(cmdOpts, async ({ account, address: signer }) => {
        const to = recipient ? parseAddress(recipient) : signer
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
          successMessage: 'Successfully claimed vault snapshot rewards.',
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('claim-operator-fees')
      .description('Claim vault snapshot operator fees for the signer (RewardsV2 Rewards).')
      .argument('<vault_address>', 'vault address')
      .argument('<network_address>', 'network address')
      .argument('<token>', 'ERC20 token address')
      .argument('[recipient]', 'recipient address (default: signer)')
      .argument('[first_reward_to_claim]', 'first reward index to claim (default 0)', '0')
      .argument('[max_rewards]', 'max rewards to claim (default 1000000)', '1000000')
      .option('--last-unclaimed <n>', 'Override lastUnclaimedOperatorReward (uint256)')
      .option('--extra-data <hex>', 'Extra data (abi-encoded hints) (optional)', '0x'),
  ).action((vaultAddress, networkAddress, tokenAddress, recipient, firstRewardToClaim, maxRewards, cmdOpts: WriteOpts & { lastUnclaimed?: string; extraData?: string }) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const rewards = ctx.symb.requireAddress('rewards')
      const vault = parseAddress(vaultAddress)
      const network = parseAddress(networkAddress)
      const token = parseAddress(tokenAddress)
      const first = parseUint256(firstRewardToClaim)
      const max = parseUint256(maxRewards)
      const extraData = parseHex(cmdOpts.extraData ?? '0x')

      await withSigningAccount(cmdOpts, async ({ account, address: signer }) => {
        const to = recipient ? parseAddress(recipient) : signer
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
          successMessage: 'Successfully claimed operator fees.',
        })
      })
    }),
  )

  withWriteOptions(
    program
      .command('claim-curator-fees')
      .description('Claim vault snapshot curator fees for the signer curator (RewardsV2 Rewards).')
      .argument('<vault_address>', 'vault address')
      .argument('<token>', 'ERC20 token address')
      .argument('[recipient]', 'recipient address (default: signer)'),
  ).action((vaultAddress, tokenAddress, recipient, cmdOpts: WriteOpts) =>
    runCliAction(async () => {
      const ctx = await getCtx()
      const rewards = ctx.symb.requireAddress('rewards')
      const vault = parseAddress(vaultAddress)
      const token = parseAddress(tokenAddress)

      await withSigningAccount(cmdOpts, async ({ account, address: signer }) => {
        const to = recipient ? parseAddress(recipient) : signer

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
          successMessage: 'Successfully claimed curator fees.',
        })
      })
    }),
  )
}
