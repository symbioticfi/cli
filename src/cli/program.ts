import { Command } from 'commander'

import { createContextGetter } from './context'
import { registerNetworkReadCommands } from '../commands/nets'
import { registerOperatorReadCommands } from '../commands/operators'
import { registerRewardsReadCommands } from '../commands/rewards'
import { registerStakerReadCommands } from '../commands/stakers'
import { registerVaultReadCommands } from '../commands/vaults'
import { registerCuratorWriteCommands } from '../commands/writesCurator'
import { registerNetworkWriteCommands } from '../commands/writesNetwork'
import { registerOperatorWriteCommands } from '../commands/writesOperator'
import { registerRewardsWriteCommands } from '../commands/writesRewards'
import { registerStakerWriteCommands } from '../commands/writesStaker'

export function createProgram() {
  const program = new Command()

  program.name('symb').description('Symbiotic CLI (TypeScript + viem)').version('0.0.0')

  program
    .option('--chain <chain>', 'Chain key or chainId (mainnet, hoodi, sepolia)', 'mainnet')
    .option('--rpc <url>', 'Ethereum RPC URL override')
    .option('--batch-size <n>', 'Multicall batch size', (v) => Number(v))
    .option('--concurrency <n>', 'Multicall concurrency', (v) => Number(v))
    .option('--timeout-ms <n>', 'RPC request timeout (ms)', (v) => Number(v))
    .option('--retries <n>', 'RPC retry count', (v) => Number(v))
    .option('--json', 'Machine-readable JSON output', false)
    .option('--quiet', 'Minimal output', false)

  program.configureHelp({ helpWidth: 110, sortSubcommands: true, sortOptions: true })
  program.showHelpAfterError()

  program.addHelpText(
    'after',
    `
Learn more:
  symb <group> --help

Examples:
  symb net list --full
  symb op stakes <operator>
  symb vault list --full
`,
  )

  const getCtx = createContextGetter(program)

  // Public groups (shown in root help).
  const net = program.command('net').description('Network-related commands')
  net.action(() => net.help())

  const op = program.command('op').description('Operator-related commands')
  op.action(() => op.help())

  const vault = program.command('vault').description('Vault-related commands')
  vault.action(() => vault.help())

  const staker = program.command('staker').description('Staker commands')
  staker.action(() => staker.help())

  const rewards = program.command('rewards').description('Rewards commands')
  rewards.action(() => rewards.help())

  // Grouped commands (primary UX).
  registerNetworkReadCommands(net, getCtx)
  registerNetworkWriteCommands(net, getCtx)

  registerOperatorReadCommands(op, getCtx)
  registerOperatorWriteCommands(op, getCtx)

  registerVaultReadCommands(vault, getCtx)
  registerCuratorWriteCommands(vault, getCtx)

  registerStakerReadCommands(staker, getCtx)
  registerStakerWriteCommands(staker, getCtx)

  registerRewardsReadCommands(rewards, getCtx)
  registerRewardsWriteCommands(rewards, getCtx)

  return program
}
