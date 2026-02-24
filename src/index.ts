import { Command } from 'commander'

import { createContextGetter } from './cli/context'
import { registerLimitReadCommands } from './commands/limits'
import { registerNetworkReadCommands } from './commands/nets'
import { registerOperatorReadCommands } from './commands/operators'
import { registerStakerReadCommands } from './commands/stakers'
import { registerVaultReadCommands } from './commands/vaults'
import { registerNetworkWriteCommands } from './commands/writesNetwork'
import { registerOperatorWriteCommands } from './commands/writesOperator'
import { registerCuratorWriteCommands } from './commands/writesCurator'
import { registerStakerWriteCommands } from './commands/writesStaker'

const program = new Command()

program.name('symb').description('Symbiotic CLI (TypeScript + viem)').version('0.0.0')

program
  .option('--chain <chain>', 'Chain key or chainId (mainnet, holesky, sepolia, hoodi)', 'mainnet')
  .option('--rpc <url>', 'Ethereum RPC URL override')
  .option('--provider <url>', 'Alias for --rpc (backwards compatible)')
  .option('--addresses-file <path>', 'JSON file overriding deployed addresses')
  .option('--batch-size <n>', 'Multicall batch size', (v) => Number(v))
  .option('--concurrency <n>', 'Multicall concurrency', (v) => Number(v))
  .option('--timeout-ms <n>', 'RPC request timeout (ms)', (v) => Number(v))
  .option('--retries <n>', 'RPC retry count', (v) => Number(v))
  .option('--json', 'Machine-readable JSON output', false)
  .option('--quiet', 'Minimal output', false)

program.showHelpAfterError()

const getCtx = createContextGetter(program)

registerNetworkReadCommands(program, getCtx)
registerOperatorReadCommands(program, getCtx)
registerVaultReadCommands(program, getCtx)
registerStakerReadCommands(program, getCtx)
registerLimitReadCommands(program, getCtx)
registerNetworkWriteCommands(program, getCtx)
registerOperatorWriteCommands(program, getCtx)
registerCuratorWriteCommands(program, getCtx)
registerStakerWriteCommands(program, getCtx)

// `tsx` may forward `--` into argv. Commander treats args after `--` as operands,
// which breaks `pnpm dev -- --help`.
const argv = process.argv.filter((arg) => arg !== '--')
await program.parseAsync(argv)
