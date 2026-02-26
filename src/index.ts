import { createProgram } from './cli/program'

const program = createProgram()

// `tsx` may forward `--` into argv. Commander treats args after `--` as operands,
// which breaks `pnpm dev -- --help`.
const argv = process.argv.filter((arg) => arg !== '--')
await program.parseAsync(argv)
