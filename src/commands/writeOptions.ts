import type { Command } from 'commander'

import type { SigningFlags, WriteFlags } from '../cli/signingOptions'

export type SigningOptions = SigningFlags
export type WriteOptions = WriteFlags

export function withSigningOptions(cmd: Command) {
  return cmd
    .option(
      '--from <address>',
      'Use an unlocked RPC account as sender (mainly for fork/local simulations)',
    )
    .option('--private-key <hex>', 'Private key to sign with (discouraged; use SYMB_PRIVATE_KEY)')
    .option('--ledger', 'Use a Ledger device for signing instead of a private key', false)
    .option(
      '--ledger-address <address>',
      'Expected Ledger address; the CLI discovers the matching Ledger Ethereum derivation path',
    )
}

export function withWriteOptions(cmd: Command) {
  return withSigningOptions(cmd)
    .option('--yes', 'Bypass confirmation prompts', false)
    .option('--dry-run', 'Simulate only (do not send transaction)', false)
}
