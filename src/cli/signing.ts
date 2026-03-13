import type { Address, Hex } from 'viem'
import type { Account } from 'viem/accounts'

import { readEnv } from '../config/env'
import { accountFromPrivateKey } from '../core/signing/local'
import type { SigningFlags } from './signingOptions'
import { parseAddress, parseBytes32Hex } from './parse'

export async function resolveSigningAccount(
  flags: SigningFlags,
): Promise<{ account: Account | Address; address: Address; close: () => Promise<void> }> {
  if (flags.from) {
    const address = parseAddress(flags.from)
    return { account: address, address, close: async () => {} }
  }

  if (flags.ledger) {
    const { createLedgerAccount } = await import('../core/signing/ledger')
    return createLedgerAccount({
      expectedAddress: flags.ledgerAddress ? parseAddress(flags.ledgerAddress) : undefined,
    })
  }

  const env = readEnv()
  const pkInput = flags.privateKey ?? env.SYMB_PRIVATE_KEY
  if (!pkInput)
    throw new Error(
      'Signer is required (use --from, --ledger, or --private-key, or SYMB_PRIVATE_KEY).',
    )

  const pk = parseBytes32Hex(pkInput) as Hex
  const account = accountFromPrivateKey(pk)
  return { account, address: account.address, close: async () => {} }
}

export async function withSigningAccount<T>(
  flags: SigningFlags,
  fn: (args: { account: Account | Address; address: Address }) => Promise<T>,
): Promise<T> {
  const { account, address, close } = await resolveSigningAccount(flags)
  try {
    return await fn({ account, address })
  } finally {
    await close()
  }
}
