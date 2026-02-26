import type { Address, Hex } from 'viem'
import type { Account, PrivateKeyAccount } from 'viem/accounts'

import { readEnv } from '../config/env'
import { accountFromPrivateKey } from '../core/signing/local'
import { parseAddress, parseBytes32Hex } from './parse'

export type SigningFlags = {
  privateKey?: string
  ledger?: boolean
  ledgerAddress?: string
  ledgerPath?: string
}

const DEFAULT_LEDGER_PATH = "m/44'/60'/0'/0/0"

export async function resolveSigningAccount(
  flags: SigningFlags,
): Promise<{ account: Account; address: Address; close: () => Promise<void> }> {
  if (flags.ledger) {
    const { createLedgerAccount } = await import('../core/signing/ledger')
    return createLedgerAccount({
      path: flags.ledgerPath ?? DEFAULT_LEDGER_PATH,
      expectedAddress: flags.ledgerAddress ? parseAddress(flags.ledgerAddress) : undefined,
    })
  }

  const env = readEnv()
  const pkInput = flags.privateKey ?? env.SYMB_PRIVATE_KEY
  if (!pkInput) throw new Error('Signer is required (use --ledger, or --private-key, or SYMB_PRIVATE_KEY).')

  const pk = parseBytes32Hex(pkInput) as Hex
  const account = accountFromPrivateKey(pk) as PrivateKeyAccount
  return { account, address: account.address, close: async () => {} }
}

export async function withSigningAccount<T>(
  flags: SigningFlags,
  fn: (args: { account: Account; address: Address }) => Promise<T>,
): Promise<T> {
  const { account, address, close } = await resolveSigningAccount(flags)
  try {
    return await fn({ account, address })
  } finally {
    await close()
  }
}
