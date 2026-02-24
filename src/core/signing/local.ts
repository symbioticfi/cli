import type { Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

export function accountFromPrivateKey(privateKey: Hex) {
  return privateKeyToAccount(privateKey)
}

