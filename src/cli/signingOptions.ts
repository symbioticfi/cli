export const DEFAULT_LEDGER_PATH = "m/44'/60'/0'/0/0"

export type SigningFlags = {
  privateKey?: string
  ledger?: boolean
  ledgerAddress?: string
  ledgerPath?: string
}

export type WriteFlags = SigningFlags & {
  yes?: boolean
  dryRun?: boolean
}
