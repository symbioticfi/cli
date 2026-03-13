export type SigningFlags = {
  privateKey?: string
  from?: string
  ledger?: boolean
  ledgerAddress?: string
}

export type WriteFlags = SigningFlags & {
  yes?: boolean
  dryRun?: boolean
}
