import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  createLedgerAccount: vi.fn(),
  close: vi.fn(async () => {}),
}))

vi.mock('../src/core/signing/ledger', () => ({
  createLedgerAccount: mocks.createLedgerAccount,
}))

describe('ledger resolution in cli/signing', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()

    mocks.createLedgerAccount.mockResolvedValue({
      account: { address: '0x0000000000000000000000000000000000000002' },
      address: '0x0000000000000000000000000000000000000002',
      close: mocks.close,
    })
  })

  it('delegates --ledger args to createLedgerAccount', async () => {
    const { resolveSigningAccount } = await import('../src/cli/signing')
    await resolveSigningAccount({
      ledger: true,
      ledgerPath: "m/44'/60'/0'/0/9",
      ledgerAddress: '0x0000000000000000000000000000000000000002',
    })

    expect(mocks.createLedgerAccount).toHaveBeenCalledWith({
      path: "m/44'/60'/0'/0/9",
      expectedAddress: '0x0000000000000000000000000000000000000002',
    })
  })

  it('withSigningAccount closes ledger transport after callback', async () => {
    const { withSigningAccount } = await import('../src/cli/signing')

    await withSigningAccount({ ledger: true }, async ({ address }) => {
      expect(address).toBe('0x0000000000000000000000000000000000000002')
    })

    expect(mocks.close).toHaveBeenCalledTimes(1)
  })
})

