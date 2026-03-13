import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  createTransport: vi.fn(),
  closeTransport: vi.fn(),
  getAddress: vi.fn(),
  signPersonalMessage: vi.fn(),
  signTransaction: vi.fn(),
  signEIP712HashedMessage: vi.fn(),
}))

vi.mock('@ledgerhq/hw-transport-node-hid', () => ({
  default: {
    default: {
      create: mocks.createTransport,
    },
  },
}))

vi.mock('@ledgerhq/hw-app-eth', () => ({
  default: {
    default: class EthMock {
      constructor() {}

      getAddress = mocks.getAddress
      signPersonalMessage = mocks.signPersonalMessage
      signTransaction = mocks.signTransaction
      signEIP712HashedMessage = mocks.signEIP712HashedMessage
    },
  },
}))

describe('createLedgerAccount', () => {
  const defaultPath = "m/44'/60'/0'/0/0"
  const ledgerLivePath = "m/44'/60'/7'/0/0"
  const legacyPath = "m/44'/60'/0'/7"
  const ledgerAddress = '0x8ba1f109551bd432803012645ac136ddd64dba72'
  const ledgerLiveAddress = '0x0000000000000000000000000000000000000007'
  const legacyAddress = '0x0000000000000000000000000000000000000008'

  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()

    mocks.createTransport.mockResolvedValue({
      close: mocks.closeTransport,
    })
    mocks.getAddress.mockImplementation(async (path: string) => {
      if (path === ledgerLivePath) return { address: ledgerLiveAddress }
      if (path === legacyPath) return { address: legacyAddress }
      return { address: ledgerAddress }
    })
    mocks.signPersonalMessage.mockResolvedValue({
      r: '1'.padStart(64, '0'),
      s: '2'.padStart(64, '0'),
      v: 27,
    })
    mocks.signTransaction.mockResolvedValue({
      r: '3'.padStart(64, '0'),
      s: '4'.padStart(64, '0'),
      v: '1b',
    })
    mocks.signEIP712HashedMessage.mockResolvedValue({
      r: '5'.padStart(64, '0'),
      s: '6'.padStart(64, '0'),
      v: 27,
    })
  })

  it('creates a ledger-backed account and closes transport', async () => {
    const { createLedgerAccount } = await import('../src/core/signing/ledger')
    const out = await createLedgerAccount({})

    expect(out.address).toBe('0x8ba1f109551bD432803012645Ac136ddd64DBA72')
    expect(mocks.getAddress).toHaveBeenCalledWith(defaultPath, false, false)

    await out.close()
    expect(mocks.closeTransport).toHaveBeenCalledTimes(1)
  })

  it('derives a Ledger Live account path from the expected address', async () => {
    const { createLedgerAccount } = await import('../src/core/signing/ledger')
    const { account, address } = await createLedgerAccount({
      expectedAddress: ledgerLiveAddress,
    })
    const signer = account as any

    expect(address).toBe('0x0000000000000000000000000000000000000007')

    await signer.signMessage({ message: 'hello' })
    expect(mocks.signPersonalMessage).toHaveBeenCalledWith(ledgerLivePath, '68656c6c6f')
  })

  it('derives a legacy Ledger path from the expected address', async () => {
    const { createLedgerAccount } = await import('../src/core/signing/ledger')
    const { account, address } = await createLedgerAccount({
      expectedAddress: legacyAddress,
    })
    const signer = account as any

    expect(address).toBe('0x0000000000000000000000000000000000000008')

    await signer.signMessage({ message: 'hello' })
    expect(mocks.signPersonalMessage).toHaveBeenCalledWith(legacyPath, '68656c6c6f')
  })

  it('fails when the expected Ledger address is not found and closes transport', async () => {
    const { createLedgerAccount } = await import('../src/core/signing/ledger')

    await expect(
      createLedgerAccount({ expectedAddress: '0x0000000000000000000000000000000000000001' }),
    ).rejects.toThrow('was not found in Ledger Ethereum derivation paths')

    expect(mocks.closeTransport).toHaveBeenCalledTimes(1)
  })

  it('uses Ledger methods for signMessage, signTransaction, signTypedData', async () => {
    const { createLedgerAccount } = await import('../src/core/signing/ledger')
    const { account } = await createLedgerAccount({})
    const signer = account as any

    const signedMessage = await signer.signMessage({ message: 'hello' })
    expect(signedMessage.startsWith('0x')).toBe(true)
    expect(mocks.signPersonalMessage).toHaveBeenCalledWith(defaultPath, '68656c6c6f')

    const serializer = vi.fn(async (_tx: unknown, sig?: unknown) =>
      sig ? '0xsigned-tx' : '0xunsigned-tx',
    )
    const signedTx = await signer.signTransaction({} as never, { serializer })
    expect(signedTx).toBe('0xsigned-tx')
    expect(mocks.signTransaction).toHaveBeenCalledWith(defaultPath, 'unsigned-tx', null)
    expect(serializer).toHaveBeenCalledTimes(2)

    const signedTypedData = await signer.signTypedData({
      domain: {
        name: 'Symbiotic CLI',
        version: '1',
        chainId: 1,
        verifyingContract: '0x0000000000000000000000000000000000000001',
      },
      types: {
        Mail: [{ name: 'from', type: 'address' }],
      },
      primaryType: 'Mail',
      message: {
        from: '0x0000000000000000000000000000000000000002',
      },
    })

    expect(signedTypedData.startsWith('0x')).toBe(true)
    expect(mocks.signEIP712HashedMessage).toHaveBeenCalledTimes(1)
    const args = mocks.signEIP712HashedMessage.mock.calls[0]!
    expect(args[0]).toBe(defaultPath)
    expect((args[1] as string).length).toBe(64)
    expect((args[2] as string).length).toBe(64)
  })
})
