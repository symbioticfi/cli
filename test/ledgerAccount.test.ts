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
    create: mocks.createTransport,
  },
}))

vi.mock('@ledgerhq/hw-app-eth', () => ({
  default: class EthMock {
    constructor(_transport: unknown) {}

    getAddress = mocks.getAddress
    signPersonalMessage = mocks.signPersonalMessage
    signTransaction = mocks.signTransaction
    signEIP712HashedMessage = mocks.signEIP712HashedMessage
  },
}))

describe('createLedgerAccount', () => {
  const path = "m/44'/60'/0'/0/0"
  const ledgerAddress = '0x8ba1f109551bd432803012645ac136ddd64dba72'

  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()

    mocks.createTransport.mockResolvedValue({
      close: mocks.closeTransport,
    })
    mocks.getAddress.mockResolvedValue({ address: ledgerAddress })
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
    const out = await createLedgerAccount({ path })

    expect(out.address).toBe('0x8ba1f109551bD432803012645Ac136ddd64DBA72')
    expect(mocks.getAddress).toHaveBeenCalledWith(path, false, false)

    await out.close()
    expect(mocks.closeTransport).toHaveBeenCalledTimes(1)
  })

  it('fails when expected Ledger address mismatches and closes transport', async () => {
    const { createLedgerAccount } = await import('../src/core/signing/ledger')

    await expect(
      createLedgerAccount({
        path,
        expectedAddress: '0x0000000000000000000000000000000000000001',
      }),
    ).rejects.toThrow('Ledger address mismatch')

    expect(mocks.closeTransport).toHaveBeenCalledTimes(1)
  })

  it('uses Ledger methods for signMessage, signTransaction, signTypedData', async () => {
    const { createLedgerAccount } = await import('../src/core/signing/ledger')
    const { account } = await createLedgerAccount({ path })
    const signer = account as any

    const signedMessage = await signer.signMessage({ message: 'hello' })
    expect(signedMessage.startsWith('0x')).toBe(true)
    expect(mocks.signPersonalMessage).toHaveBeenCalledWith(path, '68656c6c6f')

    const serializer = vi.fn(async (_tx: unknown, sig?: unknown) =>
      sig ? '0xsigned-tx' : '0xunsigned-tx',
    )
    const signedTx = await signer.signTransaction({} as never, { serializer })
    expect(signedTx).toBe('0xsigned-tx')
    expect(mocks.signTransaction).toHaveBeenCalledWith(path, 'unsigned-tx', null)
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
    expect(args[0]).toBe(path)
    expect((args[1] as string).length).toBe(64)
    expect((args[2] as string).length).toBe(64)
  })
})
