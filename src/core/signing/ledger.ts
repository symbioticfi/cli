import * as TransportNodeHidModule from '@ledgerhq/hw-transport-node-hid'
import * as EthModule from '@ledgerhq/hw-app-eth'
import type Eth from '@ledgerhq/hw-app-eth'
import {
  getAddress,
  getTypesForEIP712Domain,
  hashDomain,
  hashStruct,
  serializeSignature,
  serializeTransaction,
  toHex,
  type Address,
  type Hex,
  type SignableMessage,
  type TransactionSerializable,
  type TypedData,
  type TypedDataDomain,
  type TypedDataDefinition,
} from 'viem'
import { toAccount } from 'viem/accounts'

const DEFAULT_LEDGER_PATH = "m/44'/60'/0'/0/0"
const LEDGER_DISCOVERY_INDEX_LIMIT = 50
const LEDGER_PATH_FACTORIES = [
  (index: number) => `m/44'/60'/${index}'/0/0`,
  (index: number) => `m/44'/60'/0'/${index}`,
]

type LedgerTransport = {
  close: () => Promise<void>
}

type LedgerTransportFactory = {
  create?: () => Promise<LedgerTransport>
  open?: (path?: string | null) => Promise<LedgerTransport>
}

type EthConstructor = new (transport: unknown) => Eth

export type LedgerAccountConfig = {
  expectedAddress?: Address
}

function unwrapModuleDefault<T>(moduleValue: unknown): T {
  const seen = new Set<unknown>()
  let current: unknown = moduleValue

  while (
    (typeof current === 'object' || typeof current === 'function') &&
    current !== null &&
    !seen.has(current)
  ) {
    if (typeof current === 'function') return current as T
    seen.add(current)

    const record = current as Record<string, unknown>
    if (record.default != null) {
      current = record.default
      continue
    }
    if (record['module.exports'] != null) {
      current = record['module.exports']
      continue
    }
    return current as T
  }

  return current as T
}

function getTransportNodeHid(): LedgerTransportFactory {
  const transport = unwrapModuleDefault<LedgerTransportFactory>(TransportNodeHidModule)
  if (typeof transport?.create === 'function' || typeof transport?.open === 'function')
    return transport
  throw new Error('Failed to load Ledger HID transport module')
}

function getEthConstructor(): EthConstructor {
  const EthConstructor = unwrapModuleDefault<EthConstructor>(EthModule)
  if (typeof EthConstructor === 'function') return EthConstructor
  throw new Error('Failed to load Ledger Ethereum app module')
}

async function openLedgerTransport(): Promise<LedgerTransport> {
  const transport = getTransportNodeHid()
  if (typeof transport.create === 'function') return transport.create()
  if (typeof transport.open === 'function') return transport.open(undefined)
  throw new Error('Failed to open Ledger HID transport')
}

function signableMessageToHex(message: SignableMessage): Hex {
  if (typeof message === 'string') return toHex(message)
  if (typeof message.raw === 'string') return message.raw
  return toHex(message.raw)
}

function withEip712DomainTypes(
  types: Record<string, readonly { name: string; type: string }[]>,
  domain?: TypedDataDomain,
) {
  return {
    EIP712Domain: getTypesForEIP712Domain({ domain }),
    ...types,
  } as Record<string, readonly { name: string; type: string }[]>
}

async function readAddressAtPath(eth: Eth, path: string): Promise<Address> {
  const { address } = await eth.getAddress(path, false, false)
  return getAddress(address)
}

async function resolveLedgerPath(
  eth: Eth,
  expectedAddress?: Address,
): Promise<{ path: string; address: Address }> {
  if (!expectedAddress) {
    return {
      path: DEFAULT_LEDGER_PATH,
      address: await readAddressAtPath(eth, DEFAULT_LEDGER_PATH),
    }
  }

  const expected = getAddress(expectedAddress)
  for (let index = 0; index < LEDGER_DISCOVERY_INDEX_LIMIT; index++) {
    for (const path of new Set(LEDGER_PATH_FACTORIES.map((pathFactory) => pathFactory(index)))) {
      const address = await readAddressAtPath(eth, path)
      if (address === expected) return { path, address }
    }
  }

  throw new Error(
    `Ledger address ${expected} was not found in Ledger Ethereum derivation paths (scanned indices 0-${LEDGER_DISCOVERY_INDEX_LIMIT - 1})`,
  )
}

export async function createLedgerAccount(config: LedgerAccountConfig): Promise<{
  account: ReturnType<typeof toAccount>
  address: Address
  close: () => Promise<void>
}> {
  // Requires native deps (node-hid/usb) to be built/enabled via `pnpm approve-builds`.
  const transport = await openLedgerTransport()
  const EthConstructor = getEthConstructor()
  const eth = new EthConstructor(transport)
  let path: string
  let address: Address

  try {
    const resolved = await resolveLedgerPath(eth, config.expectedAddress)
    path = resolved.path
    address = resolved.address
  } catch (error) {
    await transport.close()
    throw error
  }

  const account = toAccount({
    address,
    async signMessage({ message }) {
      const messageHex = signableMessageToHex(message)
      // Ledger expects raw hex without 0x prefix.
      const sig = await eth.signPersonalMessage(path, messageHex.slice(2))
      return serializeSignature({
        r: `0x${sig.r}`,
        s: `0x${sig.s}`,
        v: BigInt(sig.v),
      })
    },
    async signTransaction(transaction, options) {
      const serializer = options?.serializer ?? serializeTransaction
      const unsignedTx = await serializer(transaction as TransactionSerializable)
      const sig = await eth.signTransaction(path, unsignedTx.slice(2), null)

      const signed = await serializer(transaction as TransactionSerializable, {
        r: `0x${sig.r}`,
        s: `0x${sig.s}`,
        v: BigInt(`0x${sig.v}`),
      })
      return signed
    },
    async signTypedData(parameters) {
      const {
        domain = {},
        primaryType,
        message,
        types,
      } = parameters as TypedDataDefinition<TypedData, any>
      const fullTypes = withEip712DomainTypes(types as any, domain)

      const domainHash = hashDomain({ domain, types: fullTypes })
      const messageHash =
        primaryType === 'EIP712Domain'
          ? (('0x' + '00'.repeat(32)) as Hex)
          : hashStruct({ data: message as any, primaryType: primaryType as any, types: fullTypes })

      const sig = await eth.signEIP712HashedMessage(path, domainHash.slice(2), messageHash.slice(2))

      return serializeSignature({
        r: `0x${sig.r}`,
        s: `0x${sig.s}`,
        v: BigInt(sig.v),
      })
    },
  })

  return {
    account,
    address,
    close: async () => {
      await transport.close()
    },
  }
}
