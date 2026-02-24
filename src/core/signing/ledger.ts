import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import Eth from '@ledgerhq/hw-app-eth'
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

export type LedgerAccountConfig = {
  path: string
  expectedAddress?: Address
}

function signableMessageToHex(message: SignableMessage): Hex {
  if (typeof message === 'string') return toHex(message)
  if (typeof message.raw === 'string') return message.raw
  return toHex(message.raw)
}

function withEip712DomainTypes(types: Record<string, readonly { name: string; type: string }[]>, domain?: TypedDataDomain) {
  return {
    EIP712Domain: getTypesForEIP712Domain({ domain }),
    ...types,
  } as Record<string, readonly { name: string; type: string }[]>
}

export async function createLedgerAccount(config: LedgerAccountConfig): Promise<{
  account: ReturnType<typeof toAccount>
  address: Address
  close: () => Promise<void>
}> {
  // Requires native deps (node-hid/usb) to be built/enabled via `pnpm approve-builds`.
  const transport = await TransportNodeHid.create()
  const eth = new Eth(transport)

  const { address: rawAddress } = await eth.getAddress(config.path, false, false)
  const address = getAddress(rawAddress)

  if (config.expectedAddress) {
    const expected = getAddress(config.expectedAddress)
    if (expected !== address) {
      await transport.close()
      throw new Error(`Ledger address mismatch: expected ${expected}, got ${address} for path ${config.path}`)
    }
  }

  const account = toAccount({
    address,
    async signMessage({ message }) {
      const messageHex = signableMessageToHex(message)
      // Ledger expects raw hex without 0x prefix.
      const sig = await eth.signPersonalMessage(config.path, messageHex.slice(2))
      return serializeSignature({
        r: `0x${sig.r}`,
        s: `0x${sig.s}`,
        v: BigInt(sig.v),
      })
    },
    async signTransaction(transaction, options) {
      const serializer = options?.serializer ?? serializeTransaction
      const unsignedTx = await serializer(transaction as TransactionSerializable)
      const sig = await eth.signTransaction(config.path, unsignedTx.slice(2), null)

      const signed = await serializer(transaction as TransactionSerializable, {
        r: `0x${sig.r}`,
        s: `0x${sig.s}`,
        v: BigInt(`0x${sig.v}`),
      })
      return signed
    },
    async signTypedData(parameters) {
      const { domain = {}, primaryType, message, types } = parameters as TypedDataDefinition<TypedData, any>
      const fullTypes = withEip712DomainTypes(types as any, domain)

      const domainHash = hashDomain({ domain, types: fullTypes })
      const messageHash =
        primaryType === 'EIP712Domain'
          ? ('0x' + '00'.repeat(32)) as Hex
          : hashStruct({ data: message as any, primaryType: primaryType as any, types: fullTypes })

      const sig = await eth.signEIP712HashedMessage(
        config.path,
        domainHash.slice(2),
        messageHash.slice(2),
      )

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
