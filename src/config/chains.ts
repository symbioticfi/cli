import { getAddress, type Address, type Chain } from 'viem'
import { holesky, mainnet, sepolia } from 'viem/chains'

export type ChainKey = 'mainnet' | 'holesky' | 'sepolia' | 'hoodi'

export type ChainAddresses = {
  op_registry: Address
  net_registry: Address
  op_vault_opt_in: Address
  op_net_opt_in: Address
  middleware_service: Address
  vault_factory: Address
}

export type ChainConfig = {
  key: ChainKey
  chainId: number
  defaultRpcUrl: string
  addresses: ChainAddresses
  viemChain: Chain
}

export const CHAIN_KEY_BY_ID: Record<string, ChainKey> = {
  holesky: 'holesky',
  '17000': 'holesky',
  sepolia: 'sepolia',
  '11155111': 'sepolia',
  mainnet: 'mainnet',
  '1': 'mainnet',
  hoodi: 'hoodi',
  '560048': 'hoodi',
}

export function resolveChainKey(input: string): ChainKey {
  const key = CHAIN_KEY_BY_ID[input.toLowerCase()]
  if (!key) {
    const valid = Object.keys(CHAIN_KEY_BY_ID).join(', ')
    throw new Error(`Invalid chain: ${input}. Valid options are: ${valid}`)
  }
  return key
}

function a(address: string): Address {
  return getAddress(address)
}

const baseTestnetAddresses: ChainAddresses = {
  op_registry: a('0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548'),
  net_registry: a('0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9'),
  op_vault_opt_in: a('0x95CC0a052ae33941877c9619835A233D21D57351'),
  op_net_opt_in: a('0x58973d16FFA900D11fC22e5e2B6840d9f7e13401'),
  middleware_service: a('0x62a1ddfD86b4c1636759d9286D3A0EC722D086e3'),
  vault_factory: a('0x407A039D94948484D356eFB765b3c74382A050B4'),
}

const hoodiChain: Chain = {
  id: 560_048,
  name: 'Hoodi',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: {
    default: { http: ['https://ethereum-hoodi-rpc.publicnode.com'] },
  },
}

export const CHAIN_CONFIGS: Record<ChainKey, ChainConfig> = {
  holesky: {
    key: 'holesky',
    chainId: 17_000,
    defaultRpcUrl: 'https://ethereum-holesky-rpc.publicnode.com',
    addresses: baseTestnetAddresses,
    viemChain: holesky,
  },
  sepolia: {
    key: 'sepolia',
    chainId: 11_155_111,
    defaultRpcUrl: 'https://ethereum-sepolia-rpc.publicnode.com',
    addresses: baseTestnetAddresses,
    viemChain: sepolia,
  },
  mainnet: {
    key: 'mainnet',
    chainId: 1,
    defaultRpcUrl: 'https://ethereum-rpc.publicnode.com',
    addresses: {
      op_registry: a('0xAd817a6Bc954F678451A71363f04150FDD81Af9F'),
      net_registry: a('0xC773b1011461e7314CF05f97d95aa8e92C1Fd8aA'),
      op_vault_opt_in: a('0xb361894bC06cbBA7Ea8098BF0e32EB1906A5F891'),
      op_net_opt_in: a('0x7133415b33B438843D581013f98A08704316633c'),
      middleware_service: a('0xD7dC9B366c027743D90761F71858BCa83C6899Ad'),
      vault_factory: a('0xAEb6bdd95c502390db8f52c8909F703E9Af6a346'),
    },
    viemChain: mainnet,
  },
  hoodi: {
    key: 'hoodi',
    chainId: 560_048,
    defaultRpcUrl: 'https://ethereum-hoodi-rpc.publicnode.com',
    addresses: baseTestnetAddresses,
    viemChain: hoodiChain,
  },
}

