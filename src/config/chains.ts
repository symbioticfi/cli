import { getAddress, type Address, type Chain } from 'viem'
import { hoodi, mainnet, sepolia } from 'viem/chains'

export type ChainKey = 'mainnet' | 'hoodi' | 'sepolia'

export const CORE_ADDRESS_KEYS = [
  'op_registry',
  'net_registry',
  'op_vault_opt_in',
  'op_net_opt_in',
  'middleware_service',
  'vault_factory',
] as const
export type CoreAddressKey = (typeof CORE_ADDRESS_KEYS)[number]

// Rewards (optional on some chains).
export const REWARDS_ADDRESS_KEYS = ['curator_registry', 'fee_registry', 'rewards'] as const
export type RewardsAddressKey = (typeof REWARDS_ADDRESS_KEYS)[number]

export const ALL_ADDRESS_KEYS = [...CORE_ADDRESS_KEYS, ...REWARDS_ADDRESS_KEYS] as const
export type ChainAddressKey = (typeof ALL_ADDRESS_KEYS)[number]

export type ChainAddresses = Record<CoreAddressKey, Address> &
  Partial<Record<RewardsAddressKey, Address>>

export type ChainConfig = {
  key: ChainKey
  chainId: number
  defaultRpcUrls: readonly string[]
  addresses: ChainAddresses
  viemChain: Chain
}

export const CHAIN_KEY_BY_ID: Record<string, ChainKey> = {
  mainnet: 'mainnet',
  '1': 'mainnet',
  hoodi: 'hoodi',
  '560048': 'hoodi',
  sepolia: 'sepolia',
  '11155111': 'sepolia',
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

export const CHAIN_CONFIGS: Record<ChainKey, ChainConfig> = {
  mainnet: {
    key: 'mainnet',
    chainId: 1,
    defaultRpcUrls: [
      'https://ethereum-rpc.publicnode.com',
      'https://rpc.mevblocker.io',
      'https://rpc.ankr.com/eth',
      'https://eth.drpc.org',
      'https://eth-pokt.nodies.app',
      'https://eth.merkle.io',
    ],
    addresses: {
      op_registry: a('0xAd817a6Bc954F678451A71363f04150FDD81Af9F'),
      net_registry: a('0xC773b1011461e7314CF05f97d95aa8e92C1Fd8aA'),
      op_vault_opt_in: a('0xb361894bC06cbBA7Ea8098BF0e32EB1906A5F891'),
      op_net_opt_in: a('0x7133415b33B438843D581013f98A08704316633c'),
      middleware_service: a('0xD7dC9B366c027743D90761F71858BCa83C6899Ad'),
      vault_factory: a('0xAEb6bdd95c502390db8f52c8909F703E9Af6a346'),
      curator_registry: a('0xF75D8d8F790178F0d7F2ee7656874567d382C21e'),
      fee_registry: a('0x3E5a669F673712Bf72De956608E89D36561cbAf1'),
      rewards: a('0xa13e65cA0FeFa52cCb9615108fF400EF4806866B'),
    },
    viemChain: mainnet,
  },
  hoodi: {
    key: 'hoodi',
    chainId: 560_048,
    defaultRpcUrls: [...hoodi.rpcUrls.default.http, 'https://ethereum-hoodi-rpc.publicnode.com'],
    addresses: {
      ...baseTestnetAddresses,
      curator_registry: a('0x0fbd01C89F4B12475A67204FF4e18E809839B7b4'),
      fee_registry: a('0x4804a29f16E25cE1BcBd802547445012fa7e0051'),
      rewards: a('0x2A49C0B7154919eA2453aA190A014994A5C87D84'),
    },
    viemChain: hoodi,
  },
  sepolia: {
    key: 'sepolia',
    chainId: 11_155_111,
    defaultRpcUrls: [
      ...sepolia.rpcUrls.default.http,
      'https://1rpc.io/sepolia',
      'https://0xrpc.io/sep',
      'https://ethereum-sepolia-rpc.publicnode.com',
    ],
    addresses: {
      ...baseTestnetAddresses,
    },
    viemChain: sepolia,
  },
}
