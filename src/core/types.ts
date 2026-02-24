import type { Address } from 'viem'

export type TokenMeta = { symbol: string; decimals: number }

export type NetInfo = { net: Address; middleware: Address }

export type StakeBySubnetwork = Record<number, bigint>

export type VaultInfo = {
  vault: Address
  collateral: Address
  tvl: bigint
  delegator: Address
  slasher: Address
  delegatorType: bigint
  slasherType: bigint
  delegatorOperator?: Address
  delegatorNetwork?: Address
}

