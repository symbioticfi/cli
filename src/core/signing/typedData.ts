import type { Address } from 'viem'

export function buildOperatorNetworkOptInTypedData(args: {
  chainId: number
  verifyingContract: Address
  who: Address
  where: Address
  nonce: bigint
  deadline: bigint
}) {
  return {
    domain: {
      name: 'OperatorNetworkOptInService',
      version: '1',
      chainId: args.chainId,
      verifyingContract: args.verifyingContract,
    },
    types: {
      OptIn: [
        { name: 'who', type: 'address' },
        { name: 'where', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint48' },
      ],
    },
    primaryType: 'OptIn' as const,
    message: {
      who: args.who,
      where: args.where,
      nonce: args.nonce,
      deadline: args.deadline,
    },
  }
}

export function buildOperatorNetworkOptOutTypedData(args: {
  chainId: number
  verifyingContract: Address
  who: Address
  where: Address
  nonce: bigint
  deadline: bigint
}) {
  return {
    domain: {
      name: 'OperatorNetworkOptInService',
      version: '1',
      chainId: args.chainId,
      verifyingContract: args.verifyingContract,
    },
    types: {
      OptOut: [
        { name: 'who', type: 'address' },
        { name: 'where', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint48' },
      ],
    },
    primaryType: 'OptOut' as const,
    message: {
      who: args.who,
      where: args.where,
      nonce: args.nonce,
      deadline: args.deadline,
    },
  }
}

export function buildOperatorVaultOptInTypedData(args: {
  chainId: number
  verifyingContract: Address
  who: Address
  where: Address
  nonce: bigint
  deadline: bigint
}) {
  return {
    domain: {
      name: 'OperatorVaultOptInService',
      version: '1',
      chainId: args.chainId,
      verifyingContract: args.verifyingContract,
    },
    types: {
      OptIn: [
        { name: 'who', type: 'address' },
        { name: 'where', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint48' },
      ],
    },
    primaryType: 'OptIn' as const,
    message: {
      who: args.who,
      where: args.where,
      nonce: args.nonce,
      deadline: args.deadline,
    },
  }
}

export function buildOperatorVaultOptOutTypedData(args: {
  chainId: number
  verifyingContract: Address
  who: Address
  where: Address
  nonce: bigint
  deadline: bigint
}) {
  return {
    domain: {
      name: 'OperatorVaultOptInService',
      version: '1',
      chainId: args.chainId,
      verifyingContract: args.verifyingContract,
    },
    types: {
      OptOut: [
        { name: 'who', type: 'address' },
        { name: 'where', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint48' },
      ],
    },
    primaryType: 'OptOut' as const,
    message: {
      who: args.who,
      where: args.where,
      nonce: args.nonce,
      deadline: args.deadline,
    },
  }
}

