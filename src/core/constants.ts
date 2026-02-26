import { zeroAddress } from 'viem'

export const ZERO_ADDRESS = zeroAddress

// Current on-chain subnetwork IDs used by Symbiotic.
export const SUBNETWORK_IDS = [0, 1] as const

export const DELEGATOR_TYPES_NAMES: Record<number, string> = {
  0: 'NetworkRestake',
  1: 'FullRestake',
  2: 'OperatorSpecific',
  3: 'OperatorNetworkSpecific',
} as const

export const SLASHER_TYPES_NAMES: Record<number, string> = {
  [-1]: 'NonSlashable',
  0: 'InstantSlasher',
  1: 'VetoSlasher',
} as const
