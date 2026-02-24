import { zeroAddress } from 'viem'

export const ZERO_ADDRESS = zeroAddress

// Keep parity with symb.py (TODO: generalize subnetworks).
export const SUBNETWORK_IDS = [0, 1] as const

export type DelegatorEntityKey =
  | 'network_restake_delegator'
  | 'full_restake_delegator'
  | 'operator_specific_delegator'
  | 'operator_network_specific_delegator'

export const DELEGATOR_TYPES_ENTITIES: Record<number, DelegatorEntityKey> = {
  0: 'network_restake_delegator',
  1: 'full_restake_delegator',
  2: 'operator_specific_delegator',
  3: 'operator_network_specific_delegator',
} as const

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
