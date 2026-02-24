import type { Abi } from 'viem'

import FullRestakeDelegatorJson from '../../abi/FullRestakeDelegatorABI.json'
import NetworkMiddlewareServiceJson from '../../abi/NetworkMiddlewareServiceABI.json'
import NetworkRegistryJson from '../../abi/NetworkRegistryABI.json'
import NetworkRestakeDelegatorJson from '../../abi/NetworkRestakeDelegatorABI.json'
import OperatorNetworkOptInServiceJson from '../../abi/OperatorNetworkOptInServiceABI.json'
import OperatorNetworkSpecificDelegatorJson from '../../abi/OperatorNetworkSpecificDelegatorABI.json'
import OperatorRegistryJson from '../../abi/OperatorRegistryABI.json'
import OperatorSpecificDelegatorJson from '../../abi/OperatorSpecificDelegatorABI.json'
import OperatorVaultOptInServiceJson from '../../abi/OperatorVaultOptInServiceABI.json'
import VaultFactoryJson from '../../abi/VaultFactoryABI.json'
import VaultJson from '../../abi/VaultABI.json'
import VaultTokenizedJson from '../../abi/VaultTokenizedABI.json'
import VetoSlasherJson from '../../abi/VetoSlasherABI.json'

// viem needs `Abi`-compatible shapes; JSON imports don’t keep literal types.
export const OperatorRegistryAbi = OperatorRegistryJson as unknown as Abi
export const NetworkRegistryAbi = NetworkRegistryJson as unknown as Abi
export const OperatorVaultOptInServiceAbi = OperatorVaultOptInServiceJson as unknown as Abi
export const OperatorNetworkOptInServiceAbi = OperatorNetworkOptInServiceJson as unknown as Abi
export const NetworkMiddlewareServiceAbi = NetworkMiddlewareServiceJson as unknown as Abi
export const VaultFactoryAbi = VaultFactoryJson as unknown as Abi
export const VaultAbi = VaultJson as unknown as Abi
export const VaultTokenizedAbi = VaultTokenizedJson as unknown as Abi

export const NetworkRestakeDelegatorAbi = NetworkRestakeDelegatorJson as unknown as Abi
export const FullRestakeDelegatorAbi = FullRestakeDelegatorJson as unknown as Abi
export const OperatorSpecificDelegatorAbi = OperatorSpecificDelegatorJson as unknown as Abi
export const OperatorNetworkSpecificDelegatorAbi = OperatorNetworkSpecificDelegatorJson as unknown as Abi

export const VetoSlasherAbi = VetoSlasherJson as unknown as Abi

export const AllKnownAbis = [
  OperatorRegistryAbi,
  NetworkRegistryAbi,
  OperatorVaultOptInServiceAbi,
  OperatorNetworkOptInServiceAbi,
  NetworkMiddlewareServiceAbi,
  VaultFactoryAbi,
  VaultAbi,
  VaultTokenizedAbi,
  NetworkRestakeDelegatorAbi,
  FullRestakeDelegatorAbi,
  OperatorSpecificDelegatorAbi,
  OperatorNetworkSpecificDelegatorAbi,
  VetoSlasherAbi,
] as const

