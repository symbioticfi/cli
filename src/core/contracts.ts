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
import CuratorRegistryJson from '../../abi/CuratorRegistryABI.json'
import FeeRegistryJson from '../../abi/FeeRegistryABI.json'
import ProtocolFeesJson from '../../abi/ProtocolFeesABI.json'
import VaultSnapshotRewardsJson from '../../abi/VaultSnapshotRewardsABI.json'
import CumulativeMerkleRewardsJson from '../../abi/CumulativeMerkleRewardsABI.json'
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
export const OperatorNetworkSpecificDelegatorAbi =
  OperatorNetworkSpecificDelegatorJson as unknown as Abi

export const VetoSlasherAbi = VetoSlasherJson as unknown as Abi

// Rewards
export const CuratorRegistryAbi = CuratorRegistryJson as unknown as Abi
export const FeeRegistryAbi = FeeRegistryJson as unknown as Abi
export const ProtocolFeesAbi = ProtocolFeesJson as unknown as Abi
export const VaultSnapshotRewardsAbi = VaultSnapshotRewardsJson as unknown as Abi
export const CumulativeMerkleRewardsAbi = CumulativeMerkleRewardsJson as unknown as Abi

export function delegatorAbiByType(type: bigint): Abi {
  if (type === 0n) return NetworkRestakeDelegatorAbi
  if (type === 1n) return FullRestakeDelegatorAbi
  if (type === 2n) return OperatorSpecificDelegatorAbi
  if (type === 3n) return OperatorNetworkSpecificDelegatorAbi
  return NetworkRestakeDelegatorAbi
}
