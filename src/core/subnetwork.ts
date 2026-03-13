import { getAddress, padHex, toHex, type Address, type Hex, size } from 'viem'

const MAX_UINT96 = (1n << 96n) - 1n

export function encodeSubnetwork(args: { net: Address; subnetId: bigint | number }): Hex {
  const net = getAddress(args.net)
  const subnetId = typeof args.subnetId === 'number' ? BigInt(args.subnetId) : args.subnetId
  if (subnetId < 0n || subnetId > MAX_UINT96) {
    throw new Error(`subnetId out of range for uint96: ${subnetId}`)
  }

  const subnetHex = padHex(toHex(subnetId), { size: 12 })
  const subnetwork = `${net}${subnetHex.slice(2)}` as Hex
  if (size(subnetwork) !== 32) throw new Error(`Invalid subnetwork encoding: ${subnetwork}`)
  return subnetwork
}

export function decodeSubnetwork(subnetwork: Hex): { net: Address; subnetId: bigint } {
  if (size(subnetwork) !== 32) throw new Error(`Expected bytes32 subnetwork, got: ${subnetwork}`)
  const raw = subnetwork.slice(2)
  const net = getAddress(`0x${raw.slice(0, 40)}`)
  const subnetId = BigInt(`0x${raw.slice(40)}`)
  return { net, subnetId }
}
