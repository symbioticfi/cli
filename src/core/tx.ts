import type { Abi, Address, Chain, Hash, PublicClient, Transport, WalletClient } from 'viem'
import { createWalletClient, http } from 'viem'
import type { Account } from 'viem/accounts'

import type { ResolvedClientConfig } from './client'

export function createWalletClientForAccount(resolved: ResolvedClientConfig, account: Account): WalletClient<Transport, Chain, Account> {
  return createWalletClient({
    chain: resolved.viemChain,
    transport: http(resolved.rpcUrl, {
      timeout: resolved.timeoutMs,
      retryCount: resolved.retries,
    }),
    account,
  })
}

export type SimulateWriteArgs = {
  publicClient: PublicClient<Transport, Chain>
  account: Account
  abi: Abi
  address: Address
  functionName: string
  args?: readonly unknown[]
}

export async function simulateWriteRequest(args: SimulateWriteArgs) {
  const { request } = await args.publicClient.simulateContract({
    address: args.address,
    abi: args.abi,
    functionName: args.functionName as any,
    args: args.args as any,
    account: args.account,
  })
  return request
}

export async function sendWriteRequest(args: {
  walletClient: WalletClient<Transport, Chain, Account>
  request: any
}): Promise<Hash> {
  return args.walletClient.writeContract(args.request)
}
