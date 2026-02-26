import type { Abi, Address, Chain, Hash, PublicClient, Transport, WalletClient } from 'viem'
import { createWalletClient } from 'viem'
import type { Account } from 'viem/accounts'
import ora from 'ora'

import { createViemTransport, type ResolvedClientConfig } from './client'
import { printJson, printLine, type OutputMode } from './output'

export function createWalletClientForAccount(resolved: ResolvedClientConfig, account: Account): WalletClient<Transport, Chain, Account> {
  return createWalletClient({
    chain: resolved.viemChain,
    transport: createViemTransport(resolved),
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

export async function runWriteTx(args: {
  mode: OutputMode
  resolved: ResolvedClientConfig
  publicClient: PublicClient<Transport, Chain>
  account: Account
  abi: Abi
  address: Address
  functionName: string
  args?: readonly unknown[]
  dryRun?: boolean
  successMessage?: string
}): Promise<Hash | undefined> {
  const canSpin = !args.mode.json && !args.mode.quiet

  const walletClient = createWalletClientForAccount(args.resolved, args.account)
  const simulateLabel = canSpin ? ora('Simulating...').start() : undefined
  const request = await simulateWriteRequest({
    publicClient: args.publicClient,
    account: args.account,
    abi: args.abi,
    address: args.address,
    functionName: args.functionName,
    args: args.args,
  })
  simulateLabel?.stop()

  if (args.dryRun) {
    if (args.mode.json) printJson({ dryRun: true })
    else printLine('Simulated successfully.')
    return undefined
  }

  const hash = await sendWriteRequest({ walletClient, request })

  if (args.mode.json) {
    await args.publicClient.waitForTransactionReceipt({ hash })
    printJson({ hash })
    return hash
  }

  if (canSpin) {
    printLine(`Transaction sent: ${hash}`)
    const spinner = ora('Waiting for transaction receipt...').start()
    await args.publicClient.waitForTransactionReceipt({ hash })
    spinner.stop()
  } else {
    printLine(`Transaction sent: ${hash}, waiting...`)
    await args.publicClient.waitForTransactionReceipt({ hash })
  }

  if (args.successMessage) printLine(args.successMessage)
  return hash
}
