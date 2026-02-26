import type { Abi, Address, Chain, Hash, PublicClient, Transport, WalletClient } from 'viem'
import { createWalletClient } from 'viem'
import type { Account } from 'viem/accounts'
import ora from 'ora'

import { createViemTransport, type ResolvedClientConfig } from './client'
import { confirmOrExit } from './confirm'
import { printJson, printLine, type OutputMode } from './output'
import { canUseSpinner } from './spinner'

export function createWalletClientForAccount(
  resolved: ResolvedClientConfig,
  account: Account,
): WalletClient<Transport, Chain, Account> {
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
  yes?: boolean
  confirmMessage?: string
  successMessage?: string
}): Promise<Hash | undefined> {
  const canSpin = canUseSpinner(args.mode)

  const renderArg = (value: unknown) => {
    if (typeof value === 'bigint') return value.toString()
    if (typeof value === 'string') return value
    if (value === null || value === undefined) return String(value)
    if (typeof value === 'number' || typeof value === 'boolean') return String(value)
    try {
      return JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))
    } catch {
      return String(value)
    }
  }

  const defaultConfirmMessage = () => {
    const renderedArgs = (args.args ?? []).map(renderArg).join(', ')
    const call = `${args.functionName}(${renderedArgs})`
    return `Send transaction on chainId=${args.resolved.chainId}: ${call} -> ${args.address}?`
  }

  const walletClient = createWalletClientForAccount(args.resolved, args.account)
  const simulateLabel = canSpin ? ora('Simulating...').start() : undefined
  let request: any
  try {
    request = await simulateWriteRequest({
      publicClient: args.publicClient,
      account: args.account,
      abi: args.abi,
      address: args.address,
      functionName: args.functionName,
      args: args.args,
    })
  } finally {
    simulateLabel?.stop()
  }

  if (args.dryRun) {
    if (args.mode.json) printJson({ dryRun: true })
    else printLine('Simulated successfully.')
    return undefined
  }

  if (!args.yes) {
    // Avoid breaking machine-readable output with interactive prompts.
    if (args.mode.json) {
      throw new Error('Write confirmation is required. Re-run with --yes when using --json.')
    }
    if (!process.stdin.isTTY) {
      throw new Error(
        'Write confirmation is required. Re-run with --yes in non-interactive environments.',
      )
    }

    const ok = await confirmOrExit({
      yes: args.yes,
      message: args.confirmMessage ?? defaultConfirmMessage(),
    })
    if (!ok) return undefined
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
    try {
      await args.publicClient.waitForTransactionReceipt({ hash })
    } finally {
      spinner.stop()
    }
  } else {
    printLine(`Transaction sent: ${hash}, waiting...`)
    await args.publicClient.waitForTransactionReceipt({ hash })
  }

  if (args.successMessage) printLine(args.successMessage)
  return hash
}
