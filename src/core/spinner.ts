import ora, { type Ora } from 'ora'

import type { OutputMode } from './output'

export function canUseSpinner(mode: OutputMode) {
  return !mode.json && !mode.quiet && process.stdout.isTTY
}

export function startSpinner(mode: OutputMode, text: string): Ora | undefined {
  if (!canUseSpinner(mode)) return undefined
  return ora(text).start()
}

export async function withSpinner<T>(
  mode: OutputMode,
  text: string,
  fn: () => Promise<T>,
): Promise<T> {
  const spinner = startSpinner(mode, text)
  try {
    return await fn()
  } finally {
    spinner?.stop()
  }
}

