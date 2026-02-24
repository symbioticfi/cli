export async function runCliAction(fn: () => Promise<void>) {
  try {
    await fn()
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    process.stderr.write(`${message}\n`)
    process.exitCode = 1
  }
}

