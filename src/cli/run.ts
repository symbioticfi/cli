export async function runCliAction(fn: () => Promise<void>) {
  try {
    await fn()
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    if (process.env.SYMB_DEBUG_STACK && err instanceof Error && err.stack) {
      process.stderr.write(`${err.stack}\n`)
    } else {
      process.stderr.write(`${message}\n`)
    }
    process.exitCode = 1
  }
}
