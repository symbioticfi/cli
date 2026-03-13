import prompts from 'prompts'

export async function confirmOrExit(args: { message: string; yes?: boolean }) {
  if (args.yes) return true

  const res = await prompts(
    {
      type: 'confirm',
      name: 'ok',
      message: args.message,
      initial: false,
    },
    {
      onCancel: () => true,
    },
  )

  const ok = Boolean(res.ok)
  if (!ok) {
    // Caller may return early, but keep a non-zero exit code to signal cancellation.
    process.exitCode = 1
    process.stdout.write('Cancel\n')
  }
  return ok
}
