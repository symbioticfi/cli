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
    process.stdout.write('Cancel\n')
  }
  return ok
}

