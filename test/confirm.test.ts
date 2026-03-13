import prompts from 'prompts'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { confirmOrExit } from '../src/core/confirm'

vi.mock('prompts', () => ({ default: vi.fn() }))

describe('confirmOrExit', () => {
  const promptsMock = vi.mocked(prompts)

  beforeEach(() => {
    promptsMock.mockReset()
    process.exitCode = undefined
  })

  it('bypasses prompt when yes=true', async () => {
    const ok = await confirmOrExit({ message: 'x', yes: true })
    expect(ok).toBe(true)
    expect(promptsMock).not.toHaveBeenCalled()
    expect(process.exitCode).toBeUndefined()
  })

  it('returns true when confirmed', async () => {
    promptsMock.mockResolvedValueOnce({ ok: true } as any)
    const ok = await confirmOrExit({ message: 'x' })
    expect(ok).toBe(true)
    expect(process.exitCode).toBeUndefined()
  })

  it('returns false, prints Cancel, and sets exitCode=1 when declined', async () => {
    promptsMock.mockResolvedValueOnce({ ok: false } as any)
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true as any)

    const ok = await confirmOrExit({ message: 'x' })
    expect(ok).toBe(false)
    expect(process.exitCode).toBe(1)
    expect(writeSpy).toHaveBeenCalledWith('Cancel\n')

    writeSpy.mockRestore()
  })
})
