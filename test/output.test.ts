import { describe, expect, it, vi } from 'vitest'

import { printJson } from '../src/core/output'

describe('output', () => {
  it('printJson stringifies bigint and Map values', () => {
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true as any)

    printJson({ a: 1n, m: new Map([['k', 2n]]) })

    expect(writeSpy).toHaveBeenCalledTimes(1)
    const out = String(writeSpy.mock.calls[0]?.[0] ?? '')
    const parsed = JSON.parse(out)
    expect(parsed).toEqual({ a: '1', m: { k: '2' } })

    writeSpy.mockRestore()
  })
})

