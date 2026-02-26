import { describe, expect, it } from 'vitest'

import { createProgram } from '../src/cli/program'

describe('cli help', () => {
  it('root help only shows groups', () => {
    const program = createProgram()
    const help = program.helpInformation()

    for (const name of ['net', 'op', 'vault', 'staker', 'rewards']) {
      expect(help).toMatch(new RegExp(`\\n\\s+${name}\\b`))
    }

    // Spot-check: leaf commands should not show up in root help.
    for (const legacy of ['isnet', 'nets', 'ops', 'vaults', 'rewards-protocol-fee']) {
      expect(help).not.toMatch(new RegExp(`\\n\\s+${legacy}\\b`))
    }

    // Legacy commands should not be registered.
    const rootNames = new Set(program.commands.map((c) => c.name()))
    for (const legacy of ['isnet', 'nets', 'ops', 'vaults', 'rewards-protocol-fee']) {
      expect(rootNames.has(legacy)).toBe(false)
    }
  })

  it('group help is scoped', () => {
    const program = createProgram()
    const net = program.commands.find((c) => c.name() === 'net')
    expect(net).toBeTruthy()

    const netHelp = net!.helpInformation()
    expect(netHelp).toMatch(/\n\s+list(\||\s)/)
    expect(netHelp).toMatch(/\n\s+middleware\b/)
    expect(netHelp).toMatch(/\n\s+max-network-limit\b/)
    expect(netHelp).toMatch(/\n\s+resolver\b/)
    expect(netHelp).toMatch(/\n\s+pending-resolver\b/)
    expect(netHelp).not.toMatch(/\n\s+nets\b/)

    const vault = program.commands.find((c) => c.name() === 'vault')
    expect(vault).toBeTruthy()

    const vaultHelp = vault!.helpInformation()
    expect(vaultHelp).toMatch(/\n\s+network-limit\b/)
    expect(vaultHelp).not.toMatch(/\n\s+max-network-limit\b/)
    expect(vaultHelp).not.toMatch(/\n\s+resolver\b/)
    expect(vaultHelp).not.toMatch(/\n\s+pending-resolver\b/)

    const rewards = program.commands.find((c) => c.name() === 'rewards')
    expect(rewards).toBeTruthy()

    const rewardsHelp = rewards!.helpInformation()
    expect(rewardsHelp).toMatch(/\n\s+protocol-fee\b/)
    expect(rewardsHelp).not.toMatch(/\n\s+rewards-protocol-fee\b/)
  })
})
