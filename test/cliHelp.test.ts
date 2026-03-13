import { describe, expect, it } from 'vitest'
import type { Command } from 'commander'

import { createProgram } from '../src/cli/program'

function findCommand(root: Command, path: string[]) {
  let current: Command | undefined = root
  for (const segment of path) {
    current = current?.commands.find((command) => command.name() === segment)
  }
  return current
}

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
    expect(rewardsHelp).toMatch(/\n\s+vault-snapshot-rewards\b/)
    expect(rewardsHelp).toMatch(/\n\s+operator-fees\b/)
    expect(rewardsHelp).not.toMatch(/\n\s+rewards-protocol-fee\b/)
  })

  it('subcommand help works for commands with bigint defaults', () => {
    const program = createProgram()

    const commandPaths = [
      ['net', 'set-resolver'],
      ['op', 'opt-in-vault-sig'],
      ['vault', 'set-network-limit'],
      ['rewards', 'vault-snapshot-rewards'],
      ['rewards', 'claim-vault-snapshot-rewards'],
    ]

    for (const path of commandPaths) {
      const command = findCommand(program, path)
      expect(command, `missing command: ${path.join(' ')}`).toBeTruthy()
      expect(() => command!.helpInformation()).not.toThrow()
    }
  })
})
