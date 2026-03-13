export type OutputMode = {
  json: boolean
  quiet: boolean
}

function jsonReplacer(_key: string, value: unknown) {
  if (typeof value === 'bigint') return value.toString()
  if (value instanceof Map) return Object.fromEntries(value.entries())
  return value
}

export function printJson(value: unknown) {
  process.stdout.write(`${JSON.stringify(value, jsonReplacer, 2)}\n`)
}

export function printLine(line = '') {
  process.stdout.write(`${line}\n`)
}

export function printIndented(line: string, indent = 2) {
  printLine(`${' '.repeat(indent)}${line}`)
}
