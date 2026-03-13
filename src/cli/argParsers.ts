import { Argument, InvalidArgumentError } from 'commander'

import {
  parseAddress,
  parseBytes32Hex,
  parseHex,
  parseUint48,
  parseUint96,
  parseUint256,
} from './parse'

function wrapParser<T>(fn: (value: string) => T): (value: string) => T {
  return (value: string) => {
    try {
      return fn(value)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      throw new InvalidArgumentError(message)
    }
  }
}

export function defaultedArg<T>(
  flags: string,
  description: string,
  parser: (value: string) => T,
  defaultValue: T,
  defaultValueDescription = String(defaultValue),
) {
  return new Argument(flags, description)
    .argParser(parser)
    .default(defaultValue, defaultValueDescription)
}

export const parseAddressArg = wrapParser(parseAddress)
export const parseUint256Arg = wrapParser(parseUint256)
export const parseUint96Arg = wrapParser(parseUint96)
export const parseUint48Arg = wrapParser(parseUint48)
export const parseBytes32HexArg = wrapParser(parseBytes32Hex)
export const parseHexArg = wrapParser(parseHex)
