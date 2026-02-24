import { z } from 'zod'

const envSchema = z.object({
  SYMB_RPC_URL: z.string().url().optional(),
  SYMB_ADDRESSES_JSON: z.string().optional(),
  SYMB_PRIVATE_KEY: z.string().optional(),
})

export type SymbEnv = z.infer<typeof envSchema>

export function readEnv(): SymbEnv {
  // Don’t throw on unrelated env vars.
  return envSchema.parse(process.env)
}

