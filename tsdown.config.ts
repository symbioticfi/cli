import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  outDir: 'dist',
  sourcemap: true,
  clean: true,
  dts: false,
  shims: false,
  fixedExtension: false,
  // Ledger transport uses native deps that should stay external.
  external: [
    '@ledgerhq/hw-app-eth',
    '@ledgerhq/hw-transport-node-hid',
    'node-hid',
    'usb',
    'keccak',
  ],
  banner: {
    js: '#!/usr/bin/env node',
  },
})
