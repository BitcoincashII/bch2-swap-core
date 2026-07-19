import { defineConfig } from 'tsup';

// Multi-entry build so each package export resolves to its own dist file (matches package.json exports).
// Deps in package.json (viem, @noble/*, @scure/*, buffer) are externalized automatically by tsup so
// consumers dedupe them; internal relative imports get bundled/resolved (fixes Node-ESM extensionless imports).
export default defineConfig({
  entry: [
    'src/index.ts',
    'src/swap-engine/index.ts',
    'src/order-book/index.ts',
    'src/htlc-builder.ts',
    'src/spv.ts',
    'src/seed-secret.ts',
    'src/address-codec.ts',
    'src/key-encryption.ts',
    'src/wallet-core.ts',
    'src/evm/contracts.ts',
  ],
  format: ['esm'],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: false,
  treeshake: true,
  target: 'node18',
});
