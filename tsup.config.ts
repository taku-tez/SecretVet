import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      'index': 'src/index.ts',
      'cli': 'src/cli.ts',
    },
    format: ['esm'],
    dts: true,
    clean: true,
    sourcemap: true,
    target: 'node18',
    outDir: 'dist',
    splitting: false,
    shims: true,
  },
  {
    entry: {
      'test/scanner.test': 'test/scanner.test.ts',
      'test/entropy.test': 'test/entropy.test.ts',
      'test/rules.test': 'test/rules.test.ts',
    },
    format: ['esm'],
    dts: false,
    sourcemap: true,
    target: 'node18',
    outDir: 'dist',
    splitting: false,
    shims: true,
    external: ['node:test', 'node:assert', 'node:assert/strict', 'node:path', 'node:url', 'node:fs'],
  },
]);
