// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Bundle the command line into one file for `npx`, and the library entry for
// programs that use the engine (the url.jp.ai web service). Only this project's
// own source is bundled; dependencies stay external and are installed by npm,
// so their licences and versions remain visible in package.json. Type
// declarations for the library come from the TypeScript compiler.
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { chmod, readFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';

const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const outfile = new URL('../dist/qa-scan.mjs', import.meta.url).pathname;

const common = {
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  packages: 'external',
  minify: false,
  legalComments: 'inline',
  banner: {
    js: `// ${pkg.name} ${pkg.version} — Copyright (C) 2026 iQi — ${pkg.license}\n// Source: ${pkg.repository.url.replace(/^git\+/, '')}`,
  },
  logLevel: 'warning',
};

await rm(new URL('../dist/', import.meta.url), { recursive: true, force: true });
await build({ ...common, entryPoints: [new URL('../src/cli.ts', import.meta.url).pathname], outfile });
await chmod(outfile, 0o755);
await build({
  ...common,
  entryPoints: [new URL('../src/index.ts', import.meta.url).pathname],
  outfile: new URL('../dist/index.mjs', import.meta.url).pathname,
});

// Declarations: run the compiler this package depends on, not whatever is on PATH.
const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
execFileSync(process.execPath, [tsc, '-p', new URL('../tsconfig.build.json', import.meta.url).pathname], {
  stdio: 'inherit',
});
