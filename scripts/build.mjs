// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Bundle the command line into one file for `npx`. Only this project's own
// source is bundled; dependencies stay external and are installed by npm, so
// their licences and versions remain visible in package.json.
import { build } from 'esbuild';
import { chmod, readFile } from 'node:fs/promises';

const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const outfile = new URL('../dist/qa-scan.mjs', import.meta.url).pathname;

await build({
  entryPoints: [new URL('../src/cli.ts', import.meta.url).pathname],
  outfile,
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
});
await chmod(outfile, 0o755);
