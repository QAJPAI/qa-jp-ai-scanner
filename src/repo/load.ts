// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { constants } from 'node:fs';
import { open, readdir, realpath, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { RepoContext, RepoFile, RepoLoadStats } from './context';

/**
 * Read a project folder into memory for the repo-layer checkers.
 *
 * Safety:
 * - Symbolic links are never followed (they could lead outside the project,
 *   e.g. to a home directory). Files are opened with O_NOFOLLOW as well.
 * - Per-file size, file count, total size and depth are capped; everything
 *   skipped for that reason is counted, so coverage can say so.
 * - Nothing is executed and nothing is sent anywhere.
 */

export interface LoadOptions {
  name?: string;
  maxFileBytes?: number;
  maxFiles?: number;
  maxTotalBytes?: number;
  maxDepth?: number;
}

const DEFAULTS = {
  maxFileBytes: 1024 * 1024,
  maxFiles: 5000,
  maxTotalBytes: 64 * 1024 * 1024,
  maxDepth: 32,
};

/** Generated, vendored or tool-owned directories: not the project's own code. */
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt', '.output', '.svelte-kit',
  '.vercel', '.netlify', '.turbo', '.cache', '.parcel-cache', '.expo', '.firebase', '.wrangler', '.terraform',
  'coverage', 'vendor', '.venv', 'venv', '__pycache__', 'target', '.idea', '.vscode',
]);

/** Large generated files whose content is checksums, not code. */
const LOCKFILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock', 'composer.lock', 'Cargo.lock',
  'poetry.lock', 'Gemfile.lock', 'Pipfile.lock', 'go.sum',
]);

const BINARY_EXT =
  /\.(?:png|jpe?g|gif|webp|avif|ico|bmp|tiff?|psd|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|woff2?|ttf|otf|eot|mp[34]|m4a|wav|ogg|webm|mov|avi|wasm|so|dylib|dll|exe|bin|class|pyc|sqlite3?|db)$/i;

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

function emptyStats(): RepoLoadStats {
  return { filesRead: 0, tooLarge: 0, overLimit: 0, unreadable: 0, symlinksSkipped: 0, binary: 0 };
}

async function readCapped(path: string, maxBytes: number): Promise<Buffer | 'too_large' | 'not_a_file'> {
  const handle = await open(path, constants.O_RDONLY | O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile()) return 'not_a_file';
    if (info.size > maxBytes) return 'too_large';
    const buffer = Buffer.alloc(info.size);
    const { bytesRead } = await handle.read(buffer, 0, info.size, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

function collectDependencies(file: RepoFile, into: Set<string>): void {
  try {
    const pkg: unknown = JSON.parse(file.text);
    if (typeof pkg !== 'object' || pkg === null) return;
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      const deps = (pkg as Record<string, unknown>)[field];
      if (typeof deps === 'object' && deps !== null) for (const name of Object.keys(deps)) into.add(name);
    }
  } catch {
    // not valid JSON: nothing to collect
  }
}

export async function loadRepo(rootInput: string, options: LoadOptions = {}): Promise<RepoContext> {
  const limits = { ...DEFAULTS, ...options };
  const root = await realpath(rootInput);
  if (!(await stat(root)).isDirectory()) throw new Error('The path is not a folder');

  const load = emptyStats();
  const files: RepoFile[] = [];
  const dirs = new Set<string>(['']);
  let totalBytes = 0;

  const stack: Array<{ rel: string; depth: number }> = [{ rel: '', depth: 0 }];
  while (stack.length > 0) {
    const { rel, depth } = stack.pop()!;
    let entries;
    try {
      entries = await readdir(rel ? join(root, ...rel.split('/')) : root, { withFileTypes: true });
    } catch {
      load.unreadable++;
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const entry of entries) {
      const path = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        load.symlinksSkipped++;
        continue;
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (depth + 1 > limits.maxDepth) {
          load.overLimit++;
          continue;
        }
        dirs.add(path);
        stack.push({ rel: path, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      if (LOCKFILES.has(entry.name)) continue;
      if (BINARY_EXT.test(entry.name)) {
        load.binary++;
        continue;
      }
      if (files.length >= limits.maxFiles) {
        load.overLimit++;
        continue;
      }

      let content: Awaited<ReturnType<typeof readCapped>>;
      try {
        content = await readCapped(join(root, ...path.split('/')), limits.maxFileBytes);
      } catch {
        load.unreadable++;
        continue;
      }
      if (content === 'not_a_file') continue;
      if (content === 'too_large') {
        load.tooLarge++;
        continue;
      }
      if (totalBytes + content.length > limits.maxTotalBytes) {
        load.overLimit++;
        continue;
      }
      if (content.subarray(0, 8000).includes(0)) {
        load.binary++;
        continue;
      }
      totalBytes += content.length;
      files.push({ path, text: content.toString('utf8') });
      load.filesRead++;
    }
  }

  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const dependencies = new Set<string>();
  for (const file of files) if (file.path === 'package.json' || file.path.endsWith('/package.json')) collectDependencies(file, dependencies);

  let gitExclude: string | undefined;
  try {
    const exclude = await readCapped(join(root, '.git', 'info', 'exclude'), 64 * 1024);
    if (Buffer.isBuffer(exclude)) gitExclude = exclude.toString('utf8');
  } catch {
    // no git metadata
  }

  return {
    name: options.name ?? basename(root),
    files,
    byPath: new Map(files.map((f) => [f.path, f])),
    dirs,
    dependencies,
    gitExclude,
    load,
  };
}
