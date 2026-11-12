// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later

/** One text file of the project, by its path relative to the project root (always "/"-separated). */
export interface RepoFile {
  path: string;
  text: string;
}

/**
 * What was and was not read. Anything counted here except `binary` means part
 * of the project was not examined, and a checker that reads files must say so.
 */
export interface RepoLoadStats {
  filesRead: number;
  /** Larger than the per-file cap. */
  tooLarge: number;
  /** Beyond the file-count, total-size or depth cap. */
  overLimit: number;
  /** Could not be opened or read. */
  unreadable: number;
  /** Symbolic links are never followed: they may point outside the project. */
  symlinksSkipped: number;
  /** Images, archives, fonts and other non-text files. Not counted as unread. */
  binary: number;
}

export const everythingReadInRepo = (load: RepoLoadStats): boolean =>
  load.tooLarge === 0 && load.overLimit === 0 && load.unreadable === 0 && load.symlinksSkipped === 0;

/** Everything a repo-layer checker may look at. No checker touches the file system itself. */
export interface RepoContext {
  /** Display name of the project (folder name). Never an absolute path. */
  name: string;
  /** Text files, sorted by path. */
  files: RepoFile[];
  byPath: Map<string, RepoFile>;
  /** Every directory walked, relative to the root. */
  dirs: Set<string>;
  /** Package names from every package.json (dependencies and devDependencies). */
  dependencies: Set<string>;
  /** Contents of .git/info/exclude, if present. */
  gitExclude?: string;
  load: RepoLoadStats;
}

export const baseName = (path: string): string => path.slice(path.lastIndexOf('/') + 1);

const TEST_DIR = /(?:^|\/)(?:test|tests|__tests__|spec|specs|fixtures?|__fixtures__|__mocks__|e2e|cypress|playwright|evals?|benchmarks?)\//i;
const TEST_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$/i;

/** Tests and their fixtures: not shipped, often full of deliberately bad examples. */
export const isTestPath = (path: string): boolean => TEST_DIR.test(path) || TEST_FILE.test(path);

const SIGNAL_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?|json|toml|ya?ml)$|(?:^|\/)\.env(?:\..+)?$/i;

/** Files whose content says what the app itself uses: code and configuration, not tests or prose. */
export const isAppSignalFile = (path: string): boolean => SIGNAL_FILE.test(path) && !isTestPath(path);
export const dirName = (path: string): string => (path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');

/** 1-based line number of `index` in `text`. */
export function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) line++;
  return line;
}
