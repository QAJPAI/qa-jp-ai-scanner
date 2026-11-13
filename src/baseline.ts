// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, writeSync, constants } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { Assessment } from './core/assessment';
import { validateAssessment } from './core/validate';

/**
 * The result a re-check is compared with ("baseline").
 *
 * It is kept in the user's cache folder, one file per project, and never in the
 * project itself: nothing is added to the code, nothing can be committed by
 * mistake, and the AI working in the project does not see it as a project file.
 *
 * It holds no secret values (records never do), but it names files and tables,
 * so it is readable by its owner only. A baseline that fails validation is
 * refused rather than repaired.
 */

const MAX_BASELINE_BYTES = 5 * 1024 * 1024;

export class BaselineError extends Error {
  constructor(
    readonly code: 'not_found' | 'invalid' | 'unsafe_location',
    message: string,
  ) {
    super(message);
    this.name = 'BaselineError';
  }
}

export interface BaselineEnv {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  home?: string;
}

/** The per-user folder for baselines. */
export function baselineDir({ platform = process.platform, env = process.env, home = homedir() }: BaselineEnv = {}): string {
  const base =
    platform === 'win32'
      ? (env.LOCALAPPDATA ?? join(home, 'AppData', 'Local'))
      : env.XDG_CACHE_HOME && env.XDG_CACHE_HOME.startsWith('/')
        ? env.XDG_CACHE_HOME
        : join(home, '.cache');
  return join(base, 'qa-jp-ai', 'baselines');
}

/** One file per project, named by a hash of its real path (the path itself is not written). */
export function baselinePath(projectRoot: string, options: BaselineEnv = {}): string {
  const id = createHash('sha256').update(realpathSync(projectRoot)).digest('hex').slice(0, 16);
  return join(baselineDir(options), `${id}.json`);
}

/** Create the folder for the owner only, and refuse a folder that is a link or not a folder. */
function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  const notMine = typeof process.getuid === 'function' && st.uid !== process.getuid();
  if (st.isSymbolicLink() || !st.isDirectory() || notMine) {
    throw new BaselineError('unsafe_location', 'The baseline folder is not a plain folder owned by this user');
  }
}

export function saveBaseline(projectRoot: string, assessment: Assessment, options: BaselineEnv = {}): string {
  const path = baselinePath(projectRoot, options);
  const dir = join(path, '..');
  ensureDir(dir);
  // Write to a new file, then rename: a reader never sees half a file, and an
  // existing link at the final name is replaced, not followed.
  const temp = join(dir, `.${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    writeSync(fd, JSON.stringify(assessment));
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    rmSync(temp, { force: true });
    throw err;
  }
  closeSync(fd);
  renameSync(temp, path);
  return path;
}

/** Read and validate a baseline file. Anything malformed is refused. */
export function readAssessmentFile(path: string): Assessment {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    throw new BaselineError('not_found', 'No earlier result was found');
  }
  if (st.isSymbolicLink() || !st.isFile()) throw new BaselineError('invalid', 'The earlier result is not a plain file');
  if (st.size > MAX_BASELINE_BYTES) throw new BaselineError('invalid', 'The earlier result is too large');

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new BaselineError('invalid', 'The earlier result is not valid JSON');
  }
  const errors = validateAssessment(parsed);
  if (errors.length > 0) throw new BaselineError('invalid', `The earlier result is malformed: ${errors[0]}`);
  return parsed as Assessment;
}

export function loadBaseline(projectRoot: string, options: BaselineEnv = {}): Assessment {
  return readAssessmentFile(baselinePath(projectRoot, options));
}
