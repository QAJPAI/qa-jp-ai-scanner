// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { baseName, dirName, type RepoContext } from './context';

/**
 * A minimal .gitignore matcher, used only to decide whether an env file would
 * be committed. It supports what env-file rules use in practice: `*`, `?`,
 * `**`, leading `/`, trailing `/`, `!` negation and per-directory files.
 * It does not run git and does not know what was committed in the past.
 */

interface Rule {
  /** Directory the pattern is relative to ('' for the root). */
  base: string;
  regex: RegExp;
  negate: boolean;
}

const MAX_RULES = 2000;
const MAX_PATTERN = 512;

function escapeRegex(char: string): string {
  return /[.+^${}()|[\]\\]/.test(char) ? `\\${char}` : char;
}

function globToRegex(glob: string): string {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        const atStart = i === 0;
        const slashAfter = glob[i + 2] === '/';
        if (slashAfter) {
          out += atStart || glob[i - 1] === '/' ? '(?:[^/]*/)*' : '[^/]*/';
          i += 2;
        } else {
          out += '.*';
          i += 1;
        }
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if (c === '\\' && i + 1 < glob.length) {
      out += escapeRegex(glob[++i]!);
    } else {
      out += escapeRegex(c);
    }
  }
  return out;
}

export function parseIgnoreFile(base: string, text: string): Rule[] {
  const rules: Rule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    if (rules.length >= MAX_RULES) break;
    let line = raw.replace(/(?<!\\)\s+$/, '');
    if (!line || line.startsWith('#') || line.length > MAX_PATTERN) continue;
    let negate = false;
    if (line.startsWith('!')) {
      negate = true;
      line = line.slice(1);
    }
    const dirOnly = line.endsWith('/');
    if (dirOnly) line = line.slice(0, -1);
    const anchored = line.includes('/');
    if (line.startsWith('/')) line = line.slice(1);
    if (!line) continue;

    const body = globToRegex(line);
    const prefix = anchored ? '^' : '^(?:[^/]*/)*';
    // A directory pattern matches what is inside it; a plain pattern matches the path or anything under it.
    const suffix = dirOnly ? '/.*$' : '(?:/.*)?$';
    rules.push({ base, regex: new RegExp(prefix + body + suffix), negate });
  }
  return rules;
}

export interface IgnoreMatcher {
  isIgnored(path: string): boolean;
}

/** Build a matcher from every .gitignore in the project, plus .git/info/exclude. */
export function ignoreMatcher(ctx: RepoContext): IgnoreMatcher {
  const sources = ctx.files
    .filter((f) => baseName(f.path) === '.gitignore')
    .map((f) => ({ base: dirName(f.path), text: f.text }))
    // Shallower files first: a deeper .gitignore takes precedence.
    .sort((a, b) => a.base.split('/').length - b.base.split('/').length || (a.base < b.base ? -1 : 1));

  const rules: Rule[] = [];
  if (ctx.gitExclude) rules.push(...parseIgnoreFile('', ctx.gitExclude));
  for (const source of sources) rules.push(...parseIgnoreFile(source.base, source.text));

  return {
    isIgnored(path: string): boolean {
      let ignored = false;
      for (const rule of rules) {
        let relative: string;
        if (rule.base === '') relative = path;
        else if (path.startsWith(`${rule.base}/`)) relative = path.slice(rule.base.length + 1);
        else continue;
        if (rule.regex.test(relative)) ignored = !rule.negate;
      }
      return ignored;
    },
  };
}
