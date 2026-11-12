// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { lineAt, type RepoFile } from '../context';

/**
 * Read Firebase security rules and classify each grant.
 *
 *  open        no condition, or `if true`: anyone, signed in or not.
 *  test_mode   `if request.time < timestamp.date(...)`: anyone, until a date.
 *  auth_only   `if request.auth != null` alone: every signed-in user, on every
 *              document under the path — including other users' data.
 *
 * The scan is linear: one tokenizing pass with bounded patterns, and each
 * `allow` statement is consumed up to its `;` before scanning resumes.
 */

export type GrantKind = 'open' | 'test_mode' | 'auth_only';

export interface Grant {
  kind: GrantKind;
  /** The `match` path the grant sits under, e.g. /databases/{database}/documents/{document=**}. */
  path: string;
  /** Includes a recursive wildcard such as {document=**}: the grant covers everything below. */
  wildcard: boolean;
  write: boolean;
  read: boolean;
  file: string;
  /** 1-based line; 0 when the format gives no reliable position (JSON rules). */
  line: number;
}

const WRITE_OPS = new Set(['write', 'create', 'update', 'delete']);
const READ_OPS = new Set(['read', 'get', 'list']);

/**
 * Same length as the input, with comments and string contents blanked, so `;`
 * and `{` inside them are inert. One left-to-right pass: no pattern is retried
 * from many starting points, so crafted input cannot make it slow.
 */
export function blankRules(text: string): string {
  const out: string[] = [];
  let copyFrom = 0;
  const blank = (from: number, to: number) => {
    out.push(text.slice(copyFrom, from), text.slice(from, to).replace(/[^\n]/g, ' '));
    copyFrom = to;
  };
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i);
      const to = end === -1 ? text.length : end;
      blank(i, to);
      i = to;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const to = end === -1 ? text.length : end + 2;
      blank(i, to);
      i = to;
    } else if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== c && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1;
      const to = Math.min(j, text.length);
      // Keep the quotes, blank what is between them.
      blank(i + 1, to);
      i = to + 1;
    } else {
      i++;
    }
  }
  out.push(text.slice(copyFrom));
  return out.join('');
}

function classify(condition: string): GrantKind | undefined {
  const c = condition.replace(/\s+/g, ' ').trim();
  if (c === '' || /^\(* ?true ?\)*$/.test(c)) return 'open';
  if (/request\.time ?< ?timestamp\.date ?\(/.test(c) && !/request\.auth/.test(c)) return 'test_mode';
  if (/^\(? ?request\.auth(?:\.uid)? ?!= ?null ?\)?$/.test(c)) return 'auth_only';
  return undefined;
}

/**
 * A match path is a series of `/segment` parts, where a segment is a literal
 * or a `{variable}` / `{variable=**}` capture. The captures contain braces, so
 * the path must be read segment by segment: reading up to the first `{` would
 * take `{database}` for the opening of the block.
 */
const MATCH_PATH = String.raw`(?:\/(?:\{[A-Za-z_]\w{0,63}(?:=\*\*)?\}|[^\s{}\/]{1,128})){1,32}`;
const TOKEN = new RegExp(
  String.raw`\bmatch\s{1,64}(${MATCH_PATH})\s{0,64}\{|\bfunction\b[^{;]{0,600}\{|\ballow\b|\{|\}`,
  'g',
);

export function scanRulesFile(file: RepoFile): Grant[] {
  const src = blankRules(file.text);
  const grants: Grant[] = [];
  const stack: Array<string | null> = [];

  TOKEN.lastIndex = 0;
  for (let m = TOKEN.exec(src); m; m = TOKEN.exec(src)) {
    const tok = m[0];
    if (tok === '}') {
      stack.pop();
    } else if (tok === '{' || tok.startsWith('function')) {
      stack.push(null);
    } else if (tok === 'allow') {
      const end = src.indexOf(';', TOKEN.lastIndex);
      if (end === -1) break;
      const body = src.slice(TOKEN.lastIndex, end);
      TOKEN.lastIndex = end + 1;

      const colon = body.indexOf(':');
      const ops = (colon === -1 ? body : body.slice(0, colon)).split(/[\s,]+/).filter(Boolean);
      const condition = colon === -1 ? '' : body.slice(colon + 1).replace(/^\s*if\b/, '');
      const kind = classify(condition);
      if (!kind) continue;

      const segments = stack.filter((s): s is string => s !== null);
      grants.push({
        kind,
        path: segments.join('') || '/',
        wildcard: segments.some((s) => s.includes('=**}')),
        write: ops.some((op) => WRITE_OPS.has(op)),
        read: ops.some((op) => READ_OPS.has(op)),
        file: file.path,
        line: lineAt(file.text, m.index),
      });
    } else {
      stack.push(m[1] ?? null);
    }
  }
  return grants;
}

const MAX_NODES = 10_000;

/** Realtime Database rules (database.rules.json). Returns undefined when the file cannot be parsed. */
export function scanDatabaseRules(file: RepoFile): Grant[] | undefined {
  let doc: unknown;
  try {
    doc = JSON.parse(file.text);
  } catch {
    try {
      // The Firebase CLI accepts // comments in this file.
      doc = JSON.parse(file.text.replace(/^\s*\/\/.*$/gm, ''));
    } catch {
      return undefined;
    }
  }
  const rules = typeof doc === 'object' && doc !== null ? (doc as Record<string, unknown>).rules : undefined;
  if (typeof rules !== 'object' || rules === null) return [];

  const grants: Grant[] = [];
  let visited = 0;
  const walk = (node: Record<string, unknown>, path: string[]) => {
    if (++visited > MAX_NODES || path.length > 32) return;
    for (const [key, value] of Object.entries(node)) {
      if (key === '.read' || key === '.write') {
        const condition = value === true ? 'true' : typeof value === 'string' ? value : undefined;
        if (condition === undefined) continue;
        const kind = classify(condition.replace(/\bauth\b/g, 'request.auth'));
        if (!kind) continue;
        grants.push({
          kind,
          path: `/${path.join('/')}`,
          // At the root, or under nothing but $wildcards: the grant covers every record.
          wildcard: path.every((segment) => segment.startsWith('$')),
          write: key === '.write',
          read: key === '.read',
          file: file.path,
          line: 0,
        });
      } else if (typeof value === 'object' && value !== null) {
        walk(value as Record<string, unknown>, [...path, key]);
      }
    }
  };
  walk(rules as Record<string, unknown>, []);
  return grants;
}
