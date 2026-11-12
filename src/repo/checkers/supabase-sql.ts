// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { RepoFile } from '../context';

/**
 * Replay a project's SQL migrations far enough to answer two questions per
 * table in the `public` schema (the one Supabase exposes through its API):
 * is row-level security enabled at the end, and which policies remain?
 *
 * This is not a SQL parser. It reads only the statements that matter for
 * those questions and is conservative where it cannot tell: anything it does
 * not understand is left alone, never reported.
 *
 * All work is linear in the input: comments, string literals and
 * dollar-quoted function bodies are blanked by a single scan before any
 * pattern runs, and every pattern is anchored to the start of one statement.
 */

export interface TableState {
  schema: string;
  name: string;
  rls: boolean;
  file: string;
  line: number;
}

export type PolicyCommand = 'all' | 'select' | 'insert' | 'update' | 'delete';

export interface PolicyState {
  table: string;
  name: string;
  command: PolicyCommand;
  restrictive: boolean;
  roles: string[];
  usingTrue: boolean;
  checkTrue: boolean;
  file: string;
  line: number;
}

export interface SqlReplay {
  tables: Map<string, TableState>;
  policies: Map<string, PolicyState>;
  /** Number of CREATE TABLE statements seen for the public schema. */
  tablesCreated: number;
  /**
   * RLS is switched somewhere this replay cannot follow: inside a function or
   * DO block (often via dynamic SQL), or the phrase appears in a comment. A
   * table that looks unprotected may then be protected, so the caller must not
   * report it as confirmed.
   */
  dynamicRls: boolean;
}

const MAX_STATEMENT = 20_000;

/**
 * Same length as the input, with comments, string literals and dollar-quoted
 * bodies replaced by spaces. Newlines are kept so offsets still map to lines.
 */
export function blankSql(sql: string): string {
  const out: string[] = [];
  const blank = (from: number, to: number) => out.push(sql.slice(from, to).replace(/[^\n]/g, ' '));
  const dollarTag = /\$([A-Za-z_][A-Za-z0-9_]*)?\$/y;
  let i = 0;
  let copyFrom = 0;
  const flush = (to: number) => {
    if (to > copyFrom) out.push(sql.slice(copyFrom, to));
  };

  while (i < sql.length) {
    const c = sql[i]!;
    const next = sql[i + 1];
    let end = -1;
    if (c === '-' && next === '-') {
      end = sql.indexOf('\n', i);
      if (end === -1) end = sql.length;
    } else if (c === '/' && next === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < sql.length && depth > 0) {
        if (sql[j] === '/' && sql[j + 1] === '*') {
          depth++;
          j += 2;
        } else if (sql[j] === '*' && sql[j + 1] === '/') {
          depth--;
          j += 2;
        } else j++;
      }
      end = j;
    } else if (c === "'") {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") j += 2;
          else break;
        } else j++;
      }
      end = Math.min(j + 1, sql.length);
    } else if (c === '$') {
      dollarTag.lastIndex = i;
      const m = dollarTag.exec(sql);
      if (m) {
        const close = sql.indexOf(m[0], i + m[0].length);
        end = close === -1 ? sql.length : close + m[0].length;
      }
    } else if (c === '"') {
      // Quoted identifiers are kept: table and policy names live in them.
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === '"') {
          if (sql[j + 1] === '"') j += 2;
          else break;
        } else j++;
      }
      i = Math.min(j + 1, sql.length);
      continue;
    }

    if (end === -1) {
      i++;
      continue;
    }
    flush(i);
    blank(i, end);
    i = end;
    copyFrom = end;
  }
  flush(sql.length);
  return out.join('');
}

const IDENT = String.raw`(?:"(?:[^"]|""){1,128}"|[A-Za-z_][A-Za-z0-9_$]{0,127})`;
const NAME = String.raw`(${IDENT})(?: ?\. ?(${IDENT}))?`;

const CREATE_TABLE = new RegExp(String.raw`^create (?:or replace )?(?:unlogged )?table (?:if not exists )?${NAME}`, 'i');
const CREATE_TEMP = /^create (?:(?:global |local )?(?:temporary|temp)) /i;
const ALTER_TABLE = new RegExp(String.raw`^alter table (?:if exists )?(?:only )?${NAME}(.*)$`, 'i');
const DROP_TABLE = /^drop table (?:if exists )?(.*)$/i;
const CREATE_POLICY = new RegExp(String.raw`^create policy (${IDENT}) on ${NAME}(.*)$`, 'i');
const ALTER_POLICY = new RegExp(String.raw`^alter policy (${IDENT}) on ${NAME}(.*)$`, 'i');
const DROP_POLICY = new RegExp(String.raw`^drop policy (?:if exists )?(${IDENT}) on ${NAME}`, 'i');

const RLS_TOGGLE = /\b(enable|disable) row level security\b/gi;
const RENAME_TO = new RegExp(String.raw`\brename to (${IDENT})`, 'i');
const USING_TRUE = /\busing ?\( ?(?:\( ?)?true(?: ?\))? ?\)/i;
const CHECK_TRUE = /\bwith check ?\( ?(?:\( ?)?true(?: ?\))? ?\)/i;
const HAS_USING = /\busing ?\(/i;
const HAS_CHECK = /\bwith check ?\(/i;
const COMMAND = /\bfor (all|select|insert|update|delete)\b/i;
const ROLES = /\bto (.{1,300}?)(?= using\b| with check\b|$)/i;

/** Postgres folds unquoted identifiers to lower case. */
function ident(raw: string): string {
  return raw.startsWith('"') ? raw.slice(1, -1).replace(/""/g, '"') : raw.toLowerCase();
}

function qualified(first: string, second: string | undefined): { schema: string; name: string } {
  return second === undefined ? { schema: 'public', name: ident(first) } : { schema: ident(first), name: ident(second) };
}

const tableKey = (schema: string, name: string) => `${schema}.${name}`;

/** Statements of one blanked file with their 1-based starting line. */
function statements(blanked: string): Array<{ text: string; line: number }> {
  const result: Array<{ text: string; line: number }> = [];
  let start = 0;
  let line = 1;
  let startLine = 1;
  for (let i = 0; i <= blanked.length; i++) {
    const c = blanked[i];
    if (i === blanked.length || c === ';') {
      const raw = blanked.slice(start, i);
      const lead = raw.length - raw.trimStart().length;
      const text = raw.trim();
      if (text) {
        const leadingLines = raw.slice(0, lead).split('\n').length - 1;
        result.push({ text: text.slice(0, MAX_STATEMENT).replace(/\s+/g, ' '), line: startLine + leadingLines });
      }
      start = i + 1;
      startLine = line;
    } else if (c === '\n') {
      line++;
    }
  }
  return result;
}

function parsePolicyClauses(rest: string): Pick<PolicyState, 'command' | 'restrictive' | 'roles' | 'usingTrue' | 'checkTrue'> {
  const roles = ROLES.exec(rest)?.[1]
    ?.split(',')
    .map((r) => ident(r.trim()))
    .filter(Boolean) ?? ['public'];
  return {
    command: (COMMAND.exec(rest)?.[1]?.toLowerCase() as PolicyCommand | undefined) ?? 'all',
    restrictive: /\bas restrictive\b/i.test(rest),
    roles,
    usingTrue: USING_TRUE.test(rest),
    checkTrue: CHECK_TRUE.test(rest),
  };
}

/** Replay files in path order (migration files are named by timestamp). */
export function replaySql(files: RepoFile[]): SqlReplay {
  const tables = new Map<string, TableState>();
  const policies = new Map<string, PolicyState>();
  let tablesCreated = 0;
  let dynamicRls = false;
  const RLS_PHRASE = /row\s+level\s+security/gi;

  for (const file of files) {
    const blanked = blankSql(file.text);
    if ((file.text.match(RLS_PHRASE)?.length ?? 0) > (blanked.match(RLS_PHRASE)?.length ?? 0)) dynamicRls = true;
    for (const { text, line } of statements(blanked)) {
      let m: RegExpExecArray | null;

      if ((m = CREATE_TABLE.exec(text)) && !CREATE_TEMP.test(text)) {
        const { schema, name } = qualified(m[1]!, m[2]);
        if (schema !== 'public') continue;
        tablesCreated++;
        const key = tableKey(schema, name);
        if (!tables.has(key)) tables.set(key, { schema, name, rls: false, file: file.path, line });
        continue;
      }

      if ((m = ALTER_TABLE.exec(text))) {
        const target = qualified(m[1]!, m[2]);
        const key = tableKey(target.schema, target.name);
        const table = tables.get(key);
        if (!table) continue;
        const rest = m[3] ?? '';
        RLS_TOGGLE.lastIndex = 0;
        for (const toggle of rest.matchAll(RLS_TOGGLE)) table.rls = toggle[1]!.toLowerCase() === 'enable';
        const renamed = RENAME_TO.exec(rest);
        if (renamed && !/\brename column\b/i.test(rest)) {
          const newKey = tableKey(table.schema, ident(renamed[1]!));
          tables.delete(key);
          table.name = ident(renamed[1]!);
          tables.set(newKey, table);
          for (const [policyKey, policy] of [...policies]) {
            if (policy.table !== key) continue;
            policies.delete(policyKey);
            policy.table = newKey;
            policies.set(`${newKey}::${policy.name}`, policy);
          }
        }
        continue;
      }

      if ((m = DROP_TABLE.exec(text))) {
        for (const part of (m[1] ?? '').replace(/\b(?:cascade|restrict)\b/gi, '').split(',')) {
          const nm = new RegExp(String.raw`^\s*${NAME}\s*$`).exec(part);
          if (!nm) continue;
          const { schema, name } = qualified(nm[1]!, nm[2]);
          const key = tableKey(schema, name);
          tables.delete(key);
          for (const [policyKey, policy] of [...policies]) if (policy.table === key) policies.delete(policyKey);
        }
        continue;
      }

      if ((m = CREATE_POLICY.exec(text))) {
        const { schema, name } = qualified(m[2]!, m[3]);
        if (schema !== 'public') continue;
        const table = tableKey(schema, name);
        const policyName = ident(m[1]!);
        policies.set(`${table}::${policyName}`, {
          table,
          name: policyName,
          ...parsePolicyClauses(m[4] ?? ''),
          file: file.path,
          line,
        });
        continue;
      }

      if ((m = ALTER_POLICY.exec(text))) {
        const { schema, name } = qualified(m[2]!, m[3]);
        const table = tableKey(schema, name);
        const policyKey = `${table}::${ident(m[1]!)}`;
        const policy = policies.get(policyKey);
        if (!policy) continue;
        const rest = m[4] ?? '';
        const renamed = RENAME_TO.exec(rest);
        if (renamed) {
          policies.delete(policyKey);
          policy.name = ident(renamed[1]!);
          policies.set(`${table}::${policy.name}`, policy);
          continue;
        }
        if (HAS_USING.test(rest)) policy.usingTrue = USING_TRUE.test(rest);
        if (HAS_CHECK.test(rest)) policy.checkTrue = CHECK_TRUE.test(rest);
        if (ROLES.test(rest)) policy.roles = parsePolicyClauses(rest).roles;
        continue;
      }

      if ((m = DROP_POLICY.exec(text))) {
        const { schema, name } = qualified(m[2]!, m[3]);
        policies.delete(`${tableKey(schema, name)}::${ident(m[1]!)}`);
      }
    }
  }
  return { tables, policies, tablesCreated, dynamicRls };
}

/** Roles that only the server holds: a policy for them alone exposes nothing. */
const SERVER_ROLES = new Set(['service_role', 'postgres', 'supabase_admin']);

export type PolicyRisk = 'open_write' | 'open_insert' | 'open_read';

/**
 * How a remaining permissive policy exposes data, if at all.
 *
 * USING decides which existing rows a command may touch; WITH CHECK decides
 * what new rows may look like. `using (true)` on an update or delete therefore
 * hands every row to every holder of the role.
 */
export function policyRisk(policy: PolicyState): PolicyRisk | undefined {
  if (policy.restrictive) return undefined;
  if (policy.roles.length > 0 && policy.roles.every((r) => SERVER_ROLES.has(r))) return undefined;
  switch (policy.command) {
    case 'select':
      return policy.usingTrue ? 'open_read' : undefined;
    case 'insert':
      return policy.checkTrue ? 'open_insert' : undefined;
    case 'update':
    case 'delete':
      return policy.usingTrue ? 'open_write' : undefined;
    case 'all':
      return policy.usingTrue ? 'open_write' : policy.checkTrue ? 'open_insert' : undefined;
  }
}
