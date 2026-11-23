// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Names a site's own code gives to its Supabase tables and public storage
 * buckets.
 *
 * A site that talks to Supabase from the browser names what it reads in the
 * code every visitor receives: `.from("profiles")`,
 * `/storage/v1/object/public/id-cards/…`. Reading those names costs no
 * request, and turns "check your access rules" into "check the access rules
 * of profiles and messages".
 *
 * Names only. Nothing here says a table can be read or a bucket holds
 * anything: that would need a request to the database, which this layer does
 * not make (see baas-hint.ts).
 *
 * The text is from the site being checked. Each scan is a walk over the
 * occurrences of a fixed string, with a bounded look at what follows, and
 * the number of occurrences examined is capped.
 */

const MAX_OCCURRENCES = 5000;
const MAX_NAMES = 20;
/** PostgreSQL identifiers are at most 63 bytes; bucket names are kept to the same order of size. */
const MAX_TABLE_NAME = 63;
const MAX_BUCKET_NAME = 100;
const QUOTES = new Set(['"', "'", '`']);
const TABLE_CHAR = /[A-Za-z0-9_]/;
const BUCKET_CHAR = /[A-Za-z0-9_.-]/;
/** `X.from("text")` that is not a Supabase call: built-ins that take a string. */
const NOT_A_CLIENT = ['Array', 'Buffer', 'Uint8Array', 'String', 'Set'];

export interface SupabaseNames {
  /** Tables the code reads or writes, in order of first appearance. */
  tables: string[];
  /** Buckets the code uses as public: through the public object path or getPublicUrl(). */
  publicBuckets: string[];
  /** More occurrences or names than are collected. */
  limitHit: boolean;
}

/** The characters of `allowed` that start at `from`, up to `max` of them. */
function run(text: string, from: number, allowed: RegExp, max: number): string {
  let end = from;
  while (end < text.length && end - from <= max && allowed.test(text[end]!)) end++;
  return end - from > max ? '' : text.slice(from, end);
}

/** `("name")` starting at `open`: the name and the index after the closing bracket. */
function quotedArgument(text: string, open: number, allowed: RegExp, max: number): { name: string; after: number } | undefined {
  const quote = text[open];
  if (quote === undefined || !QUOTES.has(quote)) return undefined;
  const name = run(text, open + 1, allowed, max);
  const close = open + 1 + name.length;
  if (!name || text[close] !== quote || text[close + 1] !== ')') return undefined;
  return { name, after: close + 2 };
}

function occurrences(text: string, needle: string, visit: (after: number, at: number) => void): boolean {
  let seen = 0;
  for (let at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + needle.length)) {
    if (seen >= MAX_OCCURRENCES) return true;
    seen++;
    visit(at + needle.length, at);
  }
  return false;
}

export function supabaseNames(texts: readonly { body: string }[]): SupabaseNames {
  const tables = new Set<string>();
  const buckets = new Set<string>();
  let limitHit = false;
  const add = (set: Set<string>, name: string) => {
    if (set.has(name)) return;
    if (set.size >= MAX_NAMES) limitHit = true;
    else set.add(name);
  };

  for (const { body } of texts) {
    // supabase.from("table") and supabase.storage.from("bucket").getPublicUrl(…)
    limitHit ||= occurrences(body, '.from(', (after, at) => {
      const storage = body.endsWith('.storage', at);
      const arg = quotedArgument(body, after, storage ? BUCKET_CHAR : TABLE_CHAR, storage ? MAX_BUCKET_NAME : MAX_TABLE_NAME);
      if (!arg) return;
      if (storage) {
        if (body.startsWith('.getPublicUrl(', arg.after)) add(buckets, arg.name);
        return;
      }
      if (/^[0-9]/.test(arg.name) || NOT_A_CLIENT.some((owner) => body.endsWith(owner, at))) return;
      add(tables, arg.name);
    });

    // The REST path of a table, written out.
    limitHit ||= occurrences(body, '/rest/v1/', (after) => {
      const name = run(body, after, TABLE_CHAR, MAX_TABLE_NAME);
      const next = body[after + name.length];
      if (name && !/^[0-9]/.test(name) && (next === undefined || next === '?' || QUOTES.has(next))) add(tables, name);
    });

    // The public object path only serves files of a bucket that is public.
    limitHit ||= occurrences(body, '/storage/v1/object/public/', (after) => {
      const name = run(body, after, BUCKET_CHAR, MAX_BUCKET_NAME);
      const next = body[after + name.length];
      if (name && (next === '/' || (next !== undefined && QUOTES.has(next)))) add(buckets, name);
    });
  }
  return { tables: [...tables], publicBuckets: [...buckets], limitHit };
}
