// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { NeedsValidationRecord } from '../../core/records';
import { evidence } from '../../i18n/ja';
import type { ServedText, UrlContext } from '../context';
import { supabaseNames } from '../supabase-names';
import { JWT_PATTERN, jwtRole } from './secrets';

/**
 * R01 — database access rules, as far as the outside can tell.
 *
 * When a site talks to Supabase or Firebase straight from the browser, the
 * public key is in the page by design and the access rules are the only thing
 * protecting the data. Whether those rules are on cannot be seen passively and
 * must not be tested without the owner's consent.
 *
 * So this checker never confirms anything. It detects the direct connection
 * and hands the owner one precise thing to check: a needs_validation record.
 * Where the site's code names its tables, the record names them too, so the
 * owner knows where to look first. Still no request is made to the database.
 */

/** Table names shown in one record. */
const MAX_TABLES_SHOWN = 10;

// Every quantifier here is bounded and no pattern starts with a variable-length
// part: these run over attacker-controlled text and must stay linear.
const SUPABASE = /https:\/\/[a-z0-9]{15,40}\.supabase\.co\b|(?<![A-Za-z0-9_-])sb_publishable_[A-Za-z0-9_-]{20}/i;
const FIREBASE = /\bfirebaseapp\.com\b|\bfirebaseio\.com\b|\bfirestore\.googleapis\.com\b|\bfirebasestorage\.(?:googleapis\.com|app)\b/i;

function usesSupabase(text: string): boolean {
  if (SUPABASE.test(text)) return true;
  JWT_PATTERN.lastIndex = 0;
  for (const m of text.matchAll(JWT_PATTERN)) {
    if (jwtRole(m[0]) === 'anon') return true;
  }
  return false;
}

const firstMatch = (texts: ServedText[], test: (body: string) => boolean) => texts.find((t) => test(t.body));

function tablesNamed(texts: ServedText[]): string {
  const { tables, limitHit } = supabaseNames(texts);
  if (tables.length === 0) return '';
  return evidence.supabaseTables(tables.slice(0, MAX_TABLES_SHOWN), limitHit || tables.length > MAX_TABLES_SHOWN);
}

export const baasHintChecker: Checker<UrlContext> = {
  id: 'url.baas-hint',
  layer: 'url',
  mode: 'passive',
  rules: ['R01'],
  run(ctx, make) {
    const records: NeedsValidationRecord[] = [];

    const supabase = firstMatch(ctx.texts, usesSupabase);
    if (supabase) {
      records.push(
        make.needsValidation({
          ruleId: 'R01',
          code: 'baas.supabase_rls_unverified',
          blocker: 'not_observable_from_outside',
          key: 'supabase',
          location: supabase.url,
          evidence: evidence.directConnection('Supabase') + tablesNamed(ctx.texts),
        }),
      );
    }

    const firebase = firstMatch(ctx.texts, (body) => FIREBASE.test(body));
    if (firebase) {
      records.push(
        make.needsValidation({
          ruleId: 'R01',
          code: 'baas.firebase_rules_unverified',
          blocker: 'not_observable_from_outside',
          key: 'firebase',
          location: firebase.url,
          evidence: evidence.directConnection('Firebase'),
        }),
      );
    }

    return { records, coverage: [{ ruleId: 'R01', status: 'partial', note: 'presence_hint_only' }] };
  },
};
