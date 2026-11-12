// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { AssessmentRecord, RecordFactory } from '../../core/records';
import { evidence } from '../../i18n/ja';
import { baseName, everythingReadInRepo, isAppSignalFile, type RepoContext, type RepoFile } from '../context';
import { scanDatabaseRules, scanRulesFile, type Grant } from './firebase-rules';
import { policyRisk, replaySql } from './supabase-sql';

/**
 * R01 — database access rules, as written in the project.
 *
 * When a browser talks to Supabase or Firebase directly, the access rules are
 * the only thing between the public key in the page and the data. This checker
 * reads the rules the project defines in code. Rules changed only in a
 * dashboard are invisible here, so coverage is always partial ('code_only').
 *
 * Verdicts:
 *  confirmed         the code leaves data open to anyone (RLS never enabled,
 *                    a write policy of `true`, Firebase rules open or in test mode).
 *  needs_validation  open in a way that may be intended (public read, open
 *                    insert, any signed-in user), or the rules are not in the code at all.
 */

const SUPABASE_PACKAGE = /^@supabase\//;
/** A project URL as it appears in real configuration, not a bare mention of the domain. */
const SUPABASE_PROJECT_URL = /https:\/\/[a-z0-9]{15,40}\.supabase\.co\b/;
const FIREBASE_AUTH_DOMAIN = /\b[a-z0-9-]{3,64}\.firebaseapp\.com\b/;
const FIREBASE_PACKAGES = new Set(['firebase', 'firebase-admin', 'firebase-functions', 'react-native-firebase']);

/**
 * Where the project shows it uses a service, or undefined if it does not.
 * Tests and documents are not evidence: they mention services they do not use.
 */
function supabaseEvidence(ctx: RepoContext): string | undefined {
  if ([...ctx.dependencies].some((d) => SUPABASE_PACKAGE.test(d))) return 'package.json';
  if (ctx.dirs.has('supabase')) return 'supabase/';
  return ctx.files.find((f) => isAppSignalFile(f.path) && SUPABASE_PROJECT_URL.test(f.text))?.path;
}

function firebaseEvidence(ctx: RepoContext): string | undefined {
  if ([...ctx.dependencies].some((d) => FIREBASE_PACKAGES.has(d) || d.startsWith('@firebase/'))) return 'package.json';
  return ctx.files.find((f) => {
    const name = baseName(f.path);
    if (name === 'firebase.json' || name === '.firebaserc') return true;
    return isAppSignalFile(f.path) && FIREBASE_AUTH_DOMAIN.test(f.text);
  })?.path;
}

const isRulesFile = (f: RepoFile) =>
  f.path.endsWith('.rules') && /\bservice\s+(?:cloud\.firestore|firebase\.storage)\b/.test(f.text);
const isDatabaseRules = (f: RepoFile) => baseName(f.path) === 'database.rules.json';

function supabaseRecords(ctx: RepoContext, make: RecordFactory, usedAt: string): AssessmentRecord[] {
  const sqlFiles = ctx.files.filter((f) => f.path.toLowerCase().endsWith('.sql'));
  const replay = replaySql(sqlFiles);
  const records: AssessmentRecord[] = [];

  if (replay.tablesCreated === 0) {
    records.push(
      make.needsValidation({
        ruleId: 'R01',
        code: 'rls.schema_not_in_repo',
        blocker: 'requires_deployment_fact',
        key: 'supabase-schema',
        location: sqlFiles[0]?.path ?? usedAt,
        evidence: evidence.schemaNotInRepo(sqlFiles.length),
      }),
    );
    return records;
  }

  for (const table of replay.tables.values()) {
    if (table.rls) continue;
    const input = {
      ruleId: 'R01' as const,
      code: 'rls.not_enabled',
      key: `table:${table.schema}.${table.name}`,
      location: `${table.file}:${table.line}`,
      evidence: evidence.rlsNotEnabled(`${table.schema}.${table.name}`),
    };
    // RLS may be switched inside a function this replay cannot follow: hand it over rather than guess.
    records.push(
      replay.dynamicRls
        ? make.needsValidation({ ...input, code: 'rls.not_enabled_unclear', blocker: 'requires_deployment_fact' })
        : make.confirmed({ ...input, severity: 'P0' }),
    );
  }

  for (const policy of replay.policies.values()) {
    const risk = policyRisk(policy);
    if (!risk) continue;
    const input = {
      ruleId: 'R01' as const,
      key: `policy:${policy.table}:${policy.name}`,
      location: `${policy.file}:${policy.line}`,
      evidence: evidence.openPolicy(policy.table, policy.name, policy.command, policy.roles),
    };
    if (risk === 'open_write') records.push(make.confirmed({ ...input, code: 'rls.policy_open_write', severity: 'P0' }));
    else {
      records.push(
        make.needsValidation({
          ...input,
          code: risk === 'open_read' ? 'rls.policy_open_read' : 'rls.policy_open_insert',
          blocker: 'requires_owner_intent',
        }),
      );
    }
  }
  return records;
}

function firebaseRecords(
  ctx: RepoContext,
  make: RecordFactory,
  usedAt: string,
): { records: AssessmentRecord[]; unparsed: boolean } {
  const rulesFiles = ctx.files.filter(isRulesFile);
  const databaseFiles = ctx.files.filter(isDatabaseRules);
  const records: AssessmentRecord[] = [];
  let unparsed = false;

  if (rulesFiles.length === 0 && databaseFiles.length === 0) {
    records.push(
      make.needsValidation({
        ruleId: 'R01',
        code: 'firebase.rules_not_in_repo',
        blocker: 'requires_deployment_fact',
        key: 'firebase-rules',
        location: usedAt,
        evidence: evidence.firebaseRulesNotInRepo(),
      }),
    );
    return { records, unparsed };
  }

  const grants: Grant[] = [];
  for (const file of rulesFiles) grants.push(...scanRulesFile(file));
  for (const file of databaseFiles) {
    const found = scanDatabaseRules(file);
    if (found === undefined) unparsed = true;
    else grants.push(...found);
  }

  for (const grant of grants) {
    const ops = [grant.read && 'read', grant.write && 'write'].filter(Boolean).join(',');
    const input = {
      ruleId: 'R01' as const,
      key: `${grant.file}|${grant.path}|${ops}|${grant.kind}`,
      location: grant.line > 0 ? `${grant.file}:${grant.line}` : `${grant.file} (${grant.path})`,
      evidence: evidence.firebaseGrant(grant.path, ops),
    };
    if (grant.kind === 'test_mode') {
      records.push(make.confirmed({ ...input, code: 'firebase.test_mode', severity: 'P0' }));
    } else if (grant.kind === 'open' && (grant.write || grant.wildcard)) {
      records.push(make.confirmed({ ...input, code: 'firebase.rules_open', severity: 'P0' }));
    } else if (grant.kind === 'open') {
      records.push(make.needsValidation({ ...input, code: 'firebase.public_read', blocker: 'requires_owner_intent' }));
    } else {
      records.push(make.needsValidation({ ...input, code: 'firebase.auth_only', blocker: 'requires_owner_intent' }));
    }
  }
  return { records, unparsed };
}

export const accessRulesChecker: Checker<RepoContext> = {
  id: 'repo.access-rules',
  layer: 'repo',
  mode: 'passive',
  rules: ['R01'],
  run(ctx, make) {
    const supabase = supabaseEvidence(ctx);
    const firebase = firebaseEvidence(ctx);
    if (!supabase && !firebase) return { records: [], coverage: [], notApplicable: ['R01'] };

    const records: AssessmentRecord[] = [];
    let unparsed = false;
    if (supabase) records.push(...supabaseRecords(ctx, make, supabase));
    if (firebase) {
      const result = firebaseRecords(ctx, make, firebase);
      records.push(...result.records);
      unparsed = result.unparsed;
    }
    const note = unparsed || !everythingReadInRepo(ctx.load) ? 'some_files_not_read' : 'code_only';
    return { records, coverage: [{ ruleId: 'R01', status: 'partial', note }] };
  },
};
