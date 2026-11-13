// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import type { Assessment } from '../src/core/assessment';
import { codeFamily, compareAssessments, ComparisonError, locationFile, type Comparison } from '../src/core/compare';
import type { CoverageUnit } from '../src/core/coverage';
import { recordFactory, type AssessmentRecord } from '../src/core/records';
import { ASSESSMENT_SCHEMA, ENGINE_VERSION, RULES_VERSION } from '../src/core/types';
import { validateAssessment } from '../src/core/validate';
import { inspectRepo, type RepoInspection } from '../src/repo/scan';
import { fake } from './fixture';

// ---------------------------------------------------------------- unit level

const make = recordFactory('test.checker', 'repo', 'passive');
const p0 = (key: string, location: string, code = 'rls.not_enabled') =>
  make.confirmed({ ruleId: 'R01', code, key, location, evidence: 'e', severity: 'P0' });
const question = (key: string, location: string) =>
  make.needsValidation({ ruleId: 'R01', code: 'rls.policy_open_read', key, location, evidence: 'e', blocker: 'requires_owner_intent' });

const checked = (): CoverageUnit[] => [{ ruleId: 'R01', layer: 'repo', status: 'checked', mode: 'passive', checker: 'test.checker' }];

function assessment(records: AssessmentRecord[], coverage: CoverageUnit[] = checked(), over: Partial<Assessment> = {}): Assessment {
  return {
    schema: ASSESSMENT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    rulesVersion: RULES_VERSION,
    target: { layer: 'repo', ref: 'app' },
    tier: 'owner',
    startedAt: '2026-11-13T00:00:00.000Z',
    records,
    coverage,
    ...over,
  };
}

const read = (...paths: string[]) => ({ wasRead: (p: string) => paths.includes(p) });

test('a problem gone from a file that was read, under the same coverage, is fixed', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  const cmp = compareAssessments(assessment([a]), assessment([]), read('db/001.sql'));
  assert.deepEqual(cmp.fixed.map((r) => r.fingerprint), [a.fingerprint]);
  assert.equal(cmp.unverified.length + cmp.stillPresent.length + cmp.newConfirmed.length, 0);
});

test('still present and new problems are told apart by fingerprint', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  const b = p0('table:public.b', 'db/002.sql:1');
  const cmp = compareAssessments(assessment([a]), assessment([a, b]), read('db/001.sql', 'db/002.sql'));
  assert.deepEqual(cmp.stillPresent.map((r) => r.fingerprint), [a.fingerprint]);
  assert.deepEqual(cmp.newConfirmed.map((r) => r.fingerprint), [b.fingerprint]);
  assert.equal(cmp.fixed.length, 0);
});

test('a gone problem is not called fixed when the rule was examined less, or not at all', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  const cases: Array<[CoverageUnit[], string]> = [
    [[{ ruleId: 'R01', layer: 'repo', status: 'error', mode: 'passive', checker: 'x' }], 'rule_not_examined'],
    [[{ ruleId: 'R01', layer: 'repo', status: 'not_run', reason: 'not_applicable' }], 'rule_not_examined'],
    [[], 'rule_not_examined'],
    [[{ ruleId: 'R01', layer: 'repo', status: 'partial', mode: 'passive', checker: 'x', note: 'some_files_not_read' }], 'coverage_reduced'],
    [[{ ruleId: 'R01', layer: 'repo', status: 'partial', mode: 'passive', checker: 'x', note: 'record_limit_reached' }], 'coverage_reduced'],
  ];
  for (const [coverage, reason] of cases) {
    const cmp = compareAssessments(assessment([a]), assessment([], coverage), read('db/001.sql'));
    assert.equal(cmp.fixed.length, 0, reason);
    assert.equal(cmp.unverified[0]?.reason, reason);
  }
});

test('a "code only" partial check counts the same as before when it was the same before', () => {
  const codeOnly: CoverageUnit[] = [{ ruleId: 'R01', layer: 'repo', status: 'partial', mode: 'passive', checker: 'x', note: 'code_only' }];
  const a = p0('table:public.a', 'db/001.sql:1');
  const cmp = compareAssessments(assessment([a], codeOnly), assessment([], codeOnly), read('db/001.sql'));
  assert.equal(cmp.fixed.length, 1);
});

test('a partial check that read fewer files than before is reduced coverage', () => {
  const unit = (note: 'code_only' | 'some_files_not_read'): CoverageUnit[] => [
    { ruleId: 'R01', layer: 'repo', status: 'partial', mode: 'passive', checker: 'x', note },
  ];
  const a = p0('table:public.a', 'db/001.sql:1');
  const cmp = compareAssessments(assessment([a], unit('code_only')), assessment([], unit('some_files_not_read')), read('db/001.sql'));
  assert.equal(cmp.unverified[0]?.reason, 'coverage_reduced');
});

test('a gone problem is not called fixed when its file was not read this time', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  const cmp = compareAssessments(assessment([a]), assessment([]), read());
  assert.equal(cmp.unverified[0]?.reason, 'file_not_read');
});

test('a new problem of the same kind in the same file blocks "fixed" (renamed, not removed)', () => {
  const before = p0('env:VITE_SERVICE_ROLE_KEY', '.env:2', 'secret.public_env_name');
  const after = p0('env:NEXT_PUBLIC_SERVICE_ROLE_KEY', '.env:2', 'secret.public_env_name');
  const cmp = compareAssessments(assessment([before]), assessment([after]), read('.env'));
  assert.equal(cmp.unverified[0]?.reason, 'similar_finding_present');
  assert.equal(cmp.newConfirmed.length, 1);
  // A problem of another kind in the same file does not block it.
  const other = p0('table:public.z', '.env:9', 'rls.not_enabled');
  assert.equal(compareAssessments(assessment([before]), assessment([other]), read('.env')).fixed.length, 1);
});

test('nothing is called fixed across tool or rule versions', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  for (const over of [{ engineVersion: '0.0.1' }, { rulesVersion: '0.0.1' }]) {
    const cmp = compareAssessments(assessment([a], checked(), over), assessment([]), read('db/001.sql'));
    assert.equal(cmp.toolChanged, true);
    assert.equal(cmp.fixed.length, 0);
    assert.equal(cmp.unverified[0]?.reason, 'tool_changed');
  }
});

test('owner questions get the same four outcomes', () => {
  const q1 = question('policy:a:p', 'db/001.sql:4');
  const q2 = question('policy:b:p', 'db/001.sql:5');
  const q3 = question('policy:c:p', 'db/gone.sql:1');
  const q4 = question('policy:d:p', 'db/002.sql:1');
  const cmp = compareAssessments(assessment([q1, q2, q3]), assessment([q2, q4]), read('db/001.sql', 'db/002.sql'));
  assert.deepEqual(cmp.questionsResolved.map((r) => r.fingerprint), [q1.fingerprint]);
  assert.deepEqual(cmp.questionsOpen.map((r) => r.fingerprint), [q2.fingerprint]);
  assert.deepEqual(cmp.questionsNew.map((r) => r.fingerprint), [q4.fingerprint]);
  assert.deepEqual(cmp.questionsUnverified.map((u) => [u.record.fingerprint, u.reason]), [[q3.fingerprint, 'file_not_read']]);
});

test('a problem made ambiguous (now only a question) is not fixed, and the question is new', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  const unclear = make.needsValidation({
    ruleId: 'R01', code: 'rls.not_enabled_unclear', key: 'table:public.a', location: 'db/001.sql:1', evidence: 'e', blocker: 'requires_deployment_fact',
  });
  const cmp = compareAssessments(assessment([a]), assessment([unclear]), read('db/001.sql'));
  assert.equal(cmp.fixed.length, 0);
  assert.equal(cmp.unverified[0]?.reason, 'similar_finding_present');
  assert.deepEqual(cmp.questionsNew.map((r) => r.code), ['rls.not_enabled_unclear']);
  // Even with a colliding fingerprint, a record that changed verdict is new in its verdict, never dropped.
  const collided = { ...unclear, fingerprint: a.fingerprint };
  const again = compareAssessments(assessment([a]), assessment([collided]), read('db/001.sql'));
  assert.equal(again.questionsNew.length, 1);
  assert.equal(again.fixed.length, 0);
});

test('a question that was already there does not block a fix in the same file', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  const q = question('policy:news:p', 'db/001.sql:4');
  const cmp = compareAssessments(assessment([a, q]), assessment([q]), read('db/001.sql'));
  assert.equal(cmp.fixed.length, 1);
});

test('results for another project or site are refused', () => {
  assert.throws(
    () => compareAssessments(assessment([]), assessment([], checked(), { target: { layer: 'repo', ref: 'other' } })),
    (err: unknown) => err instanceof ComparisonError && err.code === 'different_target',
  );
  assert.throws(
    () => compareAssessments(assessment([]), assessment([], checked(), { target: { layer: 'url', host: 'app' } })),
    ComparisonError,
  );
});

test('an edited earlier result cannot hide a problem the re-check finds', () => {
  const a = p0('table:public.a', 'db/001.sql:1');
  // The earlier result was edited to drop the record: the re-check still reports it.
  const cmp = compareAssessments(assessment([]), assessment([a]), read('db/001.sql'));
  assert.deepEqual(cmp.newConfirmed.map((r) => r.fingerprint), [a.fingerprint]);
});

test('code families and the file of a location', () => {
  assert.equal(codeFamily('rls.not_enabled'), codeFamily('rls.not_enabled_unclear'));
  assert.notEqual(codeFamily('rls.not_enabled'), codeFamily('firebase.rules_open'));
  assert.equal(codeFamily('plain'), 'plain');
  assert.equal(locationFile('supabase/migrations/001.sql:12'), 'supabase/migrations/001.sql');
  assert.equal(locationFile('.env.local'), '.env.local');
  assert.equal(locationFile('database.rules.json (/users/$uid)'), 'database.rules.json');
  assert.equal(locationFile('a:b/c.ts:3'), 'a:b/c.ts');
});

// --------------------------------------------------- real projects, real files

const made: string[] = [];
after(() => {
  for (const dir of made) rmSync(dir, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'qa-compare-'));
  made.push(root);
  write(root, files);
  return root;
}

function write(root: string, files: Record<string, string>): void {
  for (const [path, text] of Object.entries(files)) {
    const full = join(root, ...path.split('/'));
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
}

const move = (root: string, from: string, to: string) => {
  mkdirSync(dirname(join(root, to)), { recursive: true });
  renameSync(join(root, from), join(root, to));
};

async function recheck(root: string, change: () => void, options = {}): Promise<{ cmp: Comparison; now: RepoInspection }> {
  const before = await inspectRepo(root, { name: 'app', ...options });
  assert.deepEqual(validateAssessment(before.assessment), []);
  change();
  const now = await inspectRepo(root, { name: 'app', ...options });
  return { cmp: compareAssessments(before.assessment, now.assessment, { wasRead: (p) => now.filesRead.has(p) }), now };
}

const codes = (records: Array<{ code: string }>) => records.map((r) => r.code).sort();

const supabaseApp = () =>
  project({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2' } }),
    'supabase/migrations/001_init.sql': 'create table public.patients (id bigint, user_id uuid, name text);\n',
  });

test('fixing RLS with a new migration is confirmed as fixed', async () => {
  const root = supabaseApp();
  const { cmp } = await recheck(root, () =>
    write(root, {
      'supabase/migrations/002_rls.sql':
        'alter table public.patients enable row level security;\ncreate policy "own" on public.patients for all using (auth.uid() = user_id) with check (auth.uid() = user_id);\n',
    }),
  );
  assert.deepEqual(codes(cmp.fixed), ['rls.not_enabled']);
  assert.equal(cmp.unverified.length + cmp.newConfirmed.length + cmp.stillPresent.length, 0);
});

test('deleting the migration is not a fix', async () => {
  const root = supabaseApp();
  const { cmp } = await recheck(root, () => rmSync(join(root, 'supabase/migrations/001_init.sql')));
  assert.equal(cmp.fixed.length, 0);
  assert.deepEqual(cmp.unverified.map((u) => [u.record.code, u.reason]), [['rls.not_enabled', 'file_not_read']]);
  assert.deepEqual(codes(cmp.questionsNew), ['rls.schema_not_in_repo']);
});

test('a comment that makes RLS look dynamic is not a fix', async () => {
  const root = supabaseApp();
  const { cmp } = await recheck(root, () =>
    write(root, { 'supabase/migrations/002_note.sql': '-- TODO: enable row level security later\n' }),
  );
  assert.equal(cmp.fixed.length, 0);
  assert.deepEqual(cmp.unverified.map((u) => [u.record.code, u.reason]), [['rls.not_enabled', 'similar_finding_present']]);
  assert.deepEqual(codes(cmp.questionsNew), ['rls.not_enabled_unclear']);
});

test('a key moved to another file is still the same problem', async () => {
  const key = fake.anthropic();
  const root = project({ 'src/ai.ts': `export const k = "${key}";\n` });
  const { cmp } = await recheck(root, () => move(root, 'src/ai.ts', 'src/lib/client.ts'));
  assert.deepEqual(codes(cmp.stillPresent), ['secret.anthropic']);
  assert.equal(cmp.fixed.length, 0);
});

test('moving a key into a test folder is not a fix', async () => {
  const key = fake.anthropic();
  const root = project({ 'src/ai.ts': `export const k = "${key}";\n` });
  const { cmp } = await recheck(root, () => move(root, 'src/ai.ts', 'tests/ai.ts'));
  assert.deepEqual(cmp.unverified.map((u) => [u.record.code, u.reason]), [['secret.anthropic', 'file_not_read']]);
  assert.deepEqual(codes(cmp.questionsNew), ['secret.in_test_file']);
});

test('renaming .env.local so it is no longer an env file is not a fix', async () => {
  const key = fake.stripeLive();
  const root = project({ '.env.local': `STRIPE_SECRET_KEY=${key}\n` });
  const { cmp } = await recheck(root, () => move(root, '.env.local', 'env.txt'));
  assert.deepEqual(cmp.unverified.map((u) => [u.record.code, u.reason]), [['secret.env_not_ignored', 'file_not_read']]);
  assert.deepEqual(codes(cmp.newConfirmed), ['secret.stripe_live']);
});

test('swapping one public prefix for another is not a fix', async () => {
  const root = project({ '.env.local': 'VITE_SUPABASE_SERVICE_ROLE_KEY=\n', '.gitignore': '.env*\n' });
  const { cmp } = await recheck(root, () => write(root, { '.env.local': 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n' }));
  assert.deepEqual(cmp.unverified.map((u) => [u.record.code, u.reason]), [['secret.public_env_name', 'similar_finding_present']]);
  assert.deepEqual(codes(cmp.newConfirmed), ['secret.public_env_name']);
});

test('making a file too large to read is not a fix', async () => {
  const key = fake.openai();
  const root = project({ 'src/ai.ts': `export const k = "${key}";\n` });
  const { cmp } = await recheck(root, () => write(root, { 'src/ai.ts': `export const k = "";\n${'//'.repeat(3000)}\n` }), {
    maxFileBytes: 4096,
  });
  assert.equal(cmp.fixed.length, 0);
  assert.equal(cmp.unverified[0]?.record.code, 'secret.openai');
  assert.ok(['coverage_reduced', 'file_not_read'].includes(cmp.unverified[0]!.reason));
});

test('removing a key from the code, and ignoring the env file, are fixes', async () => {
  const key = fake.anthropic();
  const root = project({ 'src/ai.ts': `export const k = "${key}";\n`, '.env.local': `ANTHROPIC_API_KEY=${key}\n` });
  const { cmp } = await recheck(root, () =>
    write(root, { 'src/ai.ts': 'export const k = process.env.ANTHROPIC_API_KEY;\n', '.gitignore': '.env\n.env.*\n' }),
  );
  assert.deepEqual(codes(cmp.fixed), ['secret.anthropic', 'secret.env_not_ignored']);
  assert.equal(cmp.unverified.length + cmp.newConfirmed.length + cmp.stillPresent.length, 0);
});
