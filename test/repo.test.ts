// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { summarize, type Assessment } from '../src/core/assessment';
import type { CoverageUnit } from '../src/core/coverage';
import { validateAssessment } from '../src/core/validate';
import { scanDatabaseRules, scanRulesFile } from '../src/repo/checkers/firebase-rules';
import { replaySql } from '../src/repo/checkers/supabase-sql';
import { parseIgnoreFile } from '../src/repo/gitignore';
import { scanRepo } from '../src/repo/scan';
import { renderLocalReport, renderOwnerReport } from '../src/report';
import { fake } from './fixture';

// ------------------------------------------------------------------ helpers

const made: string[] = [];
after(() => {
  for (const dir of made) rmSync(dir, { recursive: true, force: true });
});

function makeRepo(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'qa-repo-'));
  made.push(root);
  for (const [path, text] of Object.entries(files)) {
    const full = join(root, ...path.split('/'));
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return root;
}

const unit = (a: Assessment, ruleId: string): CoverageUnit => a.coverage.find((u) => u.ruleId === ruleId)!;
const codes = (a: Assessment, verdict?: string) =>
  a.records.filter((r) => !verdict || r.verdict === verdict).map((r) => r.code).sort();
const lineOf = (text: string, needle: string) => text.slice(0, text.indexOf(needle)).split('\n').length;

const serviceRole = fake.supabaseJwt('service_role');
const anon = fake.supabaseJwt('anon');
const stripeLive = fake.stripeLive();
const openai = fake.openai();

// ------------------------------------------------------------------ fixtures

const VULNERABLE_SQL = `-- profiles: protected
create table public.profiles (id uuid primary key references auth.users, name text);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select using (auth.uid() = id);

-- posts: RLS forgotten
create table posts (id bigint primary key, body text, user_id uuid);

-- messages: RLS on, but anyone can change anything
create table public.messages (id bigint primary key, body text);
alter table public.messages enable row level security;
create policy "anyone can edit" on public.messages for all using (true);

-- news: public on purpose
create table public.news (id bigint primary key, title text);
alter table public.news enable row level security;
create policy "news is public" on public.news for select to anon, authenticated using (true);

-- contact form
create table public.contact (id bigint primary key, body text);
alter table public.contact enable row level security;
create policy "anyone can send" on public.contact for insert with check (true);

-- not exposed through the API
create schema private;
create table private.audit (id bigint);

-- a function body is not schema: nothing in it may count
create function public.touch() returns trigger language plpgsql as $$
begin
  -- create table fake_table (id int);
  perform 1;
  create table if not exists shadow_tbl (id int);
  return new;
end;
$$;
`;

const vulnerableApp = () =>
  makeRepo({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2', vite: '^6' } }),
    '.env': [
      'VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co',
      `VITE_SUPABASE_ANON_KEY=${anon}`,
      `VITE_SUPABASE_SERVICE_ROLE_KEY=${serviceRole}`,
      `OPENAI_API_KEY=${openai}`,
    ].join('\n'),
    'src/lib/ai.ts': 'export const key = import.meta.env.VITE_OPENAI_API_KEY;\n',
    'src/pay.ts': `import Stripe from 'stripe';\n\nexport const stripe = new Stripe("${stripeLive}");\n`,
    'README.md': `Set STRIPE_SECRET_KEY=sk_${'live'}_xxxxxxxxxxxxxxxxxxxxxxxx in your dashboard.\n`,
    'supabase/migrations/20260101000000_init.sql': VULNERABLE_SQL,
  });

// ------------------------------------------------------------------ tests

test('a typical AI-built Supabase app: every classic mistake is found, and nothing else', async () => {
  const root = vulnerableApp();
  const a = await scanRepo(root, { name: 'my-app' });
  assert.deepEqual(validateAssessment(a), []);
  assert.equal(a.tier, 'owner');
  assert.deepEqual(a.target, { layer: 'repo', ref: 'my-app' });

  assert.deepEqual(codes(a, 'confirmed'), [
    'rls.not_enabled',
    'rls.policy_open_write',
    'secret.env_not_ignored',
    'secret.public_env_name',
    'secret.public_env_name',
    'secret.stripe_live',
  ]);
  assert.deepEqual(codes(a, 'needs_validation'), ['rls.policy_open_insert', 'rls.policy_open_read']);

  const at = (code: string) => a.records.filter((r) => r.code === code).map((r) => r.location).sort();
  assert.deepEqual(at('rls.not_enabled'), [
    `supabase/migrations/20260101000000_init.sql:${lineOf(VULNERABLE_SQL, 'create table posts')}`,
  ]);
  assert.deepEqual(at('secret.stripe_live'), ['src/pay.ts:3']);
  assert.deepEqual(at('secret.public_env_name'), ['.env:3', 'src/lib/ai.ts:1']);
  assert.ok(a.records.every((r) => !r.evidence.includes('ANON')), 'the anon key is public by design');

  assert.deepEqual([unit(a, 'R01').status, unit(a, 'R01').note], ['partial', 'code_only']);
  assert.equal(unit(a, 'R02').status, 'checked');
  assert.deepEqual([unit(a, 'R11').status, unit(a, 'R11').reason], ['not_run', 'requires_deployed_site']);
  assert.deepEqual([unit(a, 'R14').status, unit(a, 'R14').reason], ['not_run', 'requires_deployed_site']);
  assert.equal(unit(a, 'R05').reason, 'not_implemented');

  const s = summarize(a, 'owner');
  assert.equal(s.grade, 'E');
  assert.equal(s.counts.P0, 6);

  // Detect only: no value appears anywhere, and no absolute path either.
  const report = renderLocalReport(a);
  const everything = report + JSON.stringify(a);
  for (const secret of [serviceRole, stripeLive, openai, anon, root]) {
    assert.equal(everything.includes(secret), false, 'output contains a secret value or the local path');
  }
  assert.match(report, /QA\.JP\.AI 公開前チェック結果（ソースコード）/);
  assert.match(report, /テーブルの行レベルセキュリティ（RLS）が有効になっていません/);
  assert.match(report, /テーブル public\.posts を作成していますが/);
  assert.match(report, /Stripe の本番用シークレットキーがソースコードに直接書かれています/);
  assert.match(report, /変数名 VITE_OPENAI_API_KEY/);
  assert.match(report, /意図した設定かどうかは、所有者の方にしか判断できません/);
  assert.match(report, /R14 通信の暗号化とレスポンスヘッダー: 未検査（公開されたサイトの検査（URL 検査）で確認します）/);

  // A source-code result is not a URL result: the URL renderer refuses it.
  assert.throws(() => renderOwnerReport(a, undefined as never));
});

test('a careful project produces no findings', async () => {
  const root = makeRepo({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2' } }),
    '.gitignore': 'node_modules/\n.env*\n!.env.example\n',
    '.env': `SUPABASE_SERVICE_ROLE_KEY=${serviceRole}\nOPENAI_API_KEY=${openai}\nVITE_SUPABASE_ANON_KEY=${anon}\n`,
    '.env.example': [
      'VITE_SUPABASE_URL=',
      'VITE_SUPABASE_ANON_KEY=',
      'SUPABASE_SERVICE_ROLE_KEY=your-service-role-key',
      `OPENAI_API_KEY=sk-${'proj'}-your-key-here`,
    ].join('\n'),
    'src/server/ai.ts': 'export const key = process.env.OPENAI_API_KEY;\n',
    'supabase/migrations/001.sql': [
      'create table "public"."Orders" (id bigint, user_id uuid);',
      'alter table public."Orders" enable row level security;',
      'create policy "own orders" on public."Orders" for all using (auth.uid() = user_id) with check (auth.uid() = user_id);',
      'create table public.notes (id bigint, user_id uuid);',
      'alter table public.notes disable row level security;',
      'alter table only public.notes enable row level security;',
      'create policy "server only" on public.notes for all to service_role using (true);',
      'create policy "restrict" on public.notes as restrictive for all using (true);',
    ].join('\n'),
  });
  const a = await scanRepo(root);
  assert.deepEqual(validateAssessment(a), []);
  assert.deepEqual(a.records, []);
  assert.equal(summarize(a, 'owner').grade, 'A');
  assert.match(renderLocalReport(a), /今回の検査範囲では問題は見つかりませんでした/);
});

test('migrations are replayed in order: disable, drop, rename and alter are followed', () => {
  const file = (path: string, text: string) => ({ path, text });
  const replay = replaySql([
    file('m/001.sql', [
      'create table a (id int);',
      'alter table a enable row level security;',
      'create policy p on a for all using (true);',
      'create table gone (id int);',
      'create table later_off (id int);',
      'alter table later_off enable row level security;',
    ].join('\n')),
    file('m/002.sql', [
      'drop policy p on a;',
      'drop table if exists gone cascade;',
      'alter table later_off disable row level security;',
      'alter table a rename to b;',
      'create policy q on b for update using (auth.uid() = id);',
      'alter policy q on b using (true);',
    ].join('\n')),
  ]);
  assert.deepEqual([...replay.tables.keys()].sort(), ['public.b', 'public.later_off']);
  assert.equal(replay.tables.get('public.b')!.rls, true);
  assert.equal(replay.tables.get('public.later_off')!.rls, false);
  assert.deepEqual([...replay.policies.keys()], ['public.b::q']);
  assert.equal(replay.policies.get('public.b::q')!.usingTrue, true, 'alter policy changed the condition to true');
});

test('RLS switched inside a function is handed to the owner, not reported as confirmed', async () => {
  const root = makeRepo({
    'supabase/migrations/001.sql': [
      'create table public.items (id int);',
      "do $$ declare t text; begin for t in select tablename from pg_tables where schemaname = 'public' loop",
      "  execute format('alter table %I enable row level security', t); end loop; end $$;",
    ].join('\n'),
  });
  const a = await scanRepo(root);
  assert.deepEqual(codes(a), ['rls.not_enabled_unclear']);
  assert.equal(a.records[0]!.verdict, 'needs_validation');
});

test('Supabase in use but no table definitions in the code: the owner is asked to check the dashboard', async () => {
  const root = makeRepo({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2' } }),
    'src/db.ts': 'import { createClient } from "@supabase/supabase-js";\n',
  });
  const a = await scanRepo(root);
  assert.deepEqual(codes(a), ['rls.schema_not_in_repo']);
  assert.match(renderLocalReport(a), /Table Editor/);
});

test('a project that uses neither Supabase nor Firebase: R01 is not applicable, not "passed"', async () => {
  const root = makeRepo({ 'package.json': '{"dependencies":{"express":"^5"}}', 'src/index.js': 'console.log(1)' });
  const a = await scanRepo(root);
  assert.deepEqual(validateAssessment(a), []);
  assert.deepEqual([unit(a, 'R01').status, unit(a, 'R01').reason], ['not_run', 'not_applicable']);
  assert.equal(summarize(a, 'owner').coverage.checked, 1, 'only R02 counts as examined');
  assert.match(renderLocalReport(a), /対象となる仕組み（Supabase・Firebase）の利用が見つかりませんでした/);
});

const FIRESTORE_RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function isOwner(userId) { return request.auth != null && request.auth.uid == userId; }
    match /users/{userId} {
      allow read, write: if isOwner(userId);
      allow read: if request.auth.token.email.matches('.*@example[.]com;{');
    }
    // the catalogue is public; see the docs } for details
    match /products/{id} {
      allow read: if true;   // public catalogue; no login needed {
      allow write: if false;
    }
    match /chats/{chatId} {
      allow read, write: if request.auth != null;
    }
    // old test mode left over
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2026, 12, 31);
    }
  }
}
`;

test('Firebase: open rules, test mode and sign-in-only rules are told apart', async () => {
  const root = makeRepo({
    'package.json': JSON.stringify({ dependencies: { firebase: '^11' } }),
    'firestore.rules': FIRESTORE_RULES,
    'storage.rules': `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write;
    }
  }
}`,
    'database.rules.json': JSON.stringify({ rules: { '.read': true, '.write': 'auth != null', public: { '.read': true } } }),
  });
  const a = await scanRepo(root);
  assert.deepEqual(validateAssessment(a), []);
  assert.deepEqual(codes(a, 'confirmed'), ['firebase.rules_open', 'firebase.rules_open', 'firebase.test_mode']);
  assert.deepEqual(codes(a, 'needs_validation'), [
    'firebase.auth_only',
    'firebase.auth_only',
    'firebase.public_read',
    'firebase.public_read',
  ]);

  const locations = a.records.map((r) => r.location).sort();
  assert.ok(locations.includes(`firestore.rules:${lineOf(FIRESTORE_RULES, 'allow read, write: if request.time')}`));
  assert.ok(locations.includes(`firestore.rules:${lineOf(FIRESTORE_RULES, 'allow read: if true')}`));
  assert.ok(locations.includes(`firestore.rules:${lineOf(FIRESTORE_RULES, 'allow read, write: if request.auth != null')}`));
  assert.ok(locations.includes('database.rules.json (/)'));
  assert.ok(locations.includes('database.rules.json (/public)'));
  assert.ok(!locations.some((l) => l.includes(`:${lineOf(FIRESTORE_RULES, 'if isOwner')}`)), 'the owner-only rule is fine');

  // Braces and semicolons inside comments and strings must not shift the match nesting.
  const publicRead = a.records.find((r) => r.code === 'firebase.public_read' && r.location.startsWith('firestore.rules'))!;
  assert.match(publicRead.evidence, /\/databases\/\{database\}\/documents\/products\/\{id\}/);
  const testMode = a.records.find((r) => r.code === 'firebase.test_mode')!;
  assert.match(testMode.evidence, /\/databases\/\{database\}\/documents\/\{document=\*\*\}/);
});

test('Firebase in use but no rules in the code: the owner is asked to check the console', async () => {
  const root = makeRepo({ 'package.json': JSON.stringify({ dependencies: { firebase: '^11' } }), 'firebase.json': '{}' });
  const a = await scanRepo(root);
  assert.deepEqual(codes(a), ['firebase.rules_not_in_repo']);
});

test('symbolic links are never followed, and what was skipped is reported', async () => {
  const outside = makeRepo({ 'secret.ts': `export const k = "${stripeLive}";\n`, 'nested/also.ts': `"${stripeLive}"` });
  const root = makeRepo({ 'src/index.ts': 'console.log(1)\n' });
  symlinkSync(join(outside, 'secret.ts'), join(root, 'src', 'linked.ts'));
  symlinkSync(join(outside, 'nested'), join(root, 'shared'));

  const a = await scanRepo(root);
  assert.equal(a.records.some((r) => r.code === 'secret.stripe_live'), false, 'nothing outside the folder was read');
  assert.deepEqual([unit(a, 'R02').status, unit(a, 'R02').note], ['partial', 'some_files_not_read']);
});

test('files over the size cap are not read, and the result says so', async () => {
  const root = makeRepo({ 'big.js': `${' '.repeat(5000)}"${stripeLive}"`, 'small.js': 'console.log(1)' });
  const a = await scanRepo(root, { maxFileBytes: 1000 });
  assert.equal(a.records.length, 0);
  assert.deepEqual([unit(a, 'R02').status, unit(a, 'R02').note], ['partial', 'some_files_not_read']);
});

test('the same project in two places gives the same fingerprints', async () => {
  const first = await scanRepo(vulnerableApp(), { name: 'x' });
  const second = await scanRepo(vulnerableApp(), { name: 'x' });
  assert.ok(first.records.length > 0);
  assert.deepEqual(first.records.map((r) => r.fingerprint).sort(), second.records.map((r) => r.fingerprint).sort());
});

test('hostile input stays fast', () => {
  const MB2 = 2 * 1024 * 1024;
  const fill = (unit: string) => unit.repeat(Math.floor(MB2 / unit.length));
  const within = (label: string, fn: () => unknown) => {
    const started = performance.now();
    fn();
    const ms = performance.now() - started;
    assert.ok(ms < 3000, `${label} took ${ms.toFixed(0)} ms`);
  };
  const sql = (text: string) => replaySql([{ path: 'x.sql', text }]);
  within('unterminated create table', () => sql(fill('create table x (')));
  within('unterminated string', () => sql(`'${fill('a ')}`));
  within('quotes and escapes', () => sql(fill("''\\'")));
  within('quoted identifiers without an end', () => sql(fill('"a')));
  within('unterminated dollar body', () => sql(`$$${fill('a;')}`));
  within('unterminated comment', () => sql(`/*${fill('/* ')}`));
  within('many dollar signs', () => sql(fill('$a$ ')));
  within('many tiny statements', () => sql(fill('create table t (id int);')));
  within('many policies', () => sql(fill('create policy p on t for all using (true);')));

  const rules = (text: string) => scanRulesFile({ path: 'firestore.rules', text });
  within('allow without semicolon', () => rules(fill('allow ')));
  within('match without brace', () => rules(fill('match ')));
  within('unterminated strings', () => rules(fill("'")));
  within('escaped quotes without an end', () => rules(fill("'\\")));
  within('double quotes without an end', () => rules(fill('"\\')));
  within('unterminated block comment', () => rules(`/*${fill('*')}`));
  within('functions without brace', () => rules(fill('function f(')));
  within('deep nesting', () => rules(fill('match /a {')));

  within('deep JSON', () => scanDatabaseRules({ path: 'database.rules.json', text: `{"rules":${'{"a":'.repeat(5000)}1${'}'.repeat(5000)}}` }));
});

test('.gitignore: the patterns env files rely on', () => {
  const matches = (patterns: string, path: string, base = '') => {
    let ignored = false;
    for (const rule of parseIgnoreFile(base, patterns)) {
      const relative = base ? path.slice(base.length + 1) : path;
      if (rule.regex.test(relative)) ignored = !rule.negate;
    }
    return ignored;
  };
  assert.equal(matches('.env', '.env'), true);
  assert.equal(matches('.env', 'apps/web/.env'), true, 'an unanchored name matches at any depth');
  assert.equal(matches('/.env', 'apps/web/.env'), false, 'a leading slash anchors to the folder of the .gitignore');
  assert.equal(matches('.env*', '.env.local'), true);
  assert.equal(matches('*.local', '.env.local'), true);
  assert.equal(matches('.env*\n!.env.example', '.env.example'), false);
  assert.equal(matches('.env.local', '.env'), false);
  assert.equal(matches('secrets/', 'secrets/.env'), true);
  assert.equal(matches('secrets/', 'secrets'), false, 'a directory pattern does not match a file of that name');
  assert.equal(matches('**/config/.env', 'a/b/config/.env'), true);
  assert.equal(matches('# .env\n', '.env'), false);
});

test('a nested .gitignore protects the env file next to it', async () => {
  const root = makeRepo({ 'apps/web/.gitignore': '.env\n', 'apps/web/.env': `STRIPE_SECRET_KEY=${stripeLive}\n` });
  const a = await scanRepo(root);
  assert.equal(a.records.some((r) => r.code === 'secret.env_not_ignored'), false);
});

test('tests and fixtures: a key-shaped value is handed to the owner, and mentions are not usage', async () => {
  const root = makeRepo({
    'package.json': '{"dependencies":{"express":"^5"}}',
    'src/index.js': 'console.log(1)',
    'test/fixtures/keys.ts': `export const fakeStripe = "${stripeLive}";\nconst url = "https://abcdefghijklmnopqrst.supabase.co";\n`,
    'src/pay.test.ts': 'const k = import.meta.env.VITE_OPENAI_API_KEY;\n',
    'docs/setup.md': 'Point VITE_SUPABASE_URL at https://abcdefghijklmnopqrst.supabase.co and my-app.firebaseapp.com\n',
    'evals/demo/build.ts': `const env = "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=";\nconst url = "https://abcdefghijklmnopqrst.supabase.co";\n`,
  });
  const a = await scanRepo(root);
  assert.deepEqual(validateAssessment(a), []);
  assert.deepEqual(codes(a, 'confirmed'), [], 'nothing in tests or documents is reported as a leak');
  assert.deepEqual(codes(a, 'needs_validation'), ['secret.in_test_file']);
  assert.equal(a.records[0]!.location, 'test/fixtures/keys.ts:1');
  assert.deepEqual([unit(a, 'R01').status, unit(a, 'R01').reason], ['not_run', 'not_applicable']);
});

test('a bare mention of a service domain is not usage; a project URL is', async () => {
  const mention = makeRepo({ 'src/list.ts': "export const domains = ['firebaseapp.com', '.supabase.co'];\n" });
  assert.deepEqual([unit(await scanRepo(mention), 'R01').reason], ['not_applicable']);
  const firebase = makeRepo({ 'src/firebase.ts': 'export const config = { authDomain: "my-clinic.firebaseapp.com" };\n' });
  assert.deepEqual(codes(await scanRepo(firebase)), ['firebase.rules_not_in_repo']);
});

test('the place that shows a service is used is the place reported', async () => {
  const root = makeRepo({ 'src/config.ts': 'export const url = "https://abcdefghijklmnopqrst.supabase.co";\n' });
  const a = await scanRepo(root);
  assert.deepEqual(a.records.map((r) => [r.code, r.location]), [['rls.schema_not_in_repo', 'src/config.ts']]);
});

test('the command line runs the pre-deployment check', () => {
  const root = vulnerableApp();
  const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'check', root], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /公開前チェック結果/);
  assert.equal(result.stdout.includes(stripeLive), false);

  const json = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'check', root, '--json'], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
    timeout: 60_000,
  });
  assert.deepEqual(validateAssessment(JSON.parse(json.stdout)), []);
});
