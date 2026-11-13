// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { baselineDir, BaselineError, baselinePath, loadBaseline, saveBaseline } from '../src/baseline';
import { compareAssessments } from '../src/core/compare';
import { ENGINE_VERSION } from '../src/core/types';
import { renderFixRequest } from '../src/fixrequest';
import { renderHandoff } from '../src/handoff';
import { afterFixNoteFor, findingText, fixStepsFor } from '../src/i18n/ja';
import { RECHECK_COMMAND } from '../src/invocation';
import { renderComparison } from '../src/recheck';
import { inspectRepo, scanRepo } from '../src/repo/scan';
import { fake } from './fixture';

const made: string[] = [];
after(() => {
  for (const dir of made) rmSync(dir, { recursive: true, force: true });
});

const temp = (prefix: string) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
};

function write(root: string, files: Record<string, string>): void {
  for (const [path, text] of Object.entries(files)) {
    const full = join(root, ...path.split('/'));
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
}

const serviceRole = fake.supabaseJwt('service_role');
const stripeTest = ['sk', 'test', 'A1b2C3d4E5f6G7h8I9j0K1l2'].join('_');
const RLO = String.fromCharCode(0x202e);

/** A small clinic app with one problem of each main kind, and one owner question. */
function clinicApp(): string {
  const root = temp('qa-fixflow-');
  write(root, {
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2' } }),
    '.env.local': `VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nVITE_SUPABASE_SERVICE_ROLE_KEY=${serviceRole}\n`,
    [`src/pay${RLO}.ts`]: `export const stripe = "${stripeTest}";\n`,
    'supabase/migrations/001_init.sql': [
      'create table public.patients (id bigint, user_id uuid, name text);',
      'create table public.news (id bigint);',
      'alter table public.news enable row level security;',
      'create policy "public" on public.news for select using (true);',
    ].join('\n'),
  });
  return root;
}

const cacheEnv = () => ({ env: { XDG_CACHE_HOME: temp('qa-cache-') }, platform: 'linux' as const });

const listTree = (root: string): string[] =>
  readdirSync(root, { recursive: true, withFileTypes: false }).map(String).sort();

// ------------------------------------------------------------------ baseline

test('the baseline is kept in the user cache, owner-only, and the project is untouched', async () => {
  const root = clinicApp();
  const before = listTree(root);
  const env = cacheEnv();
  const assessment = await scanRepo(root);

  const path = saveBaseline(root, assessment, env);
  assert.ok(path.startsWith(baselineDir(env)), 'under the cache folder');
  assert.equal(path.includes(root), false, 'named by a hash, not by the project path');
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(dirname(path)).mode & 0o777, 0o700);
  assert.deepEqual(listTree(root), before, 'nothing written into the project');
  assert.deepEqual(loadBaseline(root, env), assessment);

  // Saved again: replaced in place, no temporary files left behind.
  saveBaseline(root, assessment, env);
  assert.deepEqual(readdirSync(dirname(path)), [path.slice(dirname(path).length + 1)]);
});

test('where the cache folder is, by platform', () => {
  assert.match(baselineDir({ platform: 'linux', env: { XDG_CACHE_HOME: '/c' }, home: '/h' }), /^\/c\/qa-jp-ai\/baselines$/);
  // A relative XDG_CACHE_HOME is ignored, as the XDG specification requires.
  assert.match(baselineDir({ platform: 'linux', env: { XDG_CACHE_HOME: 'rel' }, home: '/h' }), /^\/h\/\.cache\/qa-jp-ai/);
  assert.match(baselineDir({ platform: 'win32', env: { LOCALAPPDATA: '/L' }, home: '/h' }), /^\/L\/qa-jp-ai/);
});

test('a baseline folder that is a link is refused', async () => {
  const root = clinicApp();
  const cache = temp('qa-cache-');
  const elsewhere = temp('qa-elsewhere-');
  mkdirSync(join(cache, 'qa-jp-ai'), { recursive: true });
  symlinkSync(elsewhere, join(cache, 'qa-jp-ai', 'baselines'));
  const env = { env: { XDG_CACHE_HOME: cache }, platform: 'linux' as const };
  assert.throws(
    () => saveBaseline(root, { schema: 'x' } as never, env),
    (err: unknown) => err instanceof BaselineError && err.code === 'unsafe_location',
  );
  assert.deepEqual(readdirSync(elsewhere), [], 'nothing written through the link');
});

test('a baseline that is a link, not JSON, malformed or missing is refused', async () => {
  const root = clinicApp();
  const env = cacheEnv();
  const path = baselinePath(root, env);
  const refused = (code: string) => (err: unknown) => err instanceof BaselineError && err.code === code;

  assert.throws(() => loadBaseline(root, env), refused('not_found'));
  mkdirSync(dirname(path), { recursive: true });

  const real = join(temp('qa-target-'), 'a.json');
  writeFileSync(real, JSON.stringify(await scanRepo(root)));
  symlinkSync(real, path);
  assert.throws(() => loadBaseline(root, env), refused('invalid'));
  rmSync(path);

  writeFileSync(path, 'not json');
  assert.throws(() => loadBaseline(root, env), refused('invalid'));

  const edited = { ...(await scanRepo(root)), tier: 'admin' };
  writeFileSync(path, JSON.stringify(edited));
  assert.throws(() => loadBaseline(root, env), refused('invalid'));
});

// --------------------------------------------------------------- fix request

test('the fix request lists every problem, most serious first, with steps, IDs and the re-check', async () => {
  const root = clinicApp();
  const assessment = await scanRepo(root);
  const text = renderFixRequest(assessment);

  const confirmed = assessment.records.filter((r) => r.verdict === 'confirmed');
  assert.ok(confirmed.length >= 3);
  for (const r of confirmed) assert.ok(text.includes(`ID: ${r.fingerprint}`), r.code);

  const items = [...text.matchAll(/^### \d+\. \[(P\d)/gm)].map((m) => m[1]);
  assert.deepEqual(items, [...items].sort(), 'P0 before P1');
  assert.ok(items.includes('P1'), 'the test key is P1');

  assert.match(text, /新しいマイグレーションファイルを追加/);
  assert.match(text, /発行元の管理画面でキーを無効化して再発行/);
  assert.match(text, /検査を通すためだけの変更をしないでください/);
  assert.match(text, /利用者に確認していただく項目（1 件）/);
  assert.match(text, /ポリシーが、すべての人にデータの閲覧を許可しています/);
  assert.ok(text.includes(RECHECK_COMMAND));
  assert.ok(RECHECK_COMMAND.includes(`#v${ENGINE_VERSION} check . --compare --for-ai`));

  for (const secret of [serviceRole, stripeTest, root, RLO]) assert.equal(text.includes(secret), false);
});

test('the fix request puts P0 first even when a P1 is found first', async () => {
  const root = temp('qa-order-');
  write(root, { 'src/a.ts': `export const s = "${stripeTest}";\n`, 'src/b.ts': `export const k = "${fake.anthropic()}";\n` });
  const assessment = await scanRepo(root);
  assert.deepEqual(
    assessment.records.map((r) => (r.verdict === 'confirmed' ? r.severity : '')),
    ['P1', 'P0'],
    'found in file order',
  );
  const items = [...renderFixRequest(assessment).matchAll(/^### \d+\. \[(P\d)/gm)].map((m) => m[1]);
  assert.deepEqual(items, ['P0', 'P1']);
});

test('every problem the source-code check can confirm has its own steps and an after-fix note', () => {
  const repoCodes = Object.keys(findingText).filter((c) => /^(?:secret|rls|firebase)\./.test(c));
  assert.ok(repoCodes.length >= 15);
  for (const code of repoCodes) {
    assert.ok(fixStepsFor('repo', code).length >= 2, `${code}: steps`);
    assert.ok(afterFixNoteFor('repo', code), `${code}: note`);
  }
});

test('the hand-off carries IDs and says how "fixed" is decided', async () => {
  const root = clinicApp();
  const assessment = await scanRepo(root);
  const plain = renderHandoff(assessment);
  for (const r of assessment.records) assert.ok(plain.includes(`ID: ${r.fingerprint}`));
  assert.match(plain, /修正を始める前に `npx --yes .* check \. --baseline` を実行/);
  assert.equal(plain.includes('## 0.'), false);

  const saved = renderHandoff(assessment, { baselineSaved: true });
  assert.match(saved, /修正前の結果は保存済みです/);
});

test('a re-check report and hand-off show what is fixed, and what is gone but not verified', async () => {
  const root = clinicApp();
  const before = await inspectRepo(root);
  // One real fix (RLS in a new migration), one evasion (env file renamed away).
  write(root, {
    'supabase/migrations/002_rls.sql':
      'alter table public.patients enable row level security;\ncreate policy "own" on public.patients for all using (auth.uid() = user_id);\n',
  });
  rmSync(join(root, '.env.local'));
  const now = await inspectRepo(root);
  const cmp = compareAssessments(before.assessment, now.assessment, { wasRead: (p) => now.filesRead.has(p) });

  assert.deepEqual(cmp.fixed.map((r) => r.code), ['rls.not_enabled']);
  assert.deepEqual(cmp.unverified.map((u) => [u.record.code, u.reason]).sort(), [
    ['secret.env_not_ignored', 'file_not_read'],
    ['secret.public_env_name', 'file_not_read'],
  ]);

  const report = renderComparison(cmp, now.assessment);
  assert.match(report, /■ 修正を確認しました（1 件）\n1\. \[P0・至急\] テーブルの行レベルセキュリティ/);
  assert.match(report, /本番に反映されたかどうかは、ツールでは確認できません/);
  assert.match(report, /■ 見つからなくなりましたが、修正とは確認できません（2 件）/);
  assert.match(report, /このほかに、見つからなくなったものの修正とは確認できない問題が 2 件あります/);

  const handoff = renderHandoff(now.assessment, { comparison: cmp });
  const zero = handoff.slice(handoff.indexOf('## 0.'), handoff.indexOf('## 1.'));
  assert.match(zero, /### 修正を確認しました（1 件）/);
  assert.match(zero, /### 修正とは確認できません（2 件）[\s\S]*理由: 問題のあったファイルを今回は読んでいません/);
  assert.match(zero, /「修正とは確認できません」の項目を修正済みと伝えないでください/);
  for (const secret of [serviceRole, stripeTest, root, RLO]) {
    assert.equal(report.includes(secret), false);
    assert.equal(handoff.includes(secret), false);
  }
});

// ---------------------------------------------------------- command line, E2E

const repoRoot = join(import.meta.dirname, '..');
const cli = (args: string[], cache: string) =>
  spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, XDG_CACHE_HOME: cache },
  });

test('command line: fix request, fix, re-check', async () => {
  const root = clinicApp();
  const cache = temp('qa-cache-');
  const tree = listTree(root);

  const first = cli(['check', root, '--fix-request', '--fail-on', 'P0'], cache);
  assert.equal(first.status, 3, 'P0 found');
  assert.match(first.stdout, /^# QA\.JP\.AI 修正依頼/);
  assert.match(first.stderr, /キャッシュフォルダーに保存しました/);
  assert.deepEqual(listTree(root), tree, 'the project is untouched');
  assert.ok(existsSync(join(cache, 'qa-jp-ai', 'baselines')));

  // Fix everything properly.
  write(root, {
    'supabase/migrations/002_rls.sql':
      'alter table public.patients enable row level security;\ncreate policy "own" on public.patients for all using (auth.uid() = user_id);\n',
    '.env.local': 'VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=\n',
    '.gitignore': '.env\n.env.*\n',
    [`src/pay${RLO}.ts`]: 'export const stripe = process.env.STRIPE_SECRET_KEY;\n',
  });

  const recheck = cli(['check', root, '--compare', '--fail-on', 'P0'], cache);
  assert.equal(recheck.status, 0, recheck.stderr);
  // RLS, the public variable name, the env file not ignored, and the key in code.
  assert.match(recheck.stdout, /■ 修正を確認しました（4 件）/);
  assert.match(recheck.stdout, /現在ツールが確認している問題: P0 0 件 \/ P1 0 件 \/ P2 0 件\n/);
  assert.match(recheck.stdout, /キーの無効化・再発行が済んだかどうかは、ツールでは確認できません/);

  const json = JSON.parse(cli(['check', root, '--compare', '--json'], cache).stdout);
  assert.equal(json.comparison.fixed.length, 4);
  assert.equal(json.assessment.target.layer, 'repo');

  // Comparing never replaces the saved result: the same four are still confirmed fixed.
  assert.match(cli(['check', root, '--compare', '--for-ai'], cache).stdout, /### 修正を確認しました（4 件）/);
});

test('command line: deleting the file with the problem is reported as not verified', async () => {
  const root = clinicApp();
  const cache = temp('qa-cache-');
  assert.equal(cli(['check', root, '--baseline'], cache).status, 0);
  rmSync(join(root, '.env.local'));
  const out = cli(['check', root, '--compare'], cache).stdout;
  assert.match(out, /■ 修正を確認しました（0 件）/);
  assert.match(out, /■ 見つからなくなりましたが、修正とは確認できません（2 件）[\s\S]*理由: 問題のあったファイルを今回は読んでいません/);
});

test('command line: no saved result, another project, conflicting options', async () => {
  const root = clinicApp();
  const cache = temp('qa-cache-');

  const none = cli(['check', root, '--compare'], cache);
  assert.equal(none.status, 1);
  assert.match(none.stderr, /比較する前回の結果がありません/);

  const other = temp('qa-other-');
  write(other, { 'a.ts': 'export {};\n' });
  const otherResult = join(temp('qa-json-'), 'other.json');
  writeFileSync(otherResult, cli(['check', other, '--json'], cache).stdout);
  const different = cli(['check', root, '--since', otherResult], cache);
  assert.equal(different.status, 1);
  assert.match(different.stderr, /別のプロジェクトのもの/);

  for (const args of [
    ['--compare', '--baseline'],
    ['--compare', '--fix-request'],
    ['--since', otherResult, '--compare'],
    ['--for-ai', '--fix-request'],
    ['--json', '--for-ai'],
  ]) {
    assert.equal(cli(['check', root, ...args], cache).status, 2, args.join(' '));
  }
  assert.equal(lstatSync(cache).isDirectory(), true);
  assert.deepEqual(readdirSync(cache), [], 'a refused command saves nothing');
});

test('the saved result is what the CLI compares with', async () => {
  const root = clinicApp();
  const cache = temp('qa-cache-');
  assert.equal(cli(['check', root, '--baseline'], cache).status, 0);
  const saved = JSON.parse(readFileSync(baselinePath(root, { env: { XDG_CACHE_HOME: cache }, platform: 'linux' }), 'utf8'));
  assert.equal(saved.target.layer, 'repo');
  assert.ok(saved.records.length > 0);
});
