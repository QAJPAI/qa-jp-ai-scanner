// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { compareAssessments, type Comparison } from '../src/core/compare';
import { recordFactory } from '../src/core/records';
import { renderFixRequest } from '../src/fixrequest';
import { afterFixNoteFor, findingText, fixStepsFor } from '../src/i18n/ja';
import { verifyByFile, WELL_KNOWN_PATH } from '../src/ownership/file';
import { mintVerificationToken } from '../src/ownership/token';
import { renderComparison } from '../src/recheck';
import { servedTextReader } from '../src/url/compare';
import { closeAgents } from '../src/url/net/fetcher';
import { inspectOwner, type UrlInspection } from '../src/url/scan';
import { caseSiteRoutes } from './case-site';
import { fake, html, startFixture, type Fixture, type Route } from './fixture';

/**
 * Fixing a published site, and confirming the fix: the fix request an owner
 * hands to an AI coding tool, and the comparison of two checks of one site.
 */

after(closeAgents);

const FETCH = { allowPrivate: true };
const TOKEN = mintVerificationToken('test-secret-0123456789', 'acct-1', '127.0.0.1');
const SUPABASE_URL = 'https://abcdefghijklmnopqrst.supabase.co';
const serviceRole = fake.supabaseJwt('service_role');
const stripeLive = fake.stripeLive();
const JS = { 'content-type': 'application/javascript' };
const HTML = { 'content-type': 'text/html' };

const page = (scripts: string[], headers: Record<string, string> = {}): Route => ({
  headers: { ...HTML, ...headers },
  body: html(scripts),
});
const script = (body: string): Route => ({ headers: JS, body });
const withKey = script(`const admin=createClient("${SUPABASE_URL}","${serviceRole}");`);
const clean = script('const api=(path)=>fetch("/api"+path);');

/** One site whose content changes between checks, as a real site does when it is published again. */
async function site(routes: Record<string, Route>) {
  const live: Record<string, Route> = { ...routes, [WELL_KNOWN_PATH]: { body: TOKEN } };
  const fixture: Fixture = await startFixture(live);
  const proof = await verifyByFile(fixture.origin, TOKEN, FETCH);
  assert.ok(proof);
  return {
    origin: fixture.origin,
    close: fixture.close,
    check: (options: { activeChecks?: boolean; maxScripts?: number } = {}) =>
      inspectOwner(fixture.origin, proof, { fetch: FETCH, ...options }),
    /** Publish a new version: replaces every route except the ownership file. */
    publish(next: Record<string, Route>) {
      for (const path of Object.keys(live)) if (path !== WELL_KNOWN_PATH) delete live[path];
      Object.assign(live, next);
    },
  };
}

const compare = (before: UrlInspection, now: UrlInspection): Comparison =>
  compareAssessments(before.assessment, now.assessment, { wasRead: servedTextReader(now) });

const codes = (records: { code: string }[]) => records.map((r) => r.code).sort();
const reasonOf = (cmp: Comparison, code: string) => cmp.unverified.find((u) => u.record.code === code)?.reason;

// ---------------------------------------------------------------- fix request

test('the fix request for a site speaks about the published site, and gives no command to run', async () => {
  const s = await site(caseSiteRoutes('vulnerable'));
  try {
    const { assessment } = await s.check();
    const text = renderFixRequest(assessment);

    assert.match(text, /QA\.JP\.AI 修正依頼/);
    assert.match(text, /URL 検査（公開中のサイトを外部から見る検査）/);
    assert.match(text, /対象: 127\.0\.0\.1/);
    // The AI works in the project, not on the published files, and cannot re-check by itself.
    assert.match(text, /公開中のファイルを直接書き換えず/);
    assert.match(text, /あなたは再検査を実行できません/);
    assert.match(text, /再検査は利用者が行います/);
    assert.equal(text.includes('npx'), false, 'a site has no re-check command');
    assert.equal(text.includes('プロジェクトのフォルダーで次のコマンド'), false);

    // Every confirmed problem is listed with its ID and concrete steps, most serious first.
    const confirmed = assessment.records.filter((r) => r.verdict === 'confirmed');
    assert.ok(confirmed.length >= 2);
    for (const r of confirmed) assert.ok(text.includes(r.fingerprint), `missing ${r.code}`);
    assert.match(text, /### 1\. \[P0・至急\] Supabase の service_role キーがフロントエンドに含まれています（R02）/);
    assert.match(text, /キーがどこからブラウザー向けのコードに入っているかを特定/);
    assert.match(text, /発行元の管理画面でキーを無効化して再発行するよう、利用者に依頼/);
    assert.match(text, /修正後に利用者へ伝えること: ページからキーが見つからなくなっても/);

    // The owner question is passed on, not answered.
    assert.match(text, /## 利用者に確認していただく項目（1 件）/);
    assert.match(text, /外部からの検査では判定できない項目です/);

    // Detect-only holds here too: the key itself is never in the text.
    assert.equal(text.includes(serviceRole), false);
  } finally {
    await s.close();
  }
});

test('every problem a site check can confirm has steps of its own for an AI coding tool', () => {
  const urlCodes = Object.keys(findingText).filter((code) => /^(secret|transport|header|cookie|exposed|email)\./.test(code));
  const repoOnly = new Set(['secret.public_env_name', 'secret.env_not_ignored']);
  for (const code of urlCodes.filter((c) => !repoOnly.has(c))) {
    const steps = fixStepsFor('url', code);
    assert.ok(steps.length >= 2, `${code} has no steps beyond the report text`);
  }
  // Keys: the steps differ from the source-code ones, and end with publishing again.
  assert.notDeepEqual(fixStepsFor('url', 'secret.openai'), fixStepsFor('repo', 'secret.openai'));
  assert.match(fixStepsFor('url', 'secret.openai').at(-1)!, /公開するまで、修正は効果がありません/);
  // DNS is the owner's to change.
  assert.match(fixStepsFor('url', 'email.dmarc_missing')[0]!, /DNS の設定は.*利用者が行います/);
  // A fix the tool can see is not the whole fix when something was already public.
  for (const code of ['secret.stripe_live', 'exposed.env', 'exposed.git']) {
    assert.match(afterFixNoteFor('url', code) ?? '', /ツールでは確認できません/, code);
  }
  assert.equal(afterFixNoteFor('url', 'header.csp_missing'), undefined);
});

// ---------------------------------------------------------------- re-check

test('a key removed from a rebuilt site is confirmed as fixed, whatever the new script is called', async () => {
  const s = await site({ '/': page(['/assets/index-3fA9kQ2x.js']), '/assets/index-3fA9kQ2x.js': withKey });
  try {
    const before = await s.check();
    assert.deepEqual(codes(before.assessment.records.filter((r) => r.ruleId === 'R02')), ['secret.supabase_service_role']);

    // The owner moves the call to the server and publishes: the build renames its output.
    s.publish({ '/': page(['/assets/main.B7xYz012.js']), '/assets/main.B7xYz012.js': clean });
    const now = await s.check();
    assert.equal(now.everythingRead, true);

    const cmp = compare(before, now);
    assert.deepEqual(codes(cmp.fixed), ['secret.supabase_service_role']);
    assert.equal(cmp.unverified.length, 0);
    // The page no longer talks to Supabase from the browser: that question is settled too.
    assert.deepEqual(codes(cmp.questionsResolved), ['baas.supabase_rls_unverified']);

    const text = renderComparison(cmp, now.assessment);
    assert.match(text, /^対象: 127\.0\.0\.1$/m);
    assert.match(text, /■ 修正を確認しました（1 件）/);
    assert.match(text, /補足: ページからキーが見つからなくなっても、すでに公開されたキーは使えるままです/);
    // Basic-configuration problems of the test site are untouched and stay listed.
    assert.ok(cmp.stillPresent.some((r) => r.code === 'transport.no_https'));
  } finally {
    await s.close();
  }
});

test('one key swapped for another is not a fix', async () => {
  const s = await site({ '/': page(['/app.js']), '/app.js': withKey });
  try {
    const before = await s.check();
    // The new key sits in another script: "the same place" is the whole site.
    s.publish({ '/': page(['/app.js', '/pay.js']), '/app.js': clean, '/pay.js': script(`const s=Stripe("${stripeLive}");`) });
    const now = await s.check();

    const cmp = compare(before, now);
    assert.equal(cmp.fixed.length, 0);
    assert.equal(reasonOf(cmp, 'secret.supabase_service_role'), 'similar_finding_present');
    assert.deepEqual(codes(cmp.newConfirmed), ['secret.stripe_live']);
    assert.match(renderComparison(cmp, now.assessment), /サイト内に、同じ種類の問題か確認項目が新たに見つかっています/);
  } finally {
    await s.close();
  }
});

test('a key moved to another script on the site is still present, not fixed', async () => {
  const s = await site({ '/': page(['/app.js']), '/app.js': withKey });
  try {
    const before = await s.check();
    s.publish({ '/': page(['/app.js', '/vendor.js']), '/app.js': clean, '/vendor.js': withKey });
    const cmp = compare(before, await s.check());
    assert.deepEqual(codes(cmp.stillPresent.filter((r) => r.ruleId === 'R02')), ['secret.supabase_service_role']);
    assert.equal(cmp.fixed.length, 0);
  } finally {
    await s.close();
  }
});

test('when part of the site could not be read, a key that is gone is not called fixed', async () => {
  // Read in full before, a script fails now: the rule was examined less.
  const s = await site({ '/': page(['/app.js', '/more.js']), '/app.js': withKey, '/more.js': clean });
  try {
    const before = await s.check();
    s.publish({ '/': page(['/app.js', '/more.js']), '/app.js': clean });
    const now = await s.check();
    assert.equal(now.everythingRead, false);
    const cmp = compare(before, now);
    assert.equal(cmp.fixed.length, 0);
    assert.equal(reasonOf(cmp, 'secret.supabase_service_role'), 'coverage_reduced');
  } finally {
    await s.close();
  }
});

test('with unread scripts both times, only a script of the same address that was read again counts', async () => {
  const broken = { '/broken.js': { status: 500, body: 'error' } };
  const s = await site({ '/': page(['/app.js', '/broken.js']), '/app.js': withKey, ...broken });
  try {
    const before = await s.check();
    assert.equal(before.everythingRead, false);

    // Same address, read again, key gone: fixed.
    s.publish({ '/': page(['/app.js', '/broken.js']), '/app.js': clean, ...broken });
    const same = await s.check();
    assert.deepEqual(codes(compare(before, same).fixed), ['secret.supabase_service_role']);

    // The script was renamed and something is unread: the key may be in the unread part.
    s.publish({ '/': page(['/app2.js', '/broken.js']), '/app2.js': clean, ...broken });
    const renamed = await s.check();
    const cmp = compare(before, renamed);
    assert.equal(cmp.fixed.length, 0);
    assert.equal(reasonOf(cmp, 'secret.supabase_service_role'), 'file_not_read');
    assert.match(renderComparison(cmp, renamed.assessment), /問題のあったスクリプトも読んでいません/);

    // Without the reader, the comparison would have called it fixed: the reader is what holds it back.
    assert.equal(compareAssessments(before.assessment, renamed.assessment).fixed.length, 1);

    // Same address, but cut off at the size cap with the key beyond it: not read in full, so not vouched for.
    const padding = `/*${'x'.repeat(3 * 1024 * 1024)}*/`;
    s.publish({ '/': page(['/app.js', '/broken.js']), '/app.js': script(`${padding}const admin=createClient("${SUPABASE_URL}","${serviceRole}");`), ...broken });
    const cutOff = await s.check();
    assert.equal(cutOff.textsRead.has(`${s.origin}/app.js`), false);
    assert.equal(reasonOf(compare(before, cutOff), 'secret.supabase_service_role'), 'file_not_read');
  } finally {
    await s.close();
  }
});

test('a script over the cap is unread: what was in it is not called fixed', async () => {
  const s = await site({ '/': page(['/a.js', '/b.js']), '/a.js': clean, '/b.js': withKey });
  try {
    const before = await s.check();
    const now = await s.check({ maxScripts: 1 });
    assert.equal(now.everythingRead, false);
    assert.deepEqual([...now.textsRead].map((u) => new URL(u).pathname), ['/', '/a.js']);
    const cmp = compare(before, now);
    assert.equal(cmp.fixed.length, 0);
    assert.equal(reasonOf(cmp, 'secret.supabase_service_role'), 'coverage_reduced');
  } finally {
    await s.close();
  }
});

test('a header that was added is confirmed as fixed; the ones still missing stay', async () => {
  const s = await site({ '/': page([]) });
  try {
    const before = await s.check();
    s.publish({ '/': page([], { 'content-security-policy': "default-src 'self'", 'x-content-type-options': 'nosniff' }) });
    const cmp = compare(before, await s.check());
    assert.deepEqual(codes(cmp.fixed), ['header.csp_missing', 'header.nosniff_missing']);
    assert.ok(cmp.stillPresent.some((r) => r.code === 'header.clickjacking'));
    assert.equal(cmp.unverified.length, 0);
  } finally {
    await s.close();
  }
});

test('an exposed file that is gone is fixed only if the active checks ran again', async () => {
  const s = await site({ '/': page([]), '/.env': { body: 'DATABASE_PASSWORD=x1\nAPI_KEY=y2\n' } });
  try {
    const before = await s.check();
    assert.ok(before.assessment.records.some((r) => r.code === 'exposed.env'));
    s.publish({ '/': page([]) });

    const withoutActive = compare(before, await s.check({ activeChecks: false }));
    assert.equal(withoutActive.fixed.length, 0);
    assert.equal(reasonOf(withoutActive, 'exposed.env'), 'rule_not_examined');

    const now = await s.check();
    const cmp = compare(before, now);
    assert.deepEqual(codes(cmp.fixed), ['exposed.env']);
    assert.match(renderComparison(cmp, now.assessment), /補足: ファイルを取得できなくなっても、すでに公開された内容は取り消せません/);
  } finally {
    await s.close();
  }
});

test('results of a different tool version, or of another site, are not compared as fixes', async () => {
  const s = await site({ '/': page(['/app.js']), '/app.js': withKey });
  try {
    const before = await s.check();
    s.publish({ '/': page(['/app.js']), '/app.js': clean });
    const now = await s.check();

    const older = { ...before, assessment: { ...before.assessment, engineVersion: '0.0.1' } };
    const cmp = compare(older, now);
    assert.equal(cmp.toolChanged, true);
    assert.equal(cmp.fixed.length, 0);
    assert.equal(reasonOf(cmp, 'secret.supabase_service_role'), 'tool_changed');

    const elsewhere = { ...before, assessment: { ...before.assessment, target: { layer: 'url' as const, host: 'example.jp' } } };
    assert.throws(() => compare(elsewhere, now), /different project or site/);
  } finally {
    await s.close();
  }
});

// ---------------------------------------------------------------- unit level

test('the reader vouches for a served text only when it can', () => {
  const make = recordFactory('url.secrets', 'url', 'passive');
  const key = make.confirmed({ ruleId: 'R02', code: 'secret.openai', key: 'k', location: 'https://example.jp/assets/app.js (offset 12)', evidence: 'e', severity: 'P0' });
  const header = recordFactory('url.transport', 'url', 'passive').confirmed({
    ruleId: 'R14', code: 'header.csp_missing', key: 'header.csp_missing', location: 'https://example.jp/', evidence: 'e', severity: 'P2',
  });
  const place = 'https://example.jp/assets/app.js';

  const nothing = servedTextReader({ everythingRead: false, textsRead: new Set() });
  assert.equal(nothing(place, key), false);
  // Records that do not point into a served text are not the reader's business.
  assert.equal(nothing('https://example.jp/', header), true);

  const all = servedTextReader({ everythingRead: true, textsRead: new Set() });
  assert.equal(all(place, key), true);

  const some = servedTextReader({ everythingRead: false, textsRead: new Set(['https://example.jp/assets/app.js?v=2']) });
  assert.equal(some(place, key), true, 'the query string is not part of the address');
  assert.equal(some('https://example.jp/assets/other.js', key), false);
  assert.equal(some('https://other.example/assets/app.js', key), false);
  assert.equal(some('not a url', key), false);
});
