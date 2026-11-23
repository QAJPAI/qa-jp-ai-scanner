// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { summarize } from '../src/core/assessment';
import type { Checker } from '../src/core/checker';
import { validateAssessment } from '../src/core/validate';
import { issueEmailProofAfterLinkClick } from '../src/ownership/email';
import { verifyByFile, WELL_KNOWN_PATH } from '../src/ownership/file';
import { PROOF_TTL_MS } from '../src/ownership/proof';
import { mintVerificationToken } from '../src/ownership/token';
import { renderOwnerReport, renderPublicSummary, toPublicSummary } from '../src/report';
import type { UrlContext } from '../src/url/context';
import { closeAgents } from '../src/url/net/fetcher';
import { extractScriptUrls, scan, scanPublic, URL_CHECKERS } from '../src/url/scan';
import { fake, html, startFixture } from './fixture';

after(closeAgents);

const OPTS = { fetch: { allowPrivate: true } };
const TOKEN = mintVerificationToken('test-secret-0123456789', 'acct-1', '127.0.0.1');
const ENV_VALUE = 'SUPER_SECRET_DB_PASSWORD_VALUE';
const SUPABASE_URL = 'https://abcdefghijklmnopqrst.supabase.co';

const serviceRole = fake.supabaseJwt('service_role');
const stripeLive = fake.stripeLive();
const openai = fake.openai();

/** A vibe-coded app with the classic mistakes. */
const vulnerableSite = () =>
  startFixture({
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/assets/app.js'], `window.AI_KEY="${openai}"`) },
    '/assets/app.js': {
      headers: { 'content-type': 'application/javascript' },
      body: `const supabase=createClient("${SUPABASE_URL}","${serviceRole}");const s=Stripe("${stripeLive}");\n//# sourceMappingURL=app.js.map`,
    },
    '/assets/app.js.map': { body: '{"version":3,"sources":["src/App.tsx"],"mappings":""}' },
    '/.env': { body: `DATABASE_PASSWORD=${ENV_VALUE}\nSTRIPE_KEY=abc\n` },
    '/.git/HEAD': { body: 'ref: refs/heads/main\n' },
    [WELL_KNOWN_PATH]: { body: TOKEN },
  });

const coverageOf = (a: { coverage: { ruleId: string; status: string; reason?: string }[] }, ruleId: string) =>
  a.coverage.find((u) => u.ruleId === ruleId)!;

test('public tier: counts only, passive requests only, nothing identifying', async () => {
  const site = await vulnerableSite();
  try {
    const assessment = await scan(site.origin, OPTS);
    assert.equal(assessment.tier, 'public');
    assert.deepEqual(validateAssessment(assessment), []);

    // Passive means passive: only the page and the script it references.
    assert.deepEqual(site.requests, ['/', '/assets/app.js']);

    // The ledger says what was and was not examined.
    assert.equal(assessment.coverage.length, 15);
    assert.equal(coverageOf(assessment, 'R02').status, 'partial');
    assert.equal(coverageOf(assessment, 'R14').status, 'checked');
    assert.equal(coverageOf(assessment, 'R01').status, 'partial');
    assert.deepEqual(
      [coverageOf(assessment, 'R11').status, coverageOf(assessment, 'R11').reason],
      ['not_run', 'requires_owner_verification'],
    );
    assert.equal(coverageOf(assessment, 'R05').reason, 'requires_source');

    // The full picture exists inside the engine…
    const full = summarize(assessment, 'owner');
    assert.equal(full.counts.P0, 3, 'service_role + Stripe live + OpenAI');
    assert.equal(full.needsValidation, 1, 'Supabase RLS cannot be seen from outside');

    // …but the public view carries basic configuration only.
    const summary = toPublicSummary(assessment);
    assert.deepEqual(summary.counts, { P0: 0, P1: 1, P2: 3 }, 'no HTTPS + three missing headers');
    assert.equal(summary.grade, 'D');
    assert.deepEqual([summary.coverage.checked, summary.coverage.partial, summary.coverage.total], [1, 2, 15]);
    assert.equal('records' in summary, false);
    assert.equal('needsValidation' in summary, false);

    const text = renderPublicSummary(summary) + JSON.stringify(summary);
    for (const leak of ['service_role', 'Supabase', 'supabase', 'Stripe', 'OpenAI', 'RLS', 'app.js', 'offset', 'fp_', 'P0（', '確認をお願いしたい項目', serviceRole, stripeLive, openai, 'sk_liv', 'eyJ']) {
      assert.equal(text.includes(leak), false, `public output leaks "${leak}"`);
    }
    assert.match(text, /基本設定の評価: D/);
    assert.match(text, /P1（重大）1 件 \/ P2（改善推奨）3 件/);
    assert.match(text, /全 15 項目のうち 1 項目を検査、2 項目を一部検査/);
    assert.match(text, /重大な問題の有無と、問題の場所・修正方法は、サイトの所有者であることを確認できた方にのみ表示します/);

    // Details need the tier AND a valid proof for this host. Editing the tier field is not enough.
    const elsewhere = issueEmailProofAfterLinkClick('info@example.jp', 'example.jp')!;
    const here = (await verifyByFile(site.origin, TOKEN, { allowPrivate: true }))!;
    assert.throws(() => renderOwnerReport(assessment, here), /ownership proof/);
    assert.throws(() => renderOwnerReport({ ...assessment, tier: 'owner' }, elsewhere), /ownership proof/);
    assert.throws(() => renderOwnerReport({ ...assessment, tier: 'owner' }, here, Date.now() + PROOF_TTL_MS), /ownership proof/);

    // The public entry point returns the summary and nothing else.
    const direct = await scanPublic(site.origin, OPTS);
    assert.deepEqual(Object.keys(direct).sort(), ['counts', 'coverage', 'grade', 'host', 'layer', 'rulesVersion', 'scannedAt']);
  } finally {
    await site.close();
  }
});

test('owner tier: file verification unlocks details and the active checks', async () => {
  const site = await vulnerableSite();
  try {
    const proof = await verifyByFile(site.origin, TOKEN, { allowPrivate: true });
    assert.ok(proof);

    const assessment = await scan(site.origin, { ...OPTS, proof });
    assert.equal(assessment.tier, 'owner');
    assert.deepEqual(validateAssessment(assessment), []);
    assert.equal(coverageOf(assessment, 'R11').status, 'checked');

    const codes = assessment.records.map((r) => r.code);
    for (const expected of [
      'secret.supabase_service_role',
      'secret.stripe_live',
      'secret.openai',
      'baas.supabase_rls_unverified',
      'exposed.env',
      'exposed.git',
      'exposed.sourcemap',
      'transport.no_https',
    ]) {
      assert.ok(codes.includes(expected), `missing ${expected}`);
    }

    const report = renderOwnerReport(assessment, proof);
    assert.match(report, /service_role キーがフロントエンドに含まれています/);
    assert.match(report, /環境変数ファイル（\.env）が外部から取得できる状態です/);
    assert.match(report, /2 件の変数名を確認/);
    assert.match(report, /修正方法:/);
    assert.match(report, /■ 確認をお願いしたい項目/);
    assert.match(report, /すべてのテーブルの RLS が有効になっていること/);
    assert.match(report, /R05 利用者が自分の権限や認証状態を書き換えられる: 未検査（公開中のサイトの外側からは調べられません。/);

    // Detect-only: full keys and file contents never reach the report or the result.
    const everything = report + JSON.stringify(assessment);
    for (const secret of [serviceRole, stripeLive, openai, ENV_VALUE, 'src/App.tsx']) {
      assert.equal(everything.includes(secret), false, 'report contains fetched secret material');
    }

    // Owner view: 3 keys + .env (P0); no HTTPS + .git (P1). Public view: basic configuration only.
    const asPublic = toPublicSummary(assessment);
    const asOwner = summarize(assessment);
    assert.deepEqual([asPublic.counts.P0, asPublic.counts.P1], [0, 1]);
    assert.deepEqual([asOwner.counts.P0, asOwner.counts.P1], [4, 2]);
    // The public view of an owner assessment must not show that R11 ran.
    assert.equal(asPublic.coverage.checked, 1);
    assert.equal(asOwner.coverage.checked, 2);
  } finally {
    await site.close();
  }
});

test('the public view is identical for a site with leaked keys and a site without', async () => {
  const shell = (appJs: string, extra: Record<string, object> = {}) =>
    startFixture({
      '/': { headers: { 'content-type': 'text/html' }, body: html(['/assets/app.js']) },
      '/assets/app.js': { body: appJs },
      ...extra,
    });
  const clean = await shell('console.log("hello")');
  const leaky = await shell(
    `createClient("${SUPABASE_URL}","${serviceRole}");Stripe("${stripeLive}");const k="${openai}"`,
    { '/.env': { body: 'DB_PASSWORD=x\n' }, '/.git/HEAD': { body: 'ref: refs/heads/main\n' } },
  );
  try {
    const now = () => Date.parse('2026-11-12T00:00:00Z');
    const a = await scanPublic(clean.origin, { ...OPTS, now });
    const b = await scanPublic(leaky.origin, { ...OPTS, now });
    // Nothing an unverified requester receives distinguishes the two.
    assert.deepEqual(b, a);
    assert.equal(renderPublicSummary(b), renderPublicSummary(a));
    // And the difference is real: the owner view of the second site is not clean.
    assert.equal(summarize(await scan(leaky.origin, OPTS), 'owner').counts.P0, 3);
  } finally {
    await Promise.all([clean.close(), leaky.close()]);
  }
});

test('fingerprints are stable across runs and ports', async () => {
  const first = await vulnerableSite();
  const second = await vulnerableSite();
  try {
    const a = await scan(first.origin, OPTS);
    const b = await scan(second.origin, OPTS);
    assert.notEqual(first.origin, second.origin);
    assert.deepEqual(a.records.map((r) => r.fingerprint).sort(), b.records.map((r) => r.fingerprint).sort());
  } finally {
    await Promise.all([first.close(), second.close()]);
  }
});

test('a proof for another site, or an expired one, is rejected', async () => {
  const site = await vulnerableSite();
  try {
    const other = issueEmailProofAfterLinkClick('info@example.jp', 'example.jp')!;
    await assert.rejects(scan(site.origin, { ...OPTS, proof: other }), /does not cover/);

    const proof = (await verifyByFile(site.origin, TOKEN, { allowPrivate: true }))!;
    const later = () => Date.now() + PROOF_TTL_MS + 1;
    await assert.rejects(scan(site.origin, { ...OPTS, proof, now: later }), /expired/);

    assert.equal(site.requests.includes('/.env'), false, 'no active probe without a valid proof');
  } finally {
    await site.close();
  }
});

test('public-by-design keys are not findings, but the owner is asked to check the access rules', async () => {
  const site = await startFixture({
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/app.js']) },
    '/app.js': {
      body: `createClient("${SUPABASE_URL}","${fake.supabaseJwt('anon')}");Stripe("${fake.stripePublishable()}");initializeApp({authDomain:"my-clinic.firebaseapp.com"})`,
    },
  });
  try {
    const assessment = await scan(site.origin, OPTS);
    assert.deepEqual(assessment.records.filter((r) => r.ruleId === 'R02'), []);
    const hints = assessment.records.filter((r) => r.ruleId === 'R01');
    assert.deepEqual(hints.map((r) => [r.verdict, r.code]).sort(), [
      ['needs_validation', 'baas.firebase_rules_unverified'],
      ['needs_validation', 'baas.supabase_rls_unverified'],
    ]);
    const summary = summarize(assessment, 'owner');
    assert.equal(summary.counts.P0, 0);
    assert.equal(summary.needsValidation, 2, 'needs_validation is not a finding and has no severity');
  } finally {
    await site.close();
  }
});

test('a site that uses neither service gets no access-rule item', async () => {
  const site = await startFixture({
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/app.js']) },
    '/app.js': { body: 'console.log("hello")' },
  });
  try {
    const assessment = await scan(site.origin, OPTS);
    assert.equal(summarize(assessment, 'owner').needsValidation, 0);
  } finally {
    await site.close();
  }
});

test('an SPA that answers every path with index.html is not reported as exposing files', async () => {
  const index = { headers: { 'content-type': 'text/html' }, body: html(['/app.js']) };
  const site = await startFixture(
    { '/': index, '/app.js': { body: 'console.log(1)' }, [WELL_KNOWN_PATH]: { body: TOKEN } },
    index,
  );
  try {
    const proof = (await verifyByFile(site.origin, TOKEN, { allowPrivate: true }))!;
    const assessment = await scan(site.origin, { ...OPTS, proof });
    assert.ok(site.requests.includes('/.env'), 'owner tier does probe');
    assert.deepEqual(assessment.records.filter((r) => r.ruleId === 'R11'), []);
  } finally {
    await site.close();
  }
});

test('a checker that fails is recorded as an error, never as "nothing found"', async () => {
  const site = await startFixture({ '/': { headers: { 'content-type': 'text/html' }, body: html([]) } });
  const broken: Checker<UrlContext> = {
    id: 'url.broken',
    layer: 'url',
    mode: 'passive',
    rules: ['R02'],
    run() {
      throw new Error('boom');
    },
  };
  try {
    const checkers = [broken, ...URL_CHECKERS.filter((c) => !c.rules.includes('R02'))];
    const assessment = await scan(site.origin, { ...OPTS, checkers });
    assert.equal(coverageOf(assessment, 'R02').status, 'error');
    assert.deepEqual(validateAssessment(assessment), []);
    const summary = summarize(assessment);
    assert.equal(summary.coverage.error, 1);
  } finally {
    await site.close();
  }
});

test('a slow target cannot hold a scan open: one deadline covers every request', async () => {
  const scripts = Array.from({ length: 10 }, (_, i) => `/s${i}.js`);
  const site = await startFixture({
    '/': { headers: { 'content-type': 'text/html' }, body: html(scripts) },
    ...Object.fromEntries(scripts.map((s) => [s, { body: 'console.log(1)', delayMs: 150 }])),
    [WELL_KNOWN_PATH]: { body: TOKEN },
  });
  try {
    const proof = (await verifyByFile(site.origin, TOKEN, { allowPrivate: true }))!;
    site.requests.length = 0;

    const started = performance.now();
    const assessment = await scan(site.origin, { ...OPTS, proof, maxDurationMs: 400 });
    const elapsed = performance.now() - started;

    // 10 scripts at 150 ms each would take 1.5 s; the budget is 0.4 s.
    assert.ok(elapsed < 1200, `scan took ${elapsed.toFixed(0)} ms`);
    assert.ok(site.requests.length < 8, `made ${site.requests.length} requests`);
    assert.equal(site.requests.includes('/.env'), false, 'no probe is started after the deadline');

    // What was not read is reported, not passed over.
    const r02 = assessment.coverage.find((u) => u.ruleId === 'R02')!;
    assert.deepEqual([r02.status, r02.note], ['partial', 'some_content_not_read']);
    assert.equal(coverageOf(assessment, 'R11').status, 'error', 'the skipped active check is not reported as clean');
    assert.deepEqual(validateAssessment(assessment), []);
  } finally {
    await site.close();
  }
});

test('script discovery stays on the same site', () => {
  const page = new URL('https://app.example.jp/dashboard');
  const found = extractScriptUrls(
    `<script src="/_next/static/chunks/main.js"></script>
     <script src='https://cdn.example.jp/a.js'></script>
     <script src=https://www.googletagmanager.com/gtag/js?id=G-1></script>
     <link rel="modulepreload" href="/assets/vendor.js">
     <link rel="stylesheet" href="/style.css">
     <script>inline()</script>`,
    page,
  );
  assert.deepEqual(found, [
    'https://app.example.jp/_next/static/chunks/main.js',
    'https://cdn.example.jp/a.js',
    'https://app.example.jp/assets/vendor.js',
  ]);
});
