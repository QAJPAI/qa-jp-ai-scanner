// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { closeAgents } from '../src/net/fetcher';
import { confirmEmailOwnership } from '../src/ownership/email';
import { verifyByFile, WELL_KNOWN_PATH } from '../src/ownership/file';
import { PROOF_TTL_MS } from '../src/ownership/proof';
import { mintVerificationToken } from '../src/ownership/token';
import { renderOwnerReport, renderPublicSummary, toPublicSummary } from '../src/report';
import { extractScriptUrls, scan } from '../src/scanner';
import { fake, html, startFixture } from './fixture';

after(closeAgents);

const OPTS = { fetch: { allowPrivate: true } };
const TOKEN = mintVerificationToken('test-secret-0123456789', 'acct-1', '127.0.0.1');
const ENV_VALUE = 'SUPER_SECRET_DB_PASSWORD_VALUE';

const serviceRole = fake.supabaseJwt('service_role');
const stripeLive = fake.stripeLive();
const openai = fake.openai();

/** A vibe-coded app with the classic mistakes. */
const vulnerableSite = () =>
  startFixture({
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/assets/app.js'], `window.AI_KEY="${openai}"`) },
    '/assets/app.js': {
      headers: { 'content-type': 'application/javascript' },
      body: `const supabase=createClient("https://x.supabase.co","${serviceRole}");const s=Stripe("${stripeLive}");\n//# sourceMappingURL=app.js.map`,
    },
    '/assets/app.js.map': { body: '{"version":3,"sources":["src/App.tsx"],"mappings":""}' },
    '/.env': { body: `DATABASE_PASSWORD=${ENV_VALUE}\nSTRIPE_KEY=abc\n` },
    '/.git/HEAD': { body: 'ref: refs/heads/main\n' },
    [WELL_KNOWN_PATH]: { body: TOKEN },
  });

test('public tier: counts only, passive requests only, nothing identifying', async () => {
  const site = await vulnerableSite();
  try {
    const result = await scan(site.origin, OPTS);
    assert.equal(result.tier, 'public');
    assert.deepEqual(result.checksRun, ['R02', 'R14']);
    assert.equal(result.counts.P0, 3, 'service_role + Stripe live + OpenAI');
    assert.equal(result.grade, 'E');

    // Passive means passive: only the page and the script it references.
    assert.deepEqual(site.requests, ['/', '/assets/app.js']);

    const summary = toPublicSummary(result);
    assert.equal('findings' in summary, false);
    const text = renderPublicSummary(summary) + JSON.stringify(summary);
    for (const leak of ['service_role', 'Supabase', 'Stripe', 'OpenAI', 'app.js', 'offset', serviceRole, stripeLive, openai, 'sk_liv', 'eyJ']) {
      assert.equal(text.includes(leak), false, `public output leaks "${leak}"`);
    }
    assert.match(text, /総合評価: E/);
    assert.match(text, /P0（至急）3 件/);

    assert.throws(() => renderOwnerReport(result), /ownership proof/);
  } finally {
    await site.close();
  }
});

test('owner tier: file verification unlocks details and the active checks', async () => {
  const site = await vulnerableSite();
  try {
    const proof = await verifyByFile(site.origin, TOKEN, { allowPrivate: true });
    assert.ok(proof);

    const result = await scan(site.origin, { ...OPTS, proof });
    assert.equal(result.tier, 'owner');
    assert.deepEqual(result.checksRun, ['R02', 'R14', 'R11']);

    const codes = result.findings.map((f) => f.code);
    for (const expected of [
      'secret.supabase_service_role',
      'secret.stripe_live',
      'secret.openai',
      'exposed.env',
      'exposed.git',
      'exposed.sourcemap',
      'transport.no_https',
    ]) {
      assert.ok(codes.includes(expected), `missing ${expected}`);
    }

    const report = renderOwnerReport(result);
    assert.match(report, /service_role キーがフロントエンドに含まれています/);
    assert.match(report, /環境変数ファイル（\.env）が外部から取得できる状態です/);
    assert.match(report, /2 件の変数名を確認/);
    assert.match(report, /修正方法:/);

    // Detect-only: full keys and file contents never reach the report or the result.
    const everything = report + JSON.stringify(result);
    for (const secret of [serviceRole, stripeLive, openai, ENV_VALUE, 'src/App.tsx']) {
      assert.equal(everything.includes(secret), false, 'report contains fetched secret material');
    }

    // A public summary derived from an owner scan must not reveal active-check results.
    // Passive: 3 keys (P0) + no HTTPS (P1). Active adds .env (P0) and .git (P1).
    const publicCounts = toPublicSummary(result).counts;
    assert.deepEqual([publicCounts.P0, publicCounts.P1], [3, 1]);
    assert.deepEqual([result.counts.P0, result.counts.P1], [4, 2]);
    const severityOf = (code: string) => result.findings.find((f) => f.code === code)?.severity;
    assert.equal(severityOf('exposed.env'), 'P0');
    assert.equal(severityOf('transport.no_https'), 'P1');
  } finally {
    await site.close();
  }
});

test('a proof for another site, or an expired one, is rejected', async () => {
  const site = await vulnerableSite();
  try {
    const other = confirmEmailOwnership('info@example.jp', 'example.jp')!;
    await assert.rejects(scan(site.origin, { ...OPTS, proof: other }), /does not cover/);

    const proof = (await verifyByFile(site.origin, TOKEN, { allowPrivate: true }))!;
    const later = () => Date.now() + PROOF_TTL_MS + 1;
    await assert.rejects(scan(site.origin, { ...OPTS, proof, now: later }), /expired/);

    assert.equal(site.requests.includes('/.env'), false, 'no active probe without a valid proof');
  } finally {
    await site.close();
  }
});

test('public-by-design keys produce no finding', async () => {
  const site = await startFixture({
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/app.js']) },
    '/app.js': {
      body: `createClient("https://x.supabase.co","${fake.supabaseJwt('anon')}");Stripe("${fake.stripePublishable()}")`,
    },
  });
  try {
    const result = await scan(site.origin, OPTS);
    assert.deepEqual(result.findings.filter((f) => f.ruleId === 'R02'), []);
    assert.equal(result.counts.P0, 0);
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
    const result = await scan(site.origin, { ...OPTS, proof });
    assert.ok(site.requests.includes('/.env'), 'owner tier does probe');
    assert.deepEqual(result.findings.filter((f) => f.ruleId === 'R11'), []);
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
