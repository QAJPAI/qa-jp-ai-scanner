// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { summarize } from '../src/core/assessment';
import { buildLedger, countCoverage, type CoverageUnit } from '../src/core/coverage';
import { recordFactory } from '../src/core/records';
import { validateAssessment } from '../src/core/validate';
import { verifyByFile, WELL_KNOWN_PATH } from '../src/ownership/file';
import { mintVerificationToken } from '../src/ownership/token';
import { renderPublicSummary, toPublicSummary } from '../src/report';
import { MAX_SECRET_RECORDS, scanTextForSecrets } from '../src/url/checkers/secrets';
import { checkTransport } from '../src/url/checkers/transport';
import { closeAgents, safeFetch } from '../src/url/net/fetcher';
import { isBlockedAddress, makeGuardedLookup } from '../src/url/net/guard';
import { discoverScripts, scan, ScanError } from '../src/url/scan';
import { fake, html, startFixture } from './fixture';

/**
 * Regression tests for defects found by an independent review (2026-11-12).
 * Each test fails on the code as it was before the fix.
 */

after(closeAgents);

const OPTS = { fetch: { allowPrivate: true } };
const SECRET = 'test-secret-0123456789';
const tokenFor = (host: string) => mintVerificationToken(SECRET, 'acct-1', host);
const make = recordFactory('test', 'url', 'passive');
const page = (scripts: string[] = []) => ({ headers: { 'content-type': 'text/html' }, body: html(scripts) });
const unit = (a: { coverage: CoverageUnit[] }, ruleId: string): CoverageUnit =>
  a.coverage.find((u) => u.ruleId === ruleId)!;

// ---------------------------------------------------------------- redirects

test('an owner scan never follows a redirect to a site the proof does not cover', async () => {
  const victim = await startFixture({
    '/': page(['/app.js']),
    '/app.js': { body: `Stripe("${fake.stripeLive()}")` },
    '/.env': { body: 'DB_PASSWORD=x\n' },
    '/.git/HEAD': { body: 'ref: refs/heads/main\n' },
  });
  // The attacker owns this site, proves it, and points its front page at the victim.
  const attackerToken = tokenFor('localhost');
  const attacker = await startFixture({
    '/': { status: 302, headers: { location: `${victim.origin}/` } },
    [WELL_KNOWN_PATH]: { body: attackerToken },
  });
  const attackerOrigin = `http://localhost:${attacker.port}`;
  try {
    const proof = await verifyByFile(attackerOrigin, attackerToken, { allowPrivate: true });
    assert.ok(proof, 'the attacker really does own their own site');

    await assert.rejects(scan(attackerOrigin, { ...OPTS, proof }), (err: unknown) => {
      assert.ok(err instanceof ScanError);
      assert.equal(err.code, 'redirected_elsewhere');
      return true;
    });
    // The victim saw one ordinary page load and nothing else: no script fetch, no probe.
    assert.deepEqual(victim.requests, ['/']);

    // The same address without a proof is refused too: no grade for B under A's name.
    await assert.rejects(scan(attackerOrigin, OPTS), { code: 'redirected_elsewhere' });
  } finally {
    await Promise.all([victim.close(), attacker.close()]);
  }
});

test('redirect targets are validated on every hop, with the guard active', async () => {
  const other = await startFixture({ '/': { body: 'internal' } });
  const site = await startFixture({
    '/to-metadata': { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' } },
    '/to-other-port': { status: 302, headers: { location: `http://localhost:${other.port}/` } },
    '/to-file': { status: 302, headers: { location: 'file:///etc/passwd' } },
    '/ok': { body: 'fine' },
  });
  // Only this exact host and port is permitted; every other guard stays on.
  const guarded = { allowOnly: { host: '127.0.0.1', port: site.port }, timeoutMs: 3000 };
  try {
    assert.equal((await safeFetch(`${site.origin}/ok`, guarded)).body, 'fine');
    for (const path of ['/to-metadata', '/to-other-port', '/to-file']) {
      await assert.rejects(safeFetch(site.origin + path, guarded), { code: 'QA_BLOCKED_ADDRESS' }, path);
    }
    assert.deepEqual(other.requests, [], 'the second hop was never contacted');
  } finally {
    await Promise.all([site.close(), other.close()]);
  }
});

test('verification and file probes do not follow a redirect to another host', async () => {
  const token = tokenFor('127.0.0.1');
  const elsewhere = await startFixture({
    [WELL_KNOWN_PATH]: { body: token },
    '/.env': { body: 'DB_PASSWORD=x\n' },
  });
  const elsewhereOrigin = `http://localhost:${elsewhere.port}`;
  const site = await startFixture({
    '/': page(),
    [WELL_KNOWN_PATH]: { status: 302, headers: { location: elsewhereOrigin + WELL_KNOWN_PATH } },
    '/.env': { status: 302, headers: { location: `${elsewhereOrigin}/.env` } },
  });
  // This one really is verified, but its /.env answers with a redirect to the other host.
  const honest = await startFixture({
    '/': page(),
    [WELL_KNOWN_PATH]: { body: token },
    '/.env': { status: 302, headers: { location: `${elsewhereOrigin}/.env` } },
  });
  try {
    // A token served by some other host proves nothing about this one.
    assert.equal(await verifyByFile(site.origin, token, { allowPrivate: true }), undefined);

    const proof = (await verifyByFile(honest.origin, token, { allowPrivate: true }))!;
    const assessment = await scan(honest.origin, { ...OPTS, proof });
    assert.deepEqual(assessment.records.filter((r) => r.code === 'exposed.env'), []);
    assert.equal(elsewhere.requests.includes('/.env'), false);
  } finally {
    await Promise.all([site.close(), elsewhere.close(), honest.close()]);
  }
});

// ---------------------------------------------------------------- guard

test('IPv6 forms that embed or translate IPv4 are blocked', () => {
  for (const address of [
    '::7f00:1', '::a9fe:a9fe', '::127.0.0.1', '64:ff9b:1::7f00:1', '2002:7f00:1::1', '2002:a9fe:a9fe::1',
    '2001:0:4136:e378:8000:63bf:3fff:fdd2', 'fec0::1', '100::1', 'fd00:ec2::254', '2001:db8::1', '3fff::1',
    '192.88.99.1',
  ]) {
    assert.equal(isBlockedAddress(address), true, address);
  }
  for (const address of ['2606:4700:4700::1111', '2400:cb00::1', '2a00:1450:4001::1', '8.8.8.8']) {
    assert.equal(isBlockedAddress(address), false, address);
  }
});

test('a name is refused if any of its addresses is non-public, and the message says nothing about why', async () => {
  const lookupWith = (addresses: string[]) =>
    new Promise<Error | null>((resolve) => {
      const lookup = makeGuardedLookup((_host, _opts, cb) =>
        cb(null, addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))),
      );
      lookup('intranet.example', { all: true }, (err) => resolve(err));
    });

  assert.equal(await lookupWith(['93.184.216.34']), null);
  for (const addresses of [['10.0.0.5'], ['93.184.216.34', '10.0.0.5'], ['10.0.0.5', '93.184.216.34'], []]) {
    const err = await lookupWith(addresses);
    assert.ok(err, JSON.stringify(addresses));
    assert.equal((err as { code?: string }).code, 'QA_BLOCKED_ADDRESS');
    // Same words for every cause: a requester cannot map the operator's internal DNS.
    assert.equal(err.message, 'This address cannot be scanned');
  }

  const failing = makeGuardedLookup((_h, _o, cb) => cb(Object.assign(new Error('nope'), { code: 'ENOTFOUND' }), []));
  const err = await new Promise<Error | null>((resolve) => failing('nx.example', {}, (e) => resolve(e)));
  assert.equal(err?.message, 'This address cannot be scanned');
});

// ---------------------------------------------------------------- time

test('one deadline covers all redirects of a single fetch', async () => {
  const site = await startFixture({
    '/a': { status: 302, headers: { location: '/b' }, delayMs: 250 },
    '/b': { status: 302, headers: { location: '/c' }, delayMs: 250 },
    '/c': { status: 302, headers: { location: '/d' }, delayMs: 250 },
    '/d': { body: 'late', delayMs: 250 },
  });
  try {
    const started = performance.now();
    // Each hop answers inside the 300 ms per-hop limit; together they take 1 s.
    await assert.rejects(safeFetch(`${site.origin}/a`, { allowPrivate: true, timeoutMs: 300 }));
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 900, `took ${elapsed.toFixed(0)} ms; the whole call is capped at 2 x timeoutMs`);
  } finally {
    await site.close();
  }
});

// ---------------------------------------------------------------- coverage honesty

test('an error page is not graded', async () => {
  const site = await startFixture({ '/': { status: 503, headers: { 'content-type': 'text/html' }, body: html([]) } });
  try {
    await assert.rejects(scan(site.origin, OPTS), { code: 'page_unavailable' });
  } finally {
    await site.close();
  }
});

test('a script that could not be read is reported, not treated as clean', async () => {
  const site = await startFixture({
    '/': page(['/ok.js', '/broken.js']),
    '/ok.js': { body: 'console.log(1)' },
    '/broken.js': { status: 500, body: `Stripe("${fake.stripeLive()}")` },
  });
  try {
    const assessment = await scan(site.origin, OPTS);
    assert.deepEqual([unit(assessment, 'R02').status, unit(assessment, 'R02').note], ['partial', 'some_content_not_read']);
  } finally {
    await site.close();
  }
});

test('scripts beyond the cap, and truncated scripts, are reported', async () => {
  const names = Array.from({ length: 4 }, (_, i) => `/s${i}.js`);
  const site = await startFixture({
    '/': page(names),
    ...Object.fromEntries(names.map((n) => [n, { body: 'console.log(1)' }])),
  });
  try {
    const capped = await scan(site.origin, { ...OPTS, maxScripts: 2 });
    assert.equal(unit(capped, 'R02').note, 'some_content_not_read');
    const all = await scan(site.origin, OPTS);
    assert.equal(unit(all, 'R02').note, 'html_referenced_scripts_only');
  } finally {
    await site.close();
  }
});

test('a page full of key-shaped decoys cannot crash the check or hide a real key', async () => {
  const decoys = Array.from({ length: 5000 }, (_, i) => `"AKIA${String(i).padStart(16, 'A')}"`).join(',');
  const site = await startFixture({
    '/': page(['/app.js']),
    '/app.js': { body: `Stripe("${fake.stripeLive()}");const d=[${decoys}]` },
  });
  try {
    const assessment = await scan(site.origin, OPTS);
    assert.deepEqual([unit(assessment, 'R02').status, unit(assessment, 'R02').note], ['partial', 'record_limit_reached']);
    assert.ok(assessment.records.length <= MAX_SECRET_RECORDS + 10);
    assert.ok(assessment.records.some((r) => r.code === 'secret.stripe_live'), 'the real key is still reported');
    assert.equal(summarize(assessment).grade, 'E');
    assert.deepEqual(validateAssessment(assessment), [], 'the engine never emits a result its own validator rejects');
  } finally {
    await site.close();
  }
});

test('a failed check is shown next to the grade', () => {
  const coverage = buildLedger('url', [
    { checker: 'url.secrets', mode: 'passive', reports: [{ ruleId: 'R02', status: 'error' }] },
    { checker: 'url.transport', mode: 'passive', reports: [{ ruleId: 'R14', status: 'checked' }] },
  ]);
  const text = renderPublicSummary(
    toPublicSummary({
      schema: 'qa-jp-ai/assessment@1',
      engineVersion: 'x',
      rulesVersion: '0.1.0',
      target: { layer: 'url', host: 'example.jp' },
      tier: 'public',
      startedAt: '2026-11-12T00:00:00.000Z',
      records: [],
      coverage,
    }),
  );
  assert.match(text, /総合評価: A/);
  assert.match(text, /1 項目の検査が完了しなかったため、この評価は不完全です/);
});

// ---------------------------------------------------------------- R11

const withToken = (routes: Record<string, object>, fallback?: object) =>
  startFixture({ '/': page(), [WELL_KNOWN_PATH]: { body: tokenFor('127.0.0.1') }, ...routes }, fallback);

async function ownerScan(site: { origin: string }) {
  const proof = (await verifyByFile(site.origin, tokenFor('127.0.0.1'), { allowPrivate: true }))!;
  return scan(site.origin, { ...OPTS, proof });
}

test('R11: a server that answers every path the same way exposes nothing', async () => {
  const textCatchAll = await withToken({}, { body: 'error=not_found' });
  const jsonCatchAll = await startFixture(
    {
      '/': page(['/app.js']),
      '/app.js': { body: 'console.log(1)\n//# sourceMappingURL=app.js.map' },
      [WELL_KNOWN_PATH]: { body: tokenFor('127.0.0.1') },
    },
    { headers: { 'content-type': 'application/json' }, body: '{"error":"not found","version":"1.2.0"}' },
  );
  try {
    assert.deepEqual((await ownerScan(textCatchAll)).records.filter((r) => r.ruleId === 'R11'), []);
    assert.deepEqual((await ownerScan(jsonCatchAll)).records.filter((r) => r.ruleId === 'R11'), []);
  } finally {
    await Promise.all([textCatchAll.close(), jsonCatchAll.close()]);
  }
});

test('R11: finds .env variants and the export form', async () => {
  const a = await withToken({ '/.env.production': { body: 'API_SECRET=abc\n' } });
  const b = await withToken({ '/.env': { body: '# settings\nexport DATABASE_URL=postgres://x\nexport KEY=1\n' } });
  try {
    const ra = (await ownerScan(a)).records.filter((r) => r.code === 'exposed.env');
    assert.equal(ra.length, 1);
    assert.match(ra[0]!.location, /\/\.env\.production$/);
    assert.equal((await ownerScan(b)).records.filter((r) => r.code === 'exposed.env').length, 1);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test('R11: "could not ask" is not "not there"', async () => {
  const some = await withToken({ '/.git/HEAD': { destroy: true } });
  const none = await withToken({}, { destroy: true });
  try {
    const partial = await ownerScan(some);
    assert.deepEqual([unit(partial, 'R11').status, unit(partial, 'R11').note], ['partial', 'some_probes_failed']);
    assert.equal(unit(await ownerScan(none), 'R11').status, 'error');
  } finally {
    await Promise.all([some.close(), none.close()]);
  }
});

// ---------------------------------------------------------------- fingerprints

test('a private key keeps its fingerprint when the bundle is renamed or shifted', () => {
  const pem = '-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\n-----END PRIVATE KEY-----';
  const other = '-----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDZ\\n-----END PRIVATE KEY-----';
  const a = scanTextForSecrets('https://example.jp/assets/index-abc123.js', `const k="${pem}"`, make);
  const b = scanTextForSecrets('https://example.jp/assets/index-def456.js', `/* one more line */\nconst k="${pem}"`, make);
  const c = scanTextForSecrets('https://example.jp/assets/index-abc123.js', `const k="${other}"`, make);
  assert.equal(a.length, 1);
  assert.equal(a[0]!.fingerprint, b[0]!.fingerprint);
  assert.notEqual(a[0]!.fingerprint, c[0]!.fingerprint);
  assert.equal(JSON.stringify(a).includes('MIIEvQIBADAN'), false, 'key body is not recorded');
});

// ---------------------------------------------------------------- R14

test('R14: cookie names are matched as words, and CSRF cookies are left readable', () => {
  const cookies = (list: string[]) =>
    checkTransport(
      {
        finalUrl: 'https://example.jp/',
        headers: {
          'strict-transport-security': ['max-age=31536000'],
          'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
          'x-content-type-options': ['nosniff'],
          'set-cookie': list,
        },
        httpRedirectsToHttps: true,
      },
      make,
    ).map((r) => r.location);

  assert.deepEqual(cookies(['XSRF-TOKEN=a; Secure; SameSite=Lax', 'csrftoken=a; Secure', 'consider_banner=1; Secure', 'residence=jp; Secure']), []);
  assert.deepEqual(
    cookies(['PHPSESSID=a; Secure', 'connect.sid=a; Secure', 'sb-access-token=a; Secure', '__Secure-next-auth.session-token=a; Secure']),
    ['Cookie: PHPSESSID', 'Cookie: connect.sid', 'Cookie: sb-access-token', 'Cookie: __Secure-next-auth.session-token'],
  );
});

test('R14: HSTS with max-age=0 is off, and a CSP in a <meta> element counts', () => {
  const codes = (headers: Record<string, string[]>, htmlText?: string) =>
    checkTransport({ finalUrl: 'https://example.jp/', headers, httpRedirectsToHttps: true, html: htmlText }, make).map((r) => r.code);
  const base = { 'x-content-type-options': ['nosniff'], 'x-frame-options': ['DENY'] };

  assert.deepEqual(codes({ ...base, 'strict-transport-security': ['max-age=0'] }, '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'), ['header.hsts_missing']);
  assert.deepEqual(codes({ ...base, 'strict-transport-security': ['max-age=63072000; includeSubDomains'] }), ['header.csp_missing']);
});

// ---------------------------------------------------------------- script discovery

test('script discovery: case folding, quoted ">", entities, <base>, and the tag cap', () => {
  const at = new URL('https://example.jp/app/');
  const urls = (h: string) => discoverScripts(h, at).urls;

  // "İ" lower-cases to two code units; indices must not drift.
  assert.deepEqual(urls('<title>İİİİİİİİİİ</title><script src="/app.js"></script>'), ['https://example.jp/app.js']);
  assert.deepEqual(urls('<script data-x="a>b" src="/app.js"></script>'), ['https://example.jp/app.js']);
  assert.deepEqual(urls('<script src="/a.js?x=1&amp;y=2"></script>'), ['https://example.jp/a.js?x=1&y=2']);
  assert.deepEqual(urls('<base href="/static/"><script src="main.js"></script>'), ['https://example.jp/static/main.js']);

  const flooded = discoverScripts('<script></script>'.repeat(2500) + '<script src="/late.js"></script>', at);
  assert.equal(flooded.tagLimitHit, true, 'hitting the cap is reported so coverage can say so');
});

// ---------------------------------------------------------------- core

test('the public coverage view is the same whether or not an owner-only check also covered the rule', () => {
  const passiveOnly = buildLedger('url', [
    { checker: 'p', mode: 'passive', reports: [{ ruleId: 'R02', status: 'partial', note: 'html_referenced_scripts_only' }] },
  ]);
  const both = buildLedger('url', [
    { checker: 'p', mode: 'passive', reports: [{ ruleId: 'R02', status: 'partial', note: 'html_referenced_scripts_only' }] },
    { checker: 'a', mode: 'active', reports: [{ ruleId: 'R02', status: 'checked' }] },
  ]);
  assert.deepEqual(countCoverage(both, 'public'), countCoverage(passiveOnly, 'public'));
  assert.equal(countCoverage(both, 'owner').checked, 1);
  const r02 = both.find((u) => u.ruleId === 'R02')!;
  assert.deepEqual([r02.mode, r02.status, r02.passive?.status], ['active', 'checked', 'partial']);
});

test('validator: dates, target, enums, unknown fields and record modes', async () => {
  const site = await startFixture({ '/': page(['/app.js']), '/app.js': { body: `Stripe("${fake.stripeLive()}")` } });
  try {
    const good = await scan(site.origin, OPTS);
    assert.deepEqual(validateAssessment(good), []);
    const errors = (mutate: (a: any) => void) => {
      const copy = JSON.parse(JSON.stringify(good));
      mutate(copy);
      return validateAssessment(copy).join('\n');
    };
    const r02 = (a: any) => a.coverage.find((u: any) => u.ruleId === 'R02');
    const r05 = (a: any) => a.coverage.find((u: any) => u.ruleId === 'R05');

    assert.match(errors((a) => (a.startedAt = 'yesterday')), /startedAt must be an ISO 8601/);
    assert.match(errors((a) => delete a.target.host), /target\.host must be a non-empty string/);
    assert.match(errors((a) => (a.target.extra = 1)), /target: unknown field "extra"/);
    assert.match(errors((a) => (a.debug = 'x')), /unknown field "debug"/);
    assert.match(errors((a) => (r02(a).leak = 'sk_live_whatever')), /unknown field "leak"/);
    assert.match(errors((a) => (r02(a).note = 'because')), /partial requires a known note/);
    assert.match(errors((a) => (r05(a).reason = 'because')), /not_run requires a known reason/);
    assert.match(errors((a) => (r05(a).note = 'html_referenced_scripts_only')), /not_run must not carry "note"/);
    // A passive finding relabelled "active" would vanish from the public count.
    assert.match(
      errors((a) => {
        a.tier = 'owner';
        a.records[0].mode = 'active';
      }),
      /has a active record but no active coverage/,
    );
  } finally {
    await site.close();
  }
});
