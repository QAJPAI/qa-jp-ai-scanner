// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { compareAssessments } from '../src/core/compare';
import { verifyByFile, WELL_KNOWN_PATH } from '../src/ownership/file';
import { mintVerificationToken } from '../src/ownership/token';
import { servedTextReader } from '../src/url/compare';
import { referencedScripts } from '../src/url/imports';
import { closeAgents } from '../src/url/net/fetcher';
import { inspectOwner, scan, type ScanOptions } from '../src/url/scan';
import { fake, html, startFixture, type Route } from './fixture';

/**
 * Scripts that a script loads. A build splits an app into chunks; the page
 * names the entry, the entry names the rest. For a verified owner the rest is
 * read too, so a key in a chunk that loads later is found.
 */

after(closeAgents);

const FETCH = { allowPrivate: true };
const TOKEN = mintVerificationToken('test-secret-0123456789', 'acct-1', '127.0.0.1');
const SUPABASE_URL = 'https://abcdefghijklmnopqrst.supabase.co';
const serviceRole = fake.supabaseJwt('service_role');
const JS = { 'content-type': 'text/javascript' };
const HTML = { 'content-type': 'text/html' };

const page = (scripts: string[]): Route => ({ headers: HTML, body: html(scripts) });
const script = (body: string): Route => ({ headers: JS, body });
const withKey = script(`const admin=createClient("${SUPABASE_URL}","${serviceRole}");`);

async function site(routes: Record<string, Route>, fallback?: Route) {
  const live: Record<string, Route> = { ...routes, [WELL_KNOWN_PATH]: { body: TOKEN } };
  const fixture = await startFixture(live, fallback);
  const proof = await verifyByFile(fixture.origin, TOKEN, FETCH);
  assert.ok(proof);
  fixture.requests.length = 0;
  return {
    ...fixture,
    live,
    owner: (options: Omit<ScanOptions, 'proof'> = {}) =>
      inspectOwner(fixture.origin, proof, { fetch: FETCH, activeChecks: false, ...options }),
  };
}

const r02 = (a: { coverage: { ruleId: string; status: string; note?: string }[] }) =>
  a.coverage.find((u) => u.ruleId === 'R02')!;
const keys = (a: { records: { code: string; verdict: string; location?: string }[] }) =>
  a.records.filter((r) => r.code === 'secret.supabase_service_role');

// ------------------------------------------------------------ what is a reference

const at = (path: string) => new URL(`https://app.example${path}`);
const refs = (body: string, scriptPath: string, pageBase = '/') =>
  referencedScripts(body, at(scriptPath), at(pageBase)).urls.map((u) => new URL(u).pathname);

test('references: the forms a build writes, resolved the way a browser would', () => {
  // ES module imports, static and dynamic: relative to the script.
  assert.deepEqual(
    refs('import{a}from"./vendor-D4f.js";const P=()=>import(\'./Admin-9xK.js\');import`../shared/x.mjs`', '/assets/index-Ab1.js'),
    ['/assets/vendor-D4f.js', '/assets/Admin-9xK.js', '/shared/x.mjs'],
  );
  // Vite's preload list: relative to the build's base, which the script sits under.
  assert.deepEqual(refs('m.f=["assets/Admin-9xK.js","assets/Admin-9xK.css"]', '/assets/index-Ab1.js'), ['/assets/Admin-9xK.js']);
  assert.deepEqual(refs('m.f=["assets/Admin-9xK.js"]', '/app/assets/index-Ab1.js'), ['/app/assets/Admin-9xK.js']);
  // Next.js build manifest: chunks of every page, relative to /_next/.
  assert.deepEqual(
    refs('self.__BUILD_MANIFEST={"/admin":["static/chunks/pages/admin-77a.js"]}', '/_next/static/BUILD/_buildManifest.js'),
    ['/_next/static/chunks/pages/admin-77a.js'],
  );
  // From the site root.
  assert.deepEqual(refs('load("/js/late.js")', '/assets/a.js'), ['/js/late.js']);
  // A path whose first folder the script is not under: relative to the page's base.
  assert.deepEqual(refs('x="chunks/a.js"', '/main.js', '/shop/'), ['/shop/chunks/a.js']);
});

test('references: what is not collected', () => {
  // A bare name is a word, not a chunk. Text that only ends in ".js" without quotes is not a literal.
  assert.deepEqual(refs('const n="index.js";// see ./readme.js for more', '/a.js'), []);
  // Not a path: spaces, or a name put together at runtime.
  assert.deepEqual(refs('e="could not load file.js";u="static/js/"+id+"."+hash+".chunk.js"', '/a.js'), []);
  assert.deepEqual(refs('e="could not load lib/file.js"', '/a.js'), []);
  // Longer than any chunk name.
  assert.deepEqual(refs(`x="./${'a'.repeat(300)}.js"`, '/a.js'), []);
  // Other schemes cannot be written with the characters of a path.
  assert.deepEqual(refs('a="javascript:alert(1)//.js";b="data:text/javascript,1//x.js"', '/a.js'), []);
  // The script itself, and the same chunk twice.
  assert.deepEqual(refs('a="./a.js";b="./b.js";c="./b.js#x"', '/a.js'), ['/b.js']);
  // Something else that merely contains ".js".
  assert.deepEqual(refs('fetch("./data.json");fetch("./x.jsx")', '/a.js'), []);
});

test('references: a hostile script cannot make the scan slow or endless', () => {
  // Many unterminated candidates: each is looked at within a bounded window.
  const unterminated = '.js"'.padStart(4096, 'a').repeat(3000);
  const quoted = '"./c.js"'.repeat(20000);
  const dots = '.'.repeat(2_000_000);
  const started = Date.now();
  assert.deepEqual(refs(unterminated, '/a.js'), []);
  const many = referencedScripts(quoted, at('/a.js'), at('/'));
  assert.equal(many.limitHit, true, 'more occurrences than are examined is reported');
  assert.deepEqual(refs(dots, '/a.js'), []);
  assert.ok(Date.now() - started < 2000, `took ${Date.now() - started} ms`);
});

// ------------------------------------------------------------------ in a scan

test('owner: a key in a chunk that loads later is found, with the chunk as its place', async () => {
  const s = await site({
    '/': page(['/assets/index-Ab1.js']),
    '/assets/index-Ab1.js': script('import{r}from"./vendor-D4f.js";const A=()=>import("./Admin-9xK.js");m.f=["assets/Admin-9xK.js"]'),
    '/assets/vendor-D4f.js': script('export const r=1;'),
    '/assets/Admin-9xK.js': withKey,
  });
  try {
    const { assessment, everythingRead, textsRead } = await s.owner();
    const found = keys(assessment);
    assert.equal(found.length, 1);
    assert.match(found[0]!.location ?? '', /\/assets\/Admin-9xK\.js/);
    assert.equal(found[0]!.verdict, 'confirmed');
    assert.deepEqual(r02(assessment), { ...r02(assessment), status: 'partial', note: 'scripts_and_their_imports' });
    assert.equal(everythingRead, true);
    assert.ok(textsRead.has(`${s.origin}/assets/Admin-9xK.js`));
    // Each script once, in the order a breadth-first reader meets them.
    assert.deepEqual(s.requests, ['/', '/assets/index-Ab1.js', '/assets/vendor-D4f.js', '/assets/Admin-9xK.js']);
  } finally {
    await s.close();
  }
});

test('public: only what the page itself names is requested, as before', async () => {
  const s = await site({
    '/': page(['/assets/index-Ab1.js']),
    '/assets/index-Ab1.js': script('const A=()=>import("./Admin-9xK.js");'),
    '/assets/Admin-9xK.js': withKey,
  });
  try {
    const assessment = await scan(s.origin, { fetch: FETCH });
    assert.deepEqual(s.requests, ['/', '/assets/index-Ab1.js']);
    assert.equal(keys(assessment).length, 0);
    assert.equal(r02(assessment).note, 'html_referenced_scripts_only');

    // The owner can switch following off; the note then says what was read.
    s.requests.length = 0;
    const off = await s.owner({ maxFollowedScripts: 0 });
    assert.deepEqual(s.requests, ['/', '/assets/index-Ab1.js']);
    assert.equal(r02(off.assessment).note, 'html_referenced_scripts_only');
  } finally {
    await s.close();
  }
});

test('owner: a chain of chunks is followed; a chunk listed by a Next.js manifest is read', async () => {
  const s = await site({
    '/': page(['/_next/static/BUILD/_buildManifest.js', '/a.js']),
    '/_next/static/BUILD/_buildManifest.js': script('self.__BUILD_MANIFEST={"/admin":["static/chunks/pages/admin-77a.js"]}'),
    '/_next/static/chunks/pages/admin-77a.js': withKey,
    '/a.js': script('import("./b.js")'),
    '/b.js': script('import("./c.js")'),
    '/c.js': script(`const s="${fake.stripeLive()}";import("./a.js")`),
  });
  try {
    const { assessment, everythingRead } = await s.owner();
    assert.equal(keys(assessment).length, 1);
    assert.ok(assessment.records.some((r) => r.code === 'secret.stripe_live' && /\/c\.js/.test(r.location ?? '')));
    assert.equal(everythingRead, true);
    // The loop a -> b -> c -> a ends: no script is requested twice.
    assert.equal(new Set(s.requests).size, s.requests.length);
  } finally {
    await s.close();
  }
});

test('owner: a guess that is not a script is dropped without counting as unread', async () => {
  // An app that answers every unknown path with its page, and a path that does not exist.
  const s = await site(
    {
      '/': page(['/app.js']),
      '/app.js': script('const doc="docs/setup.js";const A=()=>import("./real.js");const gone="./removed.js"'),
      '/real.js': script('export default 1;'),
      '/removed.js': { status: 404, body: 'not found' },
    },
    page(['/app.js']),
  );
  try {
    const { assessment, everythingRead, textsRead } = await s.owner();
    assert.equal(everythingRead, true);
    assert.equal(r02(assessment).note, 'scripts_and_their_imports');
    assert.deepEqual([...textsRead].map((u) => new URL(u).pathname).sort(), ['/', '/app.js', '/real.js']);
    // The page served in place of a script is not read as one: its inline text is not scanned twice.
    assert.equal(assessment.records.filter((r) => r.ruleId === 'R02').length, 0);
  } finally {
    await s.close();
  }
});

test('owner: a chunk served with the wrong content type is still read', async () => {
  const s = await site({
    '/': page(['/app.js']),
    '/app.js': script('import("./plain.js")'),
    '/plain.js': { headers: { 'content-type': 'text/plain' }, body: withKey.body! },
  });
  try {
    const { assessment, everythingRead } = await s.owner();
    assert.equal(keys(assessment).length, 1);
    assert.equal(everythingRead, true);
  } finally {
    await s.close();
  }
});

test('owner: a chunk that could not be read is unread, and the result says so', async () => {
  const s = await site({
    '/': page(['/app.js']),
    '/app.js': script('import("./broken.js");import("./cut.js")'),
    '/broken.js': { status: 500, headers: JS, body: 'oops' },
    '/cut.js': script('export default 1;'),
  });
  try {
    const failed = await s.owner();
    assert.equal(failed.everythingRead, false);
    assert.equal(r02(failed.assessment).note, 'some_content_not_read');
  } finally {
    await s.close();
  }
});

test('owner: more chunks than are followed leaves the rest unread, never clean', async () => {
  const names = Array.from({ length: 6 }, (_, i) => `/c${i}.js`);
  const routes: Record<string, Route> = {
    '/': page(['/app.js']),
    '/app.js': script(names.map((n) => `import(".${n}")`).join(';')),
  };
  for (const n of names) routes[n] = script('export default 1;');
  routes['/c5.js'] = withKey;
  const s = await site(routes);
  try {
    const capped = await s.owner({ maxFollowedScripts: 3 });
    assert.deepEqual(s.requests, ['/', '/app.js', '/c0.js', '/c1.js', '/c2.js']);
    assert.equal(capped.everythingRead, false);
    assert.equal(r02(capped.assessment).note, 'some_content_not_read');
    assert.equal(keys(capped.assessment).length, 0);

    const all = await s.owner();
    assert.equal(all.everythingRead, true);
    assert.equal(keys(all.assessment).length, 1);
  } finally {
    await s.close();
  }
});

test('owner: a chain deeper than is followed is reported as unread', async () => {
  const depth = 8;
  const routes: Record<string, Route> = { '/': page(['/d0.js']) };
  for (let i = 0; i < depth; i++) routes[`/d${i}.js`] = script(i + 1 < depth ? `import("./d${i + 1}.js")` : 'export default 1;');
  const s = await site(routes);
  try {
    const { everythingRead } = await s.owner();
    assert.equal(everythingRead, false);
    assert.ok(s.requests.length < depth + 1, 'the chain was cut');
  } finally {
    await s.close();
  }
});

test('owner: more references than are examined in one script counts as unread', async () => {
  const s = await site({
    '/': page(['/app.js']),
    '/app.js': script('x="./same.js";'.repeat(6000)),
    '/same.js': script('export default 1;'),
  });
  try {
    const { assessment, everythingRead } = await s.owner();
    assert.equal(everythingRead, false);
    assert.equal(r02(assessment).note, 'some_content_not_read');
  } finally {
    await s.close();
  }
});

test('owner: the amount of text kept from chunks is bounded', async () => {
  const big = script(`/*${'x'.repeat(2_900_000)}*/export default 1;`);
  const names = Array.from({ length: 13 }, (_, i) => `/big${i}.js`);
  const routes: Record<string, Route> = { '/': page(['/app.js']), '/app.js': script(names.map((n) => `import(".${n}")`).join(';')) };
  for (const n of names) routes[n] = big;
  const s = await site(routes);
  try {
    const { everythingRead, textsRead } = await s.owner();
    assert.equal(everythingRead, false);
    assert.ok(textsRead.size < names.length + 2, `read ${textsRead.size} texts`);
    assert.ok(s.requests.length < names.length + 2);
  } finally {
    await s.close();
  }
});

test('owner: following chunks leaves time for the checks that come after', async () => {
  const slow: Route = { headers: JS, body: 'export default 1;', delayMs: 200 };
  const s = await site({
    '/': page(['/app.js']),
    '/app.js': script('import("./s0.js");import("./s1.js");import("./s2.js");import("./s3.js");import("./s4.js")'),
    '/s0.js': slow,
    '/s1.js': slow,
    '/s2.js': slow,
    '/s3.js': slow,
    '/s4.js': slow,
  });
  try {
    // Half of the budget is for chunks: three fit, the rest is reported as unread.
    const { assessment, everythingRead } = await s.owner({ maxDurationMs: 1200, activeChecks: true });
    assert.equal(everythingRead, false);
    assert.ok(!s.requests.includes('/s4.js'));
    const r11 = assessment.coverage.find((u) => u.ruleId === 'R11')!;
    assert.notEqual(r11.status, 'error', 'the active check still ran');
    assert.notEqual(r11.status, 'not_run');
  } finally {
    await s.close();
  }
});

test('owner: text from another site is not requested, nor attributed to this one', async () => {
  const other = await startFixture({ '/evil.js': withKey });
  const s = await site({
    '/': page(['/app.js']),
    // A reference to another site, and a chunk that redirects to one.
    '/app.js': script('import("//other-site.invalid/lib/evil.js");import("./moved.js")'),
    '/moved.js': { status: 302, headers: { location: `http://localhost:${other.port}/evil.js` } },
  });
  try {
    const { assessment, everythingRead, textsRead } = await s.owner();
    // Had the other site been requested, the failed request would count as an unread script.
    assert.equal(everythingRead, true);
    assert.equal(keys(assessment).length, 0);
    assert.deepEqual([...textsRead].map((u) => new URL(u).pathname).sort(), ['/', '/app.js']);
  } finally {
    await s.close();
    await other.close();
  }
});

// ----------------------------------------------------------- with the re-check

test('re-check: a key moved from the entry script into a chunk is still there', async () => {
  const s = await site({ '/': page(['/assets/index-Ab1.js']), '/assets/index-Ab1.js': withKey });
  try {
    const before = await s.owner();
    assert.equal(keys(before.assessment).length, 1);

    // "Fixed" by code splitting: the entry is clean, the key now loads with the admin screen.
    for (const path of Object.keys(s.live)) if (path !== WELL_KNOWN_PATH) delete s.live[path];
    Object.assign(s.live, {
      '/': page(['/assets/index-Zz9.js']),
      '/assets/index-Zz9.js': script('const A=()=>import("./Admin-9xK.js");'),
      '/assets/Admin-9xK.js': withKey,
    });
    const now = await s.owner();
    const cmp = compareAssessments(before.assessment, now.assessment, { wasRead: servedTextReader(now) });
    assert.equal(cmp.fixed.length, 0);
    assert.equal(cmp.stillPresent.filter((r) => r.code === 'secret.supabase_service_role').length, 1);

    // Really removed: confirmed as fixed, because the chunks were read too.
    s.live['/assets/Admin-9xK.js'] = script('export default 1;');
    const after = await s.owner();
    const fixed = compareAssessments(before.assessment, after.assessment, { wasRead: servedTextReader(after) });
    assert.deepEqual(fixed.fixed.map((r) => r.code), ['secret.supabase_service_role']);
  } finally {
    await s.close();
  }
});
