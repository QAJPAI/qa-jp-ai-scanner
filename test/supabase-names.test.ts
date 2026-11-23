// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { compareAssessments } from '../src/core/compare';
import { renderFixRequest } from '../src/fixrequest';
import { verifyByFile, WELL_KNOWN_PATH } from '../src/ownership/file';
import { mintVerificationToken } from '../src/ownership/token';
import { renderOwnerReport } from '../src/report';
import { servedTextReader } from '../src/url/compare';
import { closeAgents } from '../src/url/net/fetcher';
import { inspectOwner, scan } from '../src/url/scan';
import { supabaseNames } from '../src/url/supabase-names';
import { CASE_TOKEN, startCaseSite } from './case-site';
import { fake, html, startFixture, type Route } from './fixture';

/**
 * Strengthening 3 and 4, part A: the names a site's own code gives to its
 * tables and public buckets make the owner's questions concrete. No request
 * is made to the database or the storage.
 */

after(closeAgents);

const FETCH = { allowPrivate: true };
const TOKEN = mintVerificationToken('test-secret-0123456789', 'acct-1', '127.0.0.1');
const SUPABASE_URL = 'https://abcdefghijklmnopqrst.supabase.co';
const JS = { 'content-type': 'text/javascript' };
const client = `const sb=createClient("${SUPABASE_URL}","${fake.supabaseJwt('anon')}");`;

const names = (body: string) => supabaseNames([{ body }]);

// ------------------------------------------------------------------ the names

test('names: tables and public buckets, in the forms a build keeps', () => {
  const found = names(
    client +
      // Property names survive minification; the client's variable name does not.
      'e.from("profiles").select("*");t.from(\'messages\').insert(m);n.from(`likes`).delete();' +
      'fetch(u+"/rest/v1/payments?select=*");fetch(u+"/rest/v1/audit_log");' +
      'const img=u+"/storage/v1/object/public/id-cards/"+id+".jpg";' +
      'const a=e.storage.from("avatars").getPublicUrl(path);' +
      'const p=`${u}/storage/v1/object/public/product-images/${file}`;',
  );
  assert.deepEqual(found.tables, ['profiles', 'messages', 'likes', 'payments', 'audit_log']);
  assert.deepEqual(found.publicBuckets, ['avatars', 'id-cards', 'product-images']);
  assert.equal(found.limitHit, false);
});

test('names: what is not a table, and what is not a public bucket', () => {
  // Other things called from(): built-ins, animation libraries, a second argument, a variable.
  assert.deepEqual(
    names('Array.from("abc");Buffer.from("text");gsap.from(".box",{x:1});rx.from(list);x.from("a b");x.from("9lives");x.from("")').tables,
    [],
  );
  // A bucket that is used, but not as public: downloads and signed URLs go through the API with the user's login.
  const priv = names('s.storage.from("contracts").download(p);s.storage.from("contracts").createSignedUrl(p,60);');
  assert.deepEqual(priv.publicBuckets, []);
  // A bucket is not a table.
  assert.deepEqual(priv.tables, []);
  // The bucket's name is not written out: nothing to name.
  assert.deepEqual(names('u+"/storage/v1/object/public/"+bucket+"/"+f;`/storage/v1/object/public/${b}/x`').publicBuckets, []);
  // Functions and the bare prefix are not tables.
  assert.deepEqual(names('fetch("/rest/v1/rpc/do_thing");fetch(u+"/rest/v1/"+t)').tables, []);
  // A second argument: not the Supabase call.
  assert.deepEqual(names('anim.from("items",{x:1})').tables, []);
  // Only part of the bucket's name is written out.
  assert.deepEqual(names('`${u}/storage/v1/object/public/user-${id}/a.png`').publicBuckets, []);
  // Longer than a table name can be.
  assert.deepEqual(names(`a.from("${'t'.repeat(63)}");b.from("${'u'.repeat(64)}")`).tables, ['t'.repeat(63)]);
  // The same name twice is one name.
  assert.deepEqual(names('a.from("t1");b.from("t1")').tables, ['t1']);
});

test('names: a hostile script cannot make this slow, and too many names are reported as such', () => {
  const started = Date.now();
  assert.deepEqual(names('.from("' + 'a'.repeat(3_000_000)).tables, []);
  assert.deepEqual(names('.from('.repeat(500_000)).tables, []);
  assert.deepEqual(names('/storage/v1/object/public/' + 'b'.repeat(3_000_000)).publicBuckets, []);
  const many = names(Array.from({ length: 6000 }, (_, i) => `x.from("t${i}")`).join(';'));
  assert.equal(many.limitHit, true);
  assert.equal(many.tables.length, 20);
  assert.ok(Date.now() - started < 2000, `took ${Date.now() - started} ms`);
});

// ------------------------------------------------------------------ in a check

async function ownerCheck(routes: Record<string, Route>) {
  const live: Record<string, Route> = { ...routes, [WELL_KNOWN_PATH]: { body: TOKEN } };
  const site = await startFixture(live);
  const proof = await verifyByFile(site.origin, TOKEN, FETCH);
  assert.ok(proof);
  return {
    site,
    live,
    proof,
    check: () => inspectOwner(site.origin, proof, { fetch: FETCH, activeChecks: false }),
  };
}

test('case site: the owner is asked about the tables and the bucket by name, and nothing is confirmed', async () => {
  const site = await startCaseSite('vulnerable');
  try {
    const proof = await verifyByFile(site.origin, CASE_TOKEN, FETCH);
    assert.ok(proof);
    const { assessment } = await inspectOwner(site.origin, proof, { fetch: FETCH });

    const rls = assessment.records.find((r) => r.code === 'baas.supabase_rls_unverified')!;
    assert.equal(rls.verdict, 'needs_validation');
    assert.match(rls.evidence, /コードに書かれているテーブル名: profiles$/);

    const buckets = assessment.records.filter((r) => r.ruleId === 'R06');
    assert.equal(buckets.length, 1);
    const bucket = buckets[0]!;
    assert.deepEqual([bucket.verdict, bucket.code], ['needs_validation', 'storage.supabase_public_bucket']);
    assert.match(bucket.evidence, /バケット「id-cards」を公開の置き場として参照しています（中に何があるかは確認していません）/);
    assert.match(bucket.location, /\/assets\/app\.js$/);

    // The rule is examined in part, and says how little that part is.
    const r06 = assessment.coverage.find((u) => u.ruleId === 'R06')!;
    assert.deepEqual([r06.status, r06.note, r06.mode], ['partial', 'names_in_code_only', 'passive']);

    // The owner reads it in plain words, and the AI is told to ask, not to answer.
    const report = renderOwnerReport(assessment, proof);
    assert.match(report, /ファイルを、誰でも開ける公開の置き場（公開バケット）に置いています（R06）/);
    assert.match(report, /本人確認書類・契約書・診療記録などを置いている場合は、バケットを非公開（Private）に変更/);
    const request = renderFixRequest(assessment);
    assert.match(request, /## 利用者に確認していただく項目（2 件）/);
    assert.ok(request.includes(bucket.fingerprint));

    // Reading names is reading the page: the site saw the same requests as before, none for data.
    assert.equal(site.requests.some((p) => p.startsWith('/api/') || p.includes('/storage/') || p.includes('/rest/')), false);
  } finally {
    await site.close();
  }
});

test('a site that uses no bucket as public is asked nothing about storage; the public view never shows any of it', async () => {
  const withBucket = await ownerCheck({
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/app.js']) },
    '/app.js': { headers: JS, body: `${client}sb.from("profiles").select();const i=sb.storage.from("id-cards").getPublicUrl(p)` },
  });
  const without = await ownerCheck({
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/app.js']) },
    '/app.js': { headers: JS, body: `${client}const i=await sb.storage.from("id-cards").createSignedUrl(p,60)` },
  });
  try {
    const a = (await withBucket.check()).assessment;
    const b = (await without.check()).assessment;
    assert.equal(a.records.filter((r) => r.ruleId === 'R06').length, 1);
    assert.equal(b.records.filter((r) => r.ruleId === 'R06').length, 0);
    // Without table names the question about access rules is the general one.
    assert.equal(b.records.find((r) => r.code === 'baas.supabase_rls_unverified')!.evidence.includes('テーブル名'), false);
    // Both were examined to the same extent.
    assert.deepEqual(a.coverage.find((u) => u.ruleId === 'R06'), b.coverage.find((u) => u.ruleId === 'R06'));

    // A public check runs the same passive readers; its ledger is the same for both sites.
    const pa = await scan(withBucket.site.origin, { fetch: FETCH });
    const pb = await scan(without.site.origin, { fetch: FETCH });
    assert.deepEqual(pa.coverage, pb.coverage);
  } finally {
    await withBucket.site.close();
    await without.site.close();
  }
});

test('re-check: a bucket no longer used as public resolves its question, unless the script was not read', async () => {
  const page = (scripts: string[]): Route => ({ headers: { 'content-type': 'text/html' }, body: html(scripts) });
  const s = await ownerCheck({
    '/': page(['/app-1.js']),
    '/app-1.js': { headers: JS, body: `${client}const i=sb.storage.from("id-cards").getPublicUrl(p)` },
  });
  const publish = (next: Record<string, Route>) => {
    for (const path of Object.keys(s.live)) if (path !== WELL_KNOWN_PATH) delete s.live[path];
    Object.assign(s.live, next);
  };
  try {
    const before = await s.check();

    // Fixed: signed URLs. The build renamed its output.
    publish({ '/': page(['/app-2.js']), '/app-2.js': { headers: JS, body: `${client}const i=await sb.storage.from("id-cards").createSignedUrl(p,60)` } });
    const fixed = await s.check();
    const cmp = compareAssessments(before.assessment, fixed.assessment, { wasRead: servedTextReader(fixed) });
    assert.deepEqual(cmp.questionsResolved.map((r) => r.code), ['storage.supabase_public_bucket']);

    // Not fixed, only unread: the script fails, so the question is not called resolved.
    publish({ '/': page(['/app-3.js']), '/app-3.js': { status: 500, headers: JS, body: 'oops' } });
    const unread = await s.check();
    const cmp2 = compareAssessments(before.assessment, unread.assessment, { wasRead: servedTextReader(unread) });
    assert.equal(cmp2.questionsResolved.some((r) => r.ruleId === 'R06'), false);
    assert.equal(cmp2.questionsUnverified.some((u) => u.record.ruleId === 'R06'), true);
  } finally {
    await s.site.close();
  }
});
