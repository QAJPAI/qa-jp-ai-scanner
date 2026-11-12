// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { closeAgents } from '../src/url/net/fetcher';
import { verifyByDns } from '../src/ownership/dns';
import { confirmEmailOwnership, evaluateEmailOwnership } from '../src/ownership/email';
import { verifyByFile, WELL_KNOWN_PATH } from '../src/ownership/file';
import { ownershipSubject, proofCovers, PROOF_TTL_MS } from '../src/ownership/proof';
import { mintVerificationToken } from '../src/ownership/token';
import { html, startFixture } from './fixture';

after(closeAgents);

const SECRET = 'test-secret-0123456789';

const decide = (email: string, host: string) => {
  const d = evaluateEmailOwnership(email, host);
  return d.status === 'eligible' ? 'eligible' : d.reason;
};

test('email: same registrable domain is accepted', () => {
  assert.equal(decide('info@example.co.jp', 'www.example.co.jp'), 'eligible');
  assert.equal(decide('Info@Mail.Example.co.jp', 'app.example.co.jp'), 'eligible');
  assert.equal(decide('owner@clinic-example.jp', 'clinic-example.jp'), 'eligible');
});

test('email: the three holes are closed', () => {
  // 1. hosting-platform subdomains have no mailbox of their own
  assert.equal(decide('me@myapp.vercel.app', 'myapp.vercel.app'), 'platform_subdomain');
  assert.equal(decide('me@example.jp', 'myapp.web.app'), 'platform_subdomain');
  // 2. free mail and carrier mail prove nothing
  assert.equal(decide('someone@gmail.com', 'example.jp'), 'free_mail');
  assert.equal(decide('someone@yahoo.co.jp', 'example.jp'), 'free_mail');
  assert.equal(decide('someone@softbank.ne.jp', 'example.jp'), 'free_mail');
  assert.equal(decide('someone@abc.ocn.ne.jp', 'example.jp'), 'free_mail');
  // 3. large shared organisations: admin mailboxes only
  assert.equal(decide('student@g.example-univ.ac.jp', 'circle.example-univ.ac.jp'), 'admin_only');
  assert.equal(decide('webmaster@example-univ.ac.jp', 'circle.example-univ.ac.jp'), 'eligible');
  assert.equal(decide('staff@city.example.lg.jp', 'city.example.lg.jp'), 'admin_only');
  assert.equal(decide('someone@example.edu', 'lab.example.edu'), 'admin_only');
});

test('email: other rejections', () => {
  assert.equal(decide('info@other.jp', 'example.jp'), 'domain_mismatch');
  assert.equal(decide('info@example.com', 'example.jp'), 'domain_mismatch');
  assert.equal(decide('info@evil-example.jp', 'example.jp'), 'domain_mismatch');
  assert.equal(decide('not-an-email', 'example.jp'), 'invalid');
  assert.equal(decide('info@example.jp', '192.0.2.10'), 'ip_address');
});

test('email proof covers the domain and its subdomains, and expires', () => {
  const now = 1_000_000;
  const proof = confirmEmailOwnership('info@example.jp', 'www.example.jp', now)!;
  assert.ok(proof);
  assert.equal(proofCovers(proof, 'example.jp', now), true);
  assert.equal(proofCovers(proof, 'app.example.jp', now), true);
  assert.equal(proofCovers(proof, 'evilexample.jp', now), false);
  assert.equal(proofCovers(proof, 'example.jp.attacker.com', now), false);
  assert.equal(proofCovers(proof, 'example.jp', now + PROOF_TTL_MS), false);
  assert.equal(confirmEmailOwnership('someone@gmail.com', 'example.jp'), undefined);
});

test('token is deterministic and bound to account and subject', () => {
  const t1 = mintVerificationToken(SECRET, 'acct-1', 'example.jp');
  assert.equal(t1, mintVerificationToken(SECRET, 'acct-1', 'EXAMPLE.jp'));
  assert.match(t1, /^qa-jp-ai-verify-[A-Za-z0-9_-]{32}$/);
  assert.notEqual(t1, mintVerificationToken(SECRET, 'acct-2', 'example.jp'));
  assert.notEqual(t1, mintVerificationToken(SECRET, 'acct-1', 'other.jp'));
  assert.notEqual(t1, mintVerificationToken(SECRET + 'x', 'acct-1', 'example.jp'));
  assert.throws(() => mintVerificationToken('short', 'acct-1', 'example.jp'));
  assert.equal(ownershipSubject('www.example.co.jp'), 'example.co.jp');
  assert.equal(ownershipSubject('myapp.vercel.app'), 'myapp.vercel.app');
});

test('file: exact token passes; wrong token, missing file and SPA fallback fail', async () => {
  const token = mintVerificationToken(SECRET, 'acct-1', '127.0.0.1');
  const good = await startFixture({ [WELL_KNOWN_PATH]: { body: `${token}\n` } });
  const wrong = await startFixture({ [WELL_KNOWN_PATH]: { body: 'qa-jp-ai-verify-' + 'z'.repeat(32) } });
  const missing = await startFixture({});
  const spa = await startFixture({}, { headers: { 'content-type': 'text/html' }, body: html([]) + token });
  try {
    const proof = await verifyByFile(good.origin, token, { allowPrivate: true });
    assert.ok(proof);
    assert.equal(proof.method, 'file');
    assert.equal(proofCovers(proof, '127.0.0.1'), true);
    assert.equal(proofCovers(proof, 'example.jp'), false);

    assert.equal(await verifyByFile(wrong.origin, token, { allowPrivate: true }), undefined);
    assert.equal(await verifyByFile(missing.origin, token, { allowPrivate: true }), undefined);
    assert.equal(await verifyByFile(spa.origin, token, { allowPrivate: true }), undefined);
  } finally {
    await Promise.all([good.close(), wrong.close(), missing.close(), spa.close()]);
  }
});

test('dns: TXT record on the registrable domain', async () => {
  const token = mintVerificationToken(SECRET, 'acct-1', 'example.jp');
  const asked: string[] = [];
  const resolver = (records: string[][]) => async (name: string) => {
    asked.push(name);
    return records;
  };

  const proof = await verifyByDns('app.example.jp', token, resolver([['v=spf1 -all'], [token]]));
  assert.ok(proof);
  assert.deepEqual(asked, ['_qa-jp-ai.example.jp']);
  assert.equal(proofCovers(proof, 'www.example.jp'), true);

  // long TXT values arrive split into chunks
  assert.ok(await verifyByDns('example.jp', token, resolver([[token.slice(0, 10), token.slice(10)]])));
  assert.equal(await verifyByDns('example.jp', token, resolver([['something-else']])), undefined);
  assert.equal(
    await verifyByDns('example.jp', token, async () => {
      throw new Error('ENOTFOUND');
    }),
    undefined,
  );
  assert.equal(await verifyByDns('192.0.2.10', token, resolver([[token]])), undefined);
});
