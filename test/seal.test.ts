// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { validateAssessment } from '../src/core/validate';
import { issueEmailProofAfterLinkClick } from '../src/ownership/email';
import { WELL_KNOWN_PATH, verifyByFile } from '../src/ownership/file';
import { PROOF_TTL_MS, proofCovers } from '../src/ownership/proof';
import { openProof, sealProof } from '../src/ownership/seal';
import { mintVerificationToken } from '../src/ownership/token';
import { closeAgents } from '../src/url/net/fetcher';
import { scan, scanOwner } from '../src/url/scan';
import { html, startFixture } from './fixture';

after(closeAgents);

const SECRET = 'a-test-sealing-secret-of-32-chars!';
const T0 = Date.UTC(2026, 10, 20, 0, 0, 0);

test('a sealed proof opens to the same proof, under the same secret, until it expires', () => {
  const proof = issueEmailProofAfterLinkClick('info@example.jp', 'example.jp', T0)!;
  const sealed = sealProof(proof, SECRET);
  const opened = openProof(sealed, SECRET, T0 + 1000)!;
  assert.ok(opened);
  assert.deepEqual(
    { ...opened },
    { ...proof },
  );
  assert.equal(proofCovers(opened, 'example.jp', T0 + 1000), true);
  assert.equal(openProof(sealed, SECRET, proof.expiresAt), undefined, 'expired');
  assert.equal(openProof(sealed, 'another-secret-of-thirty-two-chars', T0), undefined, 'other secret');
});

test('a sealed proof cannot be edited: not its site, not its expiry, not its scope', () => {
  const proof = issueEmailProofAfterLinkClick('info@example.jp', 'example.jp', T0)!;
  const [v, payload, mac] = sealProof(proof, SECRET).split('.') as [string, string, string];
  const body = JSON.parse(Buffer.from(payload, 'base64url').toString());
  const forge = (change: object) =>
    `${v}.${Buffer.from(JSON.stringify({ ...body, ...change })).toString('base64url')}.${mac}`;

  assert.equal(openProof(forge({ sub: 'victim.jp' }), SECRET, T0), undefined);
  assert.equal(openProof(forge({ ea: body.ea + PROOF_TTL_MS }), SECRET, T0), undefined);
  assert.equal(openProof(forge({ s: 'domain' }), SECRET, T0), undefined);
  for (const junk of ['', 'qa1', 'qa1..', `qa2.${payload}.${mac}`, `${v}.${payload}.${mac}.x`, 'x'.repeat(5000)]) {
    assert.equal(openProof(junk, SECRET, T0), undefined, junk.slice(0, 20));
  }
});

test('a secret too short to seal with is refused', () => {
  const proof = issueEmailProofAfterLinkClick('info@example.jp', 'example.jp', T0)!;
  assert.throws(() => sealProof(proof, 'short'), /at least 32/);
  assert.throws(() => openProof('qa1.a.b', 'short'), /at least 32/);
});

test('with active checks switched off, a verified owner gets no active probe, and the ledger says why', async () => {
  const token = mintVerificationToken('test-secret-0123456789', 'acct-1', '127.0.0.1');
  const site = await startFixture({
    '/': { headers: { 'content-type': 'text/html' }, body: html([]) },
    '/.env': { body: 'DATABASE_PASSWORD=x\n' },
    [WELL_KNOWN_PATH]: { body: token },
  });
  try {
    const proof = (await verifyByFile(site.origin, token, { allowPrivate: true }))!;
    // The sealed proof, opened again, is what a web service uses.
    const opened = openProof(sealProof(proof, SECRET), SECRET)!;
    const off = await scanOwner(site.origin, opened, { fetch: { allowPrivate: true }, activeChecks: false });
    assert.equal(site.requests.includes('/.env'), false, 'no active probe');
    assert.deepEqual(validateAssessment(off), []);
    const r11 = off.coverage.find((u) => u.ruleId === 'R11')!;
    assert.deepEqual([r11.status, r11.reason], ['not_run', 'disabled_by_operator']);

    const on = await scan(site.origin, { fetch: { allowPrivate: true }, proof: opened });
    assert.equal(site.requests.includes('/.env'), true, 'switched on, it runs');
    assert.equal(on.records.some((r) => r.ruleId === 'R11'), true);
  } finally {
    await site.close();
  }
});
