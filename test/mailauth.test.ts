// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { recordFactory } from '../src/core/records';
import { findingTextFor } from '../src/i18n/ja';
import { checkTransport, transportChecker } from '../src/url/checkers/transport';
import type { UrlContext } from '../src/url/context';
import { dmarcPolicy, lookUpMailAuth, mailDomainFor, type MailAuthFacts, recordsOf, spfAll } from '../src/url/mailauth';

const make = recordFactory('url.transport', 'url', 'passive');
const HEADERS = {
  'strict-transport-security': ['max-age=31536000'],
  'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
  'x-content-type-options': ['nosniff'],
};
const facts = (spf: string[] | 'failed', dmarc: string[] | 'failed', domain = 'example.jp'): MailAuthFacts => ({
  domain,
  spf: spf === 'failed' ? { status: 'failed', records: [] } : { status: spf.length ? 'found' : 'none', records: spf },
  dmarc: dmarc === 'failed' ? { status: 'failed', records: [] } : { status: dmarc.length ? 'found' : 'none', records: dmarc },
});
const findings = (mailAuth: MailAuthFacts) =>
  checkTransport({ finalUrl: 'https://example.jp/', headers: HEADERS, httpRedirectsToHttps: true, mailAuth }, make)
    .map((r) => [r.code, r.severity]);

test('a domain anyone can send forged mail as is P1; weaker settings are P2', () => {
  assert.deepEqual(findings(facts([], [])), [['email.spf_missing', 'P2'], ['email.dmarc_missing', 'P1']]);
  assert.deepEqual(findings(facts(['v=spf1 include:_spf.google.com ~all'], ['v=DMARC1; p=reject'])), []);
  assert.deepEqual(findings(facts(['v=spf1 -all'], ['v=DMARC1; p=quarantine; rua=mailto:d@example.jp'])), []);
  assert.deepEqual(findings(facts(['v=spf1 +all'], ['v=DMARC1; p=reject'])), [['email.spf_allows_all', 'P1']]);
  assert.deepEqual(findings(facts(['v=spf1 a mx all'], ['v=DMARC1; p=reject'])), [['email.spf_allows_all', 'P1']]);
  assert.deepEqual(findings(facts(['v=spf1 ?all'], ['v=DMARC1; p=reject'])), [['email.spf_neutral', 'P2']]);
  assert.deepEqual(findings(facts(['v=spf1 include:x.example'], ['v=DMARC1; p=reject'])), [['email.spf_neutral', 'P2']]);
  assert.deepEqual(findings(facts(['v=spf1 redirect=_spf.example.jp'], ['v=DMARC1; p=reject'])), [], 'redirect decides elsewhere');
  assert.deepEqual(findings(facts(['v=spf1 -all', 'v=spf1 ~all'], ['v=DMARC1; p=reject'])), [['email.spf_multiple', 'P2']]);
  assert.deepEqual(findings(facts(['v=spf1 -all'], ['v=DMARC1; p=none'])), [['email.dmarc_monitor_only', 'P2']]);
  assert.deepEqual(findings(facts(['v=spf1 -all'], ['v=DMARC1; rua=mailto:x@example.jp'])), [['email.dmarc_monitor_only', 'P2']], 'no p=');
  assert.deepEqual(findings(facts(['v=spf1 -all'], ['v=DMARC1; p=reject', 'v=DMARC1; p=none'])), [['email.dmarc_missing', 'P1']], 'two records count as none');
});

test('other TXT records are not SPF or DMARC', () => {
  assert.deepEqual(findings(facts(['google-site-verification=abc', 'v=spf10 nope'], ['something else'])), [
    ['email.spf_missing', 'P2'],
    ['email.dmarc_missing', 'P1'],
  ]);
  assert.deepEqual(recordsOf({ status: 'found', records: ['V=SPF1 -all', 'v=spf1', 'v=spf1x'] }, 'v=spf1'), ['V=SPF1 -all', 'v=spf1']);
});

test('a lookup that got no answer produces no finding, and the rule is only partly examined', () => {
  assert.deepEqual(findings(facts('failed', 'failed')), []);
  assert.deepEqual(findings(facts('failed', [])), [['email.dmarc_missing', 'P1']]);

  const ctx = (mailAuth: UrlContext['mailAuth']) =>
    ({ page: { finalUrl: 'https://example.jp/', headers: HEADERS, body: '' }, httpRedirectsToHttps: true, mailAuth }) as unknown as UrlContext;
  const coverage = (m: UrlContext['mailAuth']) => (transportChecker.run(ctx(m), make) as { coverage: unknown[] }).coverage[0];
  assert.deepEqual(coverage(facts(['v=spf1 -all'], ['v=DMARC1; p=reject'])), { ruleId: 'R14', status: 'checked' });
  assert.deepEqual(coverage('not_applicable'), { ruleId: 'R14', status: 'checked' });
  assert.deepEqual(coverage(facts('failed', [])), { ruleId: 'R14', status: 'partial', note: 'some_probes_failed' });
  assert.deepEqual(coverage(undefined), { ruleId: 'R14', status: 'partial', note: 'some_probes_failed' }, 'not looked up');
});

test('looking up: "no record" and "no answer" are told apart', async () => {
  const err = (code: string) => Object.assign(new Error(code), { code });
  const answers: Record<string, string[][] | Error> = {
    'example.jp': [['v=spf1 ', 'include:_spf.google.com ~all'], ['other']],
    '_dmarc.example.jp': err('ENOTFOUND'),
    'timeout.jp': err('ETIMEOUT'),
    '_dmarc.timeout.jp': err('ENODATA'),
  };
  const txt = async (name: string) => {
    const a = answers[name];
    if (a instanceof Error) throw a;
    if (!a) throw err('ENOTFOUND');
    return a;
  };
  const dns = { txt, ns: async () => ['ns1.example.net'] };
  const a = await lookUpMailAuth('example.jp', dns);
  assert.deepEqual(a.spf, { status: 'found', records: ['v=spf1 include:_spf.google.com ~all', 'other'] }, 'chunks are joined');
  assert.deepEqual(a.dmarc, { status: 'none', records: [] });
  const b = await lookUpMailAuth('timeout.jp', dns);
  assert.equal(b.spf.status, 'failed');
  assert.equal(b.dmarc.status, 'none');
});

test('looking up: a resolver that cannot see the domain is not believed when it says "no record"', async () => {
  const err = (code: string) => Object.assign(new Error(code), { code });
  // A filtered resolver: "no data" for every TXT question, and no NS either.
  const blind = { txt: async () => { throw err('ENODATA'); }, ns: async () => { throw err('ENODATA'); } };
  const a = await lookUpMailAuth('github.com', blind);
  assert.equal(a.spf.status, 'failed');
  assert.equal(a.dmarc.status, 'failed');
  // A record it did return is still evidence.
  const half = { txt: async (n: string) => (n.startsWith('_dmarc.') ? Promise.reject(err('ENOTFOUND')) : [['v=spf1 +all']]), ns: async () => [] };
  const b = await lookUpMailAuth('example.jp', half);
  assert.equal(b.spf.status, 'found');
  assert.equal(b.dmarc.status, 'failed');
});

test('which domain: the registrable one; none for IPs and hosting platforms', () => {
  assert.equal(mailDomainFor('www.example.co.jp'), 'example.co.jp');
  assert.equal(mailDomainFor('example.jp'), 'example.jp');
  assert.equal(mailDomainFor('127.0.0.1'), undefined);
  assert.equal(mailDomainFor('my-app.vercel.app'), undefined);
});

test('the DMARC advice warns that p=reject also covers subdomains', () => {
  const fix = findingTextFor('url', 'email.dmarc_missing')!.fix;
  assert.match(fix, /サブドメイン/);
  assert.match(fix, /sp=none/);
});

test('SPF and DMARC parsing details', () => {
  assert.equal(spfAll('v=spf1 -all'), '-');
  assert.equal(spfAll('v=spf1 include:a ~ALL'), '~');
  assert.equal(spfAll('v=spf1 mx'), 'none');
  assert.equal(dmarcPolicy('v=DMARC1;p=Reject;sp=none'), 'reject');
  assert.equal(dmarcPolicy('v=DMARC1; sp=reject'), undefined, 'sp= is not p=');
});

test('every mail finding explains the risk of forged mail and how to fix it', () => {
  for (const code of ['email.dmarc_missing', 'email.dmarc_monitor_only', 'email.spf_missing', 'email.spf_multiple', 'email.spf_allows_all', 'email.spf_neutral']) {
    const text = findingTextFor('url', code);
    assert.ok(text, code);
    assert.match(text!.fix, /なりすまし|偽のメール|名乗って/, code);
  }
});
