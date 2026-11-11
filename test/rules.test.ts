// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scanTextForSecrets } from '../src/rules/r02-secrets';
import { checkTransport } from '../src/rules/r14-transport';
import { fake } from './fixture';

const codes = (text: string) => scanTextForSecrets('https://example.jp/app.js', text).map((f) => f.code);

test('R02 detects privileged keys', () => {
  assert.deepEqual(codes(`const k="${fake.supabaseJwt('service_role')}"`), ['secret.supabase_service_role']);
  assert.deepEqual(codes(`key:'sb_secret_${'a'.repeat(30)}'`), ['secret.supabase_secret_key']);
  assert.deepEqual(codes(`apiKey:"${fake.openai()}"`), ['secret.openai']);
  assert.deepEqual(codes(`apiKey:"${fake.anthropic()}"`), ['secret.anthropic']);
  assert.deepEqual(codes(`stripe("${fake.stripeLive()}")`), ['secret.stripe_live']);
  assert.deepEqual(codes('-----BEGIN PRIVATE KEY-----\\nMIIE'), ['secret.private_key']);
  assert.deepEqual(codes(`t="ghp_${'a'.repeat(36)}"`), ['secret.github_token']);
  assert.deepEqual(codes(`AKIA${'A'.repeat(16)}`), ['secret.aws_access_key']);
});

test('R02 ignores keys that are public by design and look-alikes', () => {
  assert.deepEqual(codes(`const anon="${fake.supabaseJwt('anon')}"`), []);
  assert.deepEqual(codes(`key:"sb_publishable_${'a'.repeat(30)}"`), []);
  assert.deepEqual(codes(`stripe("${fake.stripePublishable()}")`), []);
  assert.deepEqual(codes('apiKey:"AIzaSyA-fake-firebase-web-key-000000000"'), []);
  // "sk-proj-" inside a longer identifier is not a key
  assert.deepEqual(codes(`"desk-proj-${'x'.repeat(40)}"`), []);
  assert.deepEqual(codes('const ask_live_updates_enabled_flag = true'), []);
  // a JWT-shaped string whose payload is not JSON
  assert.deepEqual(codes(`eyJ${'a'.repeat(20)}.eyJ${'b'.repeat(20)}.${'c'.repeat(20)}`), []);
});

test('R02 evidence never contains the full key and duplicates are reported once', () => {
  const key = fake.stripeLive();
  const seen = new Set<string>();
  const first = scanTextForSecrets('https://example.jp/a.js', `x="${key}";y="${key}"`, seen);
  const second = scanTextForSecrets('https://example.jp/b.js', `z="${key}"`, seen);
  assert.equal(first.length, 1);
  assert.equal(second.length, 0);
  assert.equal(first[0]!.evidence.includes(key), false);
  assert.equal(JSON.stringify(first).includes(key.slice(8)), false);
});

const GOOD_HEADERS = {
  'strict-transport-security': ['max-age=31536000'],
  'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
  'x-content-type-options': ['nosniff'],
  'set-cookie': ['session=abc; Path=/; Secure; HttpOnly; SameSite=Lax'],
};

test('R14 passes a well-configured HTTPS site', () => {
  const findings = checkTransport({
    finalUrl: 'https://example.jp/',
    headers: GOOD_HEADERS,
    httpRedirectsToHttps: true,
  });
  assert.deepEqual(findings, []);
});

test('R14 reports each missing protection as P2', () => {
  const findings = checkTransport({
    finalUrl: 'https://example.jp/',
    headers: { 'set-cookie': ['session=abc; Path=/', 'theme=dark; Secure'] },
    httpRedirectsToHttps: false,
  });
  assert.deepEqual(
    findings.map((f) => f.code).sort(),
    [
      'cookie.insecure',
      'header.clickjacking',
      'header.csp_missing',
      'header.hsts_missing',
      'header.nosniff_missing',
      'transport.no_https_redirect',
    ],
  );
  assert.ok(findings.every((f) => f.severity === 'P2'));
  const cookie = findings.find((f) => f.code === 'cookie.insecure')!;
  assert.equal(cookie.location, 'Cookie: session');
  assert.equal(JSON.stringify(cookie).includes('abc'), false, 'cookie value must not be recorded');
});

test('R14 flags plain HTTP', () => {
  const findings = checkTransport({ finalUrl: 'http://example.jp/', headers: GOOD_HEADERS });
  assert.deepEqual(findings.map((f) => [f.code, f.severity]), [['transport.no_https', 'P1']]);
});
