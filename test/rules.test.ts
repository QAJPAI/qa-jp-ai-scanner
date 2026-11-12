// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { dedupeByFingerprint, recordFactory } from '../src/core/records';
import { newSecretScanState, scanTextForSecrets } from '../src/url/checkers/secrets';
import { checkTransport } from '../src/url/checkers/transport';
import { fake } from './fixture';

const make = recordFactory('test', 'url', 'passive');
const codes = (text: string) => scanTextForSecrets('https://example.jp/app.js', text, make).map((f) => f.code);

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

test('R02: the same key in several places is one issue; nothing reveals the key', () => {
  const key = fake.stripeLive();
  // Within one scan (shared state) the key is reported once, wherever it appears.
  const state = newSecretScanState();
  const inScan = [
    ...scanTextForSecrets('https://example.jp/a.js', `x="${key}";y="${key}"`, make, state),
    ...scanTextForSecrets('https://example.jp/b.js', `z="${key}"`, make, state),
  ];
  assert.equal(inScan.length, 1);

  // Across separate scans the fingerprint is the same, whatever the file.
  const records = [
    ...scanTextForSecrets('https://example.jp/a.js', `x="${key}"`, make),
    ...scanTextForSecrets('https://example.jp/other/b.js', `padding;z="${key}"`, make),
  ];
  assert.equal(records.length, 2);
  assert.equal(new Set(records.map((r) => r.fingerprint)).size, 1);
  assert.equal(dedupeByFingerprint(records).length, 1);

  // A different key of the same kind is a different issue.
  const other = scanTextForSecrets('https://example.jp/a.js', `x="${key}Z"`, make);
  assert.notEqual(other[0]!.fingerprint, records[0]!.fingerprint);

  const serialized = JSON.stringify(records);
  assert.equal(serialized.includes(key), false);
  assert.equal(serialized.includes(key.slice(8)), false);
});

const GOOD_HEADERS = {
  'strict-transport-security': ['max-age=31536000'],
  'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
  'x-content-type-options': ['nosniff'],
  'set-cookie': ['session=abc; Path=/; Secure; HttpOnly; SameSite=Lax'],
};

test('R14 passes a well-configured HTTPS site', () => {
  const records = checkTransport(
    { finalUrl: 'https://example.jp/', headers: GOOD_HEADERS, httpRedirectsToHttps: true },
    make,
  );
  assert.deepEqual(records, []);
});

test('R14 reports each missing protection as P2', () => {
  const records = checkTransport(
    {
      finalUrl: 'https://example.jp/',
      headers: { 'set-cookie': ['session=abc; Path=/', 'theme=dark; Secure'] },
      httpRedirectsToHttps: false,
    },
    make,
  );
  assert.deepEqual(
    records.map((f) => f.code).sort(),
    [
      'cookie.insecure',
      'header.clickjacking',
      'header.csp_missing',
      'header.hsts_missing',
      'header.nosniff_missing',
      'transport.no_https_redirect',
    ],
  );
  assert.ok(records.every((f) => f.severity === 'P2'));
  const cookie = records.find((f) => f.code === 'cookie.insecure')!;
  assert.equal(cookie.location, 'Cookie: session');
  assert.equal(JSON.stringify(cookie).includes('abc'), false, 'cookie value must not be recorded');
});

test('R14 flags plain HTTP as P1', () => {
  const records = checkTransport({ finalUrl: 'http://example.jp/', headers: GOOD_HEADERS }, make);
  assert.deepEqual(records.map((f) => [f.code, f.severity]), [['transport.no_https', 'P1']]);
});
