// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { recordFactory } from '../src/core/records';
import { evaluateEmailOwnership } from '../src/ownership/email';
import { baasHintChecker } from '../src/url/checkers/baas-hint';
import { scanTextForSecrets } from '../src/url/checkers/secrets';
import type { UrlContext } from '../src/url/context';
import { extractScriptUrls, normalizeTarget } from '../src/url/scan';

/**
 * The page being scanned is written by whoever submitted the URL. A pattern
 * that takes quadratic time on crafted text would let one request stall the
 * service. These inputs are at the size caps; before the fix the first two
 * took minutes and the third took hours.
 */

const HTML_CAP = 2 * 1024 * 1024;
const SCRIPT_CAP = 3 * 1024 * 1024;
const BUDGET_MS = 3000;

const make = recordFactory('test', 'url', 'passive');
const page = new URL('https://example.jp/');

function within(label: string, fn: () => unknown): void {
  const started = performance.now();
  fn();
  const elapsed = performance.now() - started;
  assert.ok(elapsed < BUDGET_MS, `${label} took ${elapsed.toFixed(0)} ms`);
}

const fill = (unit: string, size: number) => unit.repeat(Math.floor(size / unit.length));

test('script discovery stays fast on a page made of unterminated tags', () => {
  within('unterminated <script', () => extractScriptUrls(fill('<script ', HTML_CAP), page));
  within('unterminated <link', () => extractScriptUrls(fill('<link ', HTML_CAP), page));
  within('unterminated <script src=', () => extractScriptUrls(fill('<script src= ', HTML_CAP), page));
  within('many terminated tags', () => extractScriptUrls(fill('<script src="/a.js"></script>', HTML_CAP), page));
});

test('script discovery still works, and ignores look-alike tags', () => {
  const found = extractScriptUrls(
    `<SCRIPT SRC="/upper.js"></SCRIPT><scripted src="/no.js"><script\n  defer\n  src='/multi.js'></script>
     <link href="/pre.js" rel="modulepreload"><link rel="stylesheet" href="/no.css"><linker href="/no2.js" rel="modulepreload">
     <script data-src="/not-src.js"></script>`,
    page,
  );
  assert.deepEqual(found, ['https://example.jp/upper.js', 'https://example.jp/multi.js', 'https://example.jp/pre.js']);
});

test('service detection stays fast on crafted script text', () => {
  const run = (body: string) =>
    baasHintChecker.run({ texts: [{ url: 'https://example.jp/a.js', body }] } as unknown as UrlContext, make);
  within('a-a-a-…', () => run(fill('a-', SCRIPT_CAP)));
  within('https://aaaa…', () => run(fill('https://' + 'a'.repeat(60), SCRIPT_CAP)));
  within('eyJ.eyJ.…', () => run(fill('eyJaaaaaaaa.', SCRIPT_CAP)));
});

test('service detection still recognises real connection settings', async () => {
  const codes = async (body: string) =>
    (await baasHintChecker.run({ texts: [{ url: 'https://example.jp/a.js', body }] } as unknown as UrlContext, make))
      .records.map((r) => r.code);
  assert.deepEqual(await codes('createClient("https://abcdefghijklmnopqrst.supabase.co", k)'), ['baas.supabase_rls_unverified']);
  assert.deepEqual(await codes(`key:"sb_publishable_${'a'.repeat(30)}"`), ['baas.supabase_rls_unverified']);
  assert.deepEqual(await codes('authDomain:"my-clinic.firebaseapp.com"'), ['baas.firebase_rules_unverified']);
  assert.deepEqual(await codes('databaseURL:"https://x.firebaseio.com"'), ['baas.firebase_rules_unverified']);
  assert.deepEqual(await codes('see https://supabase.com/docs and notfirebaseapp.community'), []);
});

test('key detection stays fast on crafted script text', () => {
  for (const unit of ['eyJ', 'eyJaaaaaaaa.', 'eyJaaaaaaaa.eyJaaaaaaaa.', ' sk-proj-', 'sk-', ' github_pat_', '-----BEGIN ', '_-']) {
    within(`secrets "${unit}"`, () => scanTextForSecrets('https://example.jp/a.js', fill(unit, SCRIPT_CAP), make));
  }
});

test('over-long user input is rejected before any pattern runs', () => {
  assert.throws(() => normalizeTarget('https://example.jp/' + 'a'.repeat(3000)), /too long/);
  assert.throws(() => normalizeTarget('   '), /empty/);
  const decision = evaluateEmailOwnership('a'.repeat(300) + '@example.jp', 'example.jp');
  assert.deepEqual(decision, { status: 'ineligible', reason: 'invalid' });
});
