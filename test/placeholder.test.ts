// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { isPlaceholder } from '../src/detect/secrets';

/**
 * The placeholder filter keeps documentation examples out of the results. Its
 * cost is that a real key could be dismissed by chance. That rate is measured
 * here on random keys of each real shape, so a later change cannot raise it
 * unnoticed.
 */

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const rand = (n: number, alphabet: string) => Array.from(randomBytes(n), (b) => alphabet[b % alphabet.length]).join('');

const SHAPES: Record<string, () => string> = {
  aws: () => `AK${'IA'}${rand(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}`,
  stripe: () => `sk_${'live'}_${rand(24, B62)}`,
  openai: () => `sk-${'proj'}-${rand(48, `${B62}_-`)}`,
  github: () => `gh${'p'}_${rand(36, B62)}`,
  slack: () => `xox${'b'}-${rand(12, '0123456789')}-${rand(12, '0123456789')}-${rand(24, B62)}`,
};

test('real-looking random keys are almost never dismissed as placeholders', () => {
  const N = 100_000;
  for (const [name, make] of Object.entries(SHAPES)) {
    let missed = 0;
    for (let i = 0; i < N; i++) if (isPlaceholder(make())) missed++;
    // Expected well under 1 in 10,000; the bound leaves room for chance.
    assert.ok(missed <= 10, `${name}: ${missed} of ${N} random keys were treated as placeholders`);
  }
});

test('documentation and template placeholders are recognised', () => {
  for (const value of [
    `sk_${'live'}_xxxxxxxxxxxxxxxxxxxxxxxx`,
    `sk_${'live'}_51HxXxXxXxXxXxXxXxXxXxXx`,
    `sk-${'proj'}-your-api-key-goes-here-0123456789`,
    `sk-${'proj'}-${'0'.repeat(40)}`,
    `AK${'IA'}IOSFODNN7EXAMPLE`,
    `AK${'IA'}AAAAAAAAAAAAAAAA`,
    `gh${'p'}_${'a'.repeat(36)}`,
    `sb_${'secret'}_REPLACE_WITH_YOUR_SECRET_KEY`,
  ]) {
    assert.equal(isPlaceholder(value), true, value);
  }
});
