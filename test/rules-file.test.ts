// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { RULE_IDS } from '../src/core/types';

/**
 * The rules file people paste into their AI tool and the rule registry the
 * scanner checks against must not drift apart.
 */
const file = readFileSync(new URL('../rules/security-rules.ja.md', import.meta.url), 'utf8');
const START = '<!-- ここから -->';
const END = '<!-- ここまで -->';

test('the pasteable block exists and names every rule exactly once as a heading', () => {
  const start = file.indexOf(START);
  const end = file.indexOf(END);
  assert.ok(start >= 0 && end > start, 'copy markers are present and ordered');
  const block = file.slice(start, end);

  for (const id of RULE_IDS) {
    const headings = block.match(new RegExp(`^\\*\\*${id} `, 'gm')) ?? [];
    assert.equal(headings.length, 1, `${id} must appear once as a rule heading`);
  }
  const numbered = block.match(/^\*\*R\d{2} /gm) ?? [];
  assert.equal(numbered.length, RULE_IDS.length, 'no rule id outside the registry');
});

test('the block tells the AI to report in three verdicts and never to pass an unchecked item', () => {
  const block = file.slice(file.indexOf(START), file.indexOf(END));
  for (const phrase of ['確認できた', '問題あり', '確認できない', '確認していない項目を「問題なし」と報告しないでください']) {
    assert.ok(block.includes(phrase), phrase);
  }
});

test('the file does not claim certification or safety', () => {
  assert.ok(file.includes('QA.JP.AI の認証を受けたことにはなりません'));
  assert.ok(file.includes('安全を保証するものでもありません'));
  assert.ok(file.includes('まだ検証していません'), 'states that its effect is not yet measured');
});

test('the rules are public domain, and say so where a reader will see it', () => {
  assert.ok(file.includes('CC0 1.0'));
  assert.ok(file.includes('出典の表示も要りません'));
  const licence = readFileSync(new URL('../rules/LICENSE', import.meta.url), 'utf8');
  assert.ok(licence.includes('CC0 1.0 Universal') || licence.includes('Creative Commons Legal Code'));
});
