// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { RULES } from '../src/core/rules';
import { ENGINE_VERSION, RULE_IDS } from '../src/core/types';
import { notRunReasonLabel, ruleReviewFocus, ruleTitle } from '../src/i18n/ja';
import { verifyByFile } from '../src/ownership/file';
import { renderOwnerReport } from '../src/report';
import { scanRepo } from '../src/repo/scan';
import { renderSourceReview, sourceReviewRules } from '../src/sourcereview';
import { closeAgents } from '../src/url/net/fetcher';
import { inspectOwner } from '../src/url/scan';
import { CASE_PROBLEMS, CASE_TOKEN, scoreCaseSite, startCaseSite } from './case-site';
import { fake } from './fixture';

/**
 * What a site check leaves to the source code: the rules that cannot be
 * examined from outside get a next step instead of only "not examined".
 */

after(closeAgents);

const FETCH = { allowPrivate: true };

async function caseSite(activeChecks = true) {
  const site = await startCaseSite('vulnerable');
  try {
    const proof = await verifyByFile(site.origin, CASE_TOKEN, FETCH);
    assert.ok(proof);
    const { assessment } = await inspectOwner(site.origin, proof, { fetch: FETCH, activeChecks });
    return { assessment, proof };
  } finally {
    await site.close();
  }
}

test('the rules a site check leaves to the source code: all that it cannot answer, none that it examined', async () => {
  const { assessment } = await caseSite();
  const routed = sourceReviewRules(assessment);

  // Every rule that the site layer cannot answer at all, and the ones it has no inspector for yet.
  const outside = RULE_IDS.filter((id) => !RULES[id].layers.includes('url'));
  assert.equal(outside.length, 8);
  assert.deepEqual(routed.filter((u) => u.reason === 'requires_source').map((u) => u.ruleId), outside);
  assert.deepEqual(routed.filter((u) => u.reason === 'not_implemented').map((u) => u.ruleId), ['R03', 'R04', 'R06']);

  // Nothing that was examined, in full or in part, is handed over as "not examined".
  const examined = assessment.coverage.filter((u) => u.status !== 'not_run').map((u) => u.ruleId);
  assert.deepEqual(examined, ['R01', 'R02', 'R11', 'R14']);
  for (const id of examined) assert.equal(routed.some((u) => u.ruleId === id), false, id);
});

test('the request: runs the pre-release check, then asks the AI to review each rule as its own judgement', async () => {
  const { assessment } = await caseSite();
  const text = renderSourceReview(assessment);
  const routed = sourceReviewRules(assessment);

  assert.match(text, /^# QA\.JP\.AI ソースコードの確認依頼（AI コーディングツールへ）/);
  assert.match(text, /URL 検査（公開中のサイトを外部から見る検査）では、次の 11 項目を調べられませんでした/);
  assert.match(text, /開いているプロジェクトが 127\.0\.0\.1 のソースコードであることを利用者に確認/);

  // The command is the pre-release check of this exact version: the tool judges what it can judge.
  assert.ok(text.includes(`npx --yes github:QAJPAI/qa-jp-ai-scanner#v${ENGINE_VERSION} check . --for-ai`));
  assert.match(text, /コードの実行や外部への送信は行いません/);

  // Each rule with what to look at, in the words of the rules file.
  assert.match(text, /## 2\. コードを読んで確認する項目（11 件）/);
  for (const unit of routed) {
    assert.ok(text.includes(`- ${unit.ruleId} ${ruleTitle[unit.ruleId]}`), unit.ruleId);
    assert.ok(text.includes(ruleReviewFocus[unit.ruleId]), unit.ruleId);
  }
  assert.match(text, /- R09 [^\n]+\n  - 理由: 公開中のサイトの外側からは調べられない項目です/);
  assert.match(text, /- R04 [^\n]+\n  - 理由: URL 検査では、まだ対応していない項目です/);

  // The AI's review is never passed off as the tool's result, and never as "safe".
  assert.match(text, /必ず「AI による確認」と明記してください/);
  assert.match(text, /確認していない項目を「問題なし」と報告しないでください/);
  assert.match(text, /「安全です」「問題ありません」と断定しないでください/);
  // Reviewing is reading: the published site is not to be probed.
  assert.match(text, /公開中のサイトに対して、試しにデータを取得する、書き換えるなどの操作をしないでください/);

  // It names rules, not findings: nothing of this site's result is in it.
  for (const record of assessment.records) {
    assert.equal(text.includes(record.fingerprint), false);
    if (record.location) assert.equal(text.includes(record.location), false);
  }
  assert.equal(text.includes(fake.supabaseJwt('service_role')), false);
  assert.equal(text.includes('/assets/app.js'), false);
});

test('the request covers the problems of the case that the site check could not examine', async () => {
  const { assessment } = await caseSite();
  const text = renderSourceReview(assessment);
  const notExamined = scoreCaseSite(assessment).filter((s) => s.status === 'not_examined');
  assert.deepEqual(notExamined.map((s) => s.problem.id), [1, 2, 5, 6]);
  // Problems 1, 2, 5 and 6, and the rule behind the question of problem 3, each have a line to review.
  for (const problem of CASE_PROBLEMS.filter((p) => [1, 2, 3, 5, 6].includes(p.id))) {
    assert.ok(text.includes(`- ${problem.rules[0]} ${ruleTitle[problem.rules[0]!]}`), `problem ${problem.id}`);
  }
});

test('the owner report says where an unexamined rule is answered, and that a request text exists', async () => {
  const { assessment, proof } = await caseSite();
  const report = renderOwnerReport(assessment, proof);
  assert.ok(report.includes(`R09 ${ruleTitle.R09}: 未検査（${notRunReasonLabel.requires_source}）`));
  assert.match(notRunReasonLabel.requires_source, /公開前チェックで、AI コーディングツールが確認する項目です/);
  // The old wording promised a tool check that does not exist.
  assert.equal(report.includes('ソースコードの検査が必要なため、今後対応予定です'), false);
  assert.match(report, /※ 未検査の項目のうち 11 項目は、ソースコードを見れば確認できます/);
  assert.ok(report.includes(`（\`npx --yes github:QAJPAI/qa-jp-ai-scanner#v${ENGINE_VERSION} check . --for-ai\`）`));
});

test('a rule the operator switched off is not handed to the source review as if it had been looked at', async () => {
  const { assessment } = await caseSite(false);
  const r11 = assessment.coverage.find((u) => u.ruleId === 'R11')!;
  assert.deepEqual([r11.status, r11.reason], ['not_run', 'disabled_by_operator']);
  assert.equal(sourceReviewRules(assessment).some((u) => u.ruleId === 'R11'), false);
});

test('a source-code check has no such request: it is the source review', async () => {
  const root = mkdtempSync(join(tmpdir(), 'qa-sourcereview-'));
  try {
    writeFileSync(join(root, 'index.js'), 'console.log(1)');
    const assessment = await scanRepo(root);
    assert.deepEqual(sourceReviewRules(assessment), []);
    assert.throws(() => renderSourceReview(assessment), /site checks only/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
