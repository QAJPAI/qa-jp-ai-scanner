// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { RULES } from '../src/core/rules';
import { validateAssessment } from '../src/core/validate';
import { verifyByFile } from '../src/ownership/file';
import { closeAgents } from '../src/url/net/fetcher';
import { inspectOwner } from '../src/url/scan';
import { CASE_PROBLEMS, CASE_TOKEN, scoreCaseSite, startCaseSite, type CaseStatus, type CaseVariant } from './case-site';

after(closeAgents);

const FETCH = { allowPrivate: true };

async function check(variant: CaseVariant) {
  const site = await startCaseSite(variant);
  try {
    const proof = await verifyByFile(site.origin, CASE_TOKEN, FETCH);
    assert.ok(proof, 'the case site must verify as owned');
    const { assessment } = await inspectOwner(site.origin, proof, { fetch: FETCH });
    assert.deepEqual(validateAssessment(assessment), []);
    return { assessment, requests: [...site.requests] };
  } finally {
    await site.close();
  }
}

/**
 * The scoreboard of the free check against the case site, as it stands today.
 *
 * This table is the ruler: change it only together with the checker that
 * moves a line, and update evals/case-site/README.md in the same change.
 * A line may move towards "confirmed" on the vulnerable site. It must never
 * move away from it, and the fixed site must never gain a "confirmed".
 */
const TODAY: Record<number, CaseStatus> = {
  1: 'not_examined', // R04: the URL layer can answer this, no checker yet
  2: 'not_examined', // R06: the URL layer can answer this, no checker yet
  3: 'question', //     R05 needs source; the Supabase access-rule question (R01) points at it
  4: 'confirmed', //    R02: the service_role key is in a script the page references
  5: 'not_examined', // R09 needs source
  6: 'not_examined', // R07 needs source
};

test('case site: the six problems, as the owner check sees them today', async () => {
  const { assessment } = await check('vulnerable');
  const scores = scoreCaseSite(assessment);

  assert.deepEqual(
    Object.fromEntries(scores.map((s) => [s.problem.id, s.status])),
    TODAY,
  );

  // What "not examined" means differs: two problems wait for a URL checker, three need the source.
  const reasons = Object.fromEntries(scores.map((s) => [s.problem.id, s.reason]));
  assert.equal(reasons[1], 'not_implemented');
  assert.equal(reasons[2], 'not_implemented');
  assert.equal(reasons[5], 'requires_source');
  assert.equal(reasons[6], 'requires_source');

  // The one confirmed problem is the admin key, at the highest priority.
  const confirmed = assessment.records.filter((r) => r.verdict === 'confirmed' && RULES[r.ruleId].disclosure === 'owner');
  assert.deepEqual(confirmed.map((r) => [r.code, r.verdict === 'confirmed' && r.severity]), [['secret.supabase_service_role', 'P0']]);
});

test('case site: after a correct fix, none of the six is reported as a problem', async () => {
  const { assessment } = await check('fixed');
  const scores = scoreCaseSite(assessment);

  assert.equal(scores.filter((s) => s.status === 'confirmed').length, 0);
  // The admin key is gone, and the rule was examined: "clear", not "not examined".
  assert.equal(scores.find((s) => s.problem.id === 4)?.status, 'clear');
  // The site still talks to Supabase from the browser, so the owner is still asked about its access rules.
  assert.equal(scores.find((s) => s.problem.id === 3)?.status, 'question');

  // No false alarm of any kind outside basic configuration.
  const serious = assessment.records.filter((r) => r.verdict === 'confirmed' && RULES[r.ruleId].disclosure === 'owner');
  assert.deepEqual(serious, []);
});

test('case site: the check reads the site like a visitor and never asks for user data', async () => {
  const { requests } = await check('vulnerable');
  // Today no checker touches an API. When one does (R04), this is where its limits are pinned.
  assert.equal(requests.some((path) => path.startsWith('/api/')), false);
});

test('case site: every problem belongs to a rule of the registry', () => {
  assert.deepEqual(CASE_PROBLEMS.map((p) => p.id), [1, 2, 3, 4, 5, 6]);
  for (const p of CASE_PROBLEMS) {
    for (const rule of [...p.rules, ...p.related]) assert.ok(RULES[rule], `${rule} is not a rule`);
  }
});
