// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { summarize, type Assessment } from '../src/core/assessment';
import { buildLedger } from '../src/core/coverage';
import { fingerprintOf, recordFactory } from '../src/core/records';
import { RULES } from '../src/core/rules';
import { ASSESSMENT_SCHEMA, ENGINE_VERSION, RULE_IDS, RULES_VERSION } from '../src/core/types';
import { validateAssessment } from '../src/core/validate';

const passive = recordFactory('url.test', 'url', 'passive');
const active = recordFactory('url.test-active', 'url', 'active');

/** A small, valid owner-tier assessment to mutate. */
function sample(): Assessment {
  return {
    schema: ASSESSMENT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    rulesVersion: RULES_VERSION,
    target: { layer: 'url', host: 'example.jp' },
    tier: 'owner',
    startedAt: '2026-11-12T00:00:00.000Z',
    records: [
      passive.confirmed({ ruleId: 'R02', code: 'secret.openai', severity: 'P0', key: 'k1', location: '/app.js', evidence: 'e' }),
      passive.confirmed({ ruleId: 'R14', code: 'header.csp_missing', severity: 'P2', key: 'csp', location: '/', evidence: 'e' }),
      passive.needsValidation({
        ruleId: 'R01',
        code: 'baas.supabase_rls_unverified',
        blocker: 'not_observable_from_outside',
        key: 'supabase',
        location: '/app.js',
        evidence: 'e',
      }),
      active.confirmed({ ruleId: 'R11', code: 'exposed.git', severity: 'P1', key: '/.git/HEAD', location: '/.git/HEAD', evidence: 'e' }),
    ],
    coverage: buildLedger('url', [
      { checker: 'url.test', mode: 'passive', reports: [
        { ruleId: 'R02', status: 'partial', note: 'html_referenced_scripts_only' },
        { ruleId: 'R14', status: 'checked' },
        { ruleId: 'R01', status: 'partial', note: 'presence_hint_only' },
      ] },
      { checker: 'url.test-active', mode: 'active', reports: [{ ruleId: 'R11', status: 'checked' }] },
    ]),
  };
}

/** Deep-clone, apply a mutation, validate. */
function errorsAfter(mutate: (a: any) => void): string[] {
  const copy = JSON.parse(JSON.stringify(sample()));
  mutate(copy);
  return validateAssessment(copy);
}

test('fingerprints identify an issue, not a run', () => {
  const a = fingerprintOf('url', 'R02', 'secret.openai', 'k1');
  assert.match(a, /^fp_[0-9a-f]{24}$/);
  assert.equal(a, fingerprintOf('url', 'R02', 'secret.openai', 'k1'));
  assert.notEqual(a, fingerprintOf('url', 'R02', 'secret.openai', 'k2'));
  assert.notEqual(a, fingerprintOf('repo', 'R02', 'secret.openai', 'k1'));
  assert.notEqual(a, fingerprintOf('url', 'R02', 'secret.anthropic', 'k1'));
});

test('the ledger always accounts for every rule and never calls an unexamined rule passed', () => {
  const ledger = buildLedger(
    'url',
    [{ checker: 'c', mode: 'passive', reports: [{ ruleId: 'R14', status: 'checked' }] }],
    [{ ruleId: 'R11', reason: 'requires_owner_verification' }],
  );
  assert.deepEqual(ledger.map((u) => u.ruleId), [...RULE_IDS]);
  const by = Object.fromEntries(ledger.map((u) => [u.ruleId, u]));
  assert.equal(by.R14!.status, 'checked');
  assert.deepEqual([by.R11!.status, by.R11!.reason], ['not_run', 'requires_owner_verification']);
  // A rule the URL layer could cover but does not yet.
  assert.deepEqual([by.R04!.status, by.R04!.reason], ['not_run', 'not_implemented']);
  // A rule only source code can answer.
  assert.deepEqual([by.R08!.status, by.R08!.reason], ['not_run', 'requires_source']);
  assert.equal(ledger.filter((u) => u.status === 'checked').length, 1);
});

test('when two checkers cover a rule, the more complete result is kept', () => {
  const ledger = buildLedger('url', [
    { checker: 'a', mode: 'passive', reports: [{ ruleId: 'R02', status: 'error' }] },
    { checker: 'b', mode: 'passive', reports: [{ ruleId: 'R02', status: 'partial', note: 'html_referenced_scripts_only' }] },
  ]);
  const unit = ledger.find((u) => u.ruleId === 'R02')!;
  assert.deepEqual([unit.status, unit.checker], ['partial', 'b']);
});

test('summaries: needs_validation has no severity; the public view shows basic configuration only', () => {
  const a = sample();
  const owner = summarize(a);
  assert.deepEqual(owner.counts, { P0: 1, P1: 1, P2: 1 });
  assert.equal(owner.needsValidation, 1);
  assert.equal(owner.grade, 'E');
  assert.deepEqual([owner.coverage.checked, owner.coverage.partial, owner.coverage.notRun], [2, 2, 11]);

  const pub = summarize(a, 'public');
  // R02 (a leaked key) is not disclosed publicly at all; R14 (headers) is.
  assert.deepEqual(pub.counts, { P0: 0, P1: 0, P2: 1 });
  assert.equal(pub.needsValidation, 0);
  assert.equal(pub.grade, 'B');
  assert.deepEqual([pub.coverage.checked, pub.coverage.partial, pub.coverage.notRun], [1, 2, 12]);
});

test('validator accepts a consistent assessment', () => {
  assert.deepEqual(validateAssessment(sample()), []);
  assert.deepEqual(validateAssessment(JSON.parse(JSON.stringify(sample()))), []);
});

test('validator enforces the verdict contracts', () => {
  assert.match(errorsAfter((a) => delete a.records[0].severity).join('\n'), /confirmed record requires a severity/);
  assert.match(errorsAfter((a) => (a.records[2].severity = 'P1')).join('\n'), /needs_validation record must not have "severity"/);
  assert.match(errorsAfter((a) => delete a.records[2].blocker).join('\n'), /requires a known blocker/);
  assert.match(errorsAfter((a) => (a.records[0].verdict = 'probably')).join('\n'), /not a known verdict/);
  assert.match(errorsAfter((a) => (a.records[0].note = 'extra')).join('\n'), /must not have "note"/);
  assert.match(errorsAfter((a) => (a.records[0].evidence = '')).join('\n'), /evidence must be a non-empty string/);
  assert.match(
    errorsAfter((a) => a.records.push({ ...a.records[0], verdict: 'rejected', severity: undefined, fingerprint: 'fp_' + '0'.repeat(24) })).join('\n'),
    /rejected record requires a reason/,
  );
});

test('validator ties records to the ledger and the rules', () => {
  // severity may not exceed what the rule allows
  assert.match(errorsAfter((a) => (a.records[1].severity = 'P0')).join('\n'), /severity P0 exceeds the maximum for R14/);
  // a record cannot exist for a rule the ledger says was not examined
  assert.match(
    errorsAfter((a) => {
      const unit = a.coverage.find((u: any) => u.ruleId === 'R02');
      unit.status = 'not_run';
      unit.reason = 'not_implemented';
      delete unit.mode;
      delete unit.checker;
      delete unit.note;
    }).join('\n'),
    /R02 has a record but its coverage status is not_run/,
  );
  assert.match(errorsAfter((a) => a.coverage.pop()).join('\n'), /coverage is missing a unit for R15/);
  assert.match(errorsAfter((a) => a.coverage.push(a.coverage[0])).join('\n'), /duplicate coverage unit for R01/);
  assert.match(errorsAfter((a) => (a.records[1].fingerprint = a.records[0].fingerprint)).join('\n'), /duplicate fingerprint/);
  assert.match(errorsAfter((a) => (a.records[0].ruleId = 'R99')).join('\n'), /not a known rule/);
  assert.match(errorsAfter((a) => (a.records[0].layer = 'repo')).join('\n'), /layer must match target.layer/);
  // a repo-only rule cannot be reported as examined by the URL layer
  assert.match(
    errorsAfter((a) => {
      const unit = a.coverage.find((u: any) => u.ruleId === 'R08');
      Object.assign(unit, { status: 'checked', mode: 'passive', checker: 'x' });
      delete unit.reason;
    }).join('\n'),
    /R08 has no url-layer checks/,
  );
});

test('validator: a public-tier assessment cannot contain active checks', () => {
  const errors = errorsAfter((a) => (a.tier = 'public')).join('\n');
  assert.match(errors, /an active check cannot appear in a public-tier assessment/);
  assert.match(errors, /a record from an active check cannot appear in a public-tier assessment/);
});

test('validator treats arbitrary input as untrusted', () => {
  for (const junk of [null, 42, 'x', [], {}, { records: 'no', coverage: 'no' }]) {
    assert.ok(validateAssessment(junk).length > 0);
  }
  assert.match(errorsAfter((a) => (a.records = new Array(1001).fill(a.records[0]))).join('\n'), /records exceeds 1000/);
});

test('the rule registry covers every rule id', () => {
  assert.deepEqual(Object.keys(RULES), [...RULE_IDS]);
  for (const id of RULE_IDS) assert.ok(RULES[id].layers.length > 0);
});
