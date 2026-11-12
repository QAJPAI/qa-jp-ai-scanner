// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { COVERAGE_NOTES, NOT_RUN_REASONS } from './coverage';
import { BLOCKERS } from './records';
import { exceedsRuleSeverity, RULES } from './rules';
import { ASSESSMENT_SCHEMA, RULE_IDS, SEVERITIES, type RuleId, type Severity } from './types';

/**
 * Validate an assessment that may have been produced by anything: this engine,
 * another tool, another vendor's model. Zero dependencies, input treated as
 * untrusted. Success proves the result is well-formed and internally
 * consistent — not that its claims are true.
 */

const MAX_RECORDS = 1000;
const MAX_ERRORS = 100;
const FINGERPRINT = /^fp_[0-9a-f]{24}$/;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isRuleId = (v: unknown): v is RuleId => typeof v === 'string' && (RULE_IDS as readonly string[]).includes(v);
const oneOf = (list: readonly string[], v: unknown): boolean => typeof v === 'string' && list.includes(v);

const TOP_KEYS = ['schema', 'engineVersion', 'rulesVersion', 'target', 'tier', 'startedAt', 'records', 'coverage'];
const UNIT_KEYS = ['ruleId', 'layer', 'status', 'mode', 'checker', 'reason', 'note', 'passive'];
const PASSIVE_KEYS = ['status', 'checker', 'note'];
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

/** Unknown fields are refused everywhere: a result must not carry data the contract does not describe. */
function unknownKeys(obj: Record<string, unknown>, allowed: readonly string[]): string[] {
  return Object.keys(obj).filter((k) => !allowed.includes(k));
}

const RECORD_KEYS = {
  common: ['verdict', 'fingerprint', 'ruleId', 'code', 'layer', 'mode', 'checker', 'location', 'evidence'],
  confirmed: ['severity'],
  needs_validation: ['blocker'],
  rejected: ['reason'],
} as const;

export function validateAssessment(input: unknown): string[] {
  const errors: string[] = [];
  const fail = (message: string) => {
    if (errors.length < MAX_ERRORS) errors.push(message);
  };

  if (!isObject(input)) return ['assessment must be an object'];
  for (const key of unknownKeys(input, TOP_KEYS)) fail(`unknown field "${key}"`);
  if (input.schema !== ASSESSMENT_SCHEMA) fail(`schema must be "${ASSESSMENT_SCHEMA}"`);
  for (const key of ['engineVersion', 'rulesVersion'] as const) {
    if (!isString(input[key])) fail(`${key} must be a non-empty string`);
  }
  if (typeof input.startedAt !== 'string' || !ISO_DATE.test(input.startedAt) || Number.isNaN(Date.parse(input.startedAt))) {
    fail('startedAt must be an ISO 8601 UTC timestamp');
  }
  if (input.tier !== 'public' && input.tier !== 'owner') fail('tier must be "public" or "owner"');

  const target = input.target;
  const layer = isObject(target) ? target.layer : undefined;
  if (layer !== 'url' && layer !== 'repo') {
    fail('target.layer must be "url" or "repo"');
  } else if (isObject(target)) {
    const nameKey = layer === 'url' ? 'host' : 'ref';
    if (!isString(target[nameKey])) fail(`target.${nameKey} must be a non-empty string`);
    for (const key of unknownKeys(target, ['layer', nameKey])) fail(`target: unknown field "${key}"`);
  }

  // --- coverage: exactly one unit per rule ---
  const covered = new Map<RuleId, { status: unknown; mode: unknown; hasPassive: boolean }>();
  if (!Array.isArray(input.coverage)) {
    fail('coverage must be an array');
  } else {
    for (const [i, unit] of input.coverage.entries()) {
      const at = `coverage[${i}]`;
      if (!isObject(unit)) {
        fail(`${at} must be an object`);
        continue;
      }
      if (!isRuleId(unit.ruleId)) {
        fail(`${at}.ruleId is not a known rule`);
        continue;
      }
      if (covered.has(unit.ruleId)) fail(`${at}: duplicate coverage unit for ${unit.ruleId}`);
      covered.set(unit.ruleId, { status: unit.status, mode: unit.mode, hasPassive: isObject(unit.passive) });
      for (const key of unknownKeys(unit, UNIT_KEYS)) fail(`${at}: unknown field "${key}"`);
      if (unit.layer !== layer) fail(`${at}.layer must match target.layer`);

      if (unit.status === 'not_run') {
        if (!oneOf(NOT_RUN_REASONS, unit.reason)) fail(`${at}: not_run requires a known reason`);
        for (const key of ['mode', 'checker', 'note', 'passive'] as const) {
          if (unit[key] !== undefined) fail(`${at}: not_run must not carry "${key}"`);
        }
      } else if (unit.status === 'checked' || unit.status === 'partial' || unit.status === 'error') {
        if (unit.mode !== 'passive' && unit.mode !== 'active') fail(`${at}: ${unit.status} requires a mode`);
        if (!isString(unit.checker)) fail(`${at}: ${unit.status} requires a checker`);
        if (unit.reason !== undefined) fail(`${at}: ${unit.status} must not carry a reason`);
        if (unit.status === 'partial') {
          if (!oneOf(COVERAGE_NOTES, unit.note)) fail(`${at}: partial requires a known note`);
        } else if (unit.note !== undefined) {
          fail(`${at}: only a partial unit carries a note`);
        }
        if (unit.passive !== undefined) {
          const p = unit.passive;
          if (unit.mode !== 'active') fail(`${at}: only an active unit may carry a passive result`);
          if (!isObject(p)) {
            fail(`${at}.passive must be an object`);
          } else {
            for (const key of unknownKeys(p, PASSIVE_KEYS)) fail(`${at}.passive: unknown field "${key}"`);
            if (p.status !== 'checked' && p.status !== 'partial' && p.status !== 'error') {
              fail(`${at}.passive.status is not a known status`);
            }
            if (!isString(p.checker)) fail(`${at}.passive requires a checker`);
            if (p.status === 'partial' ? !oneOf(COVERAGE_NOTES, p.note) : p.note !== undefined) {
              fail(`${at}.passive: a note is required for partial and forbidden otherwise`);
            }
          }
        }
        if (unit.mode === 'active' && input.tier === 'public') {
          fail(`${at}: an active check cannot appear in a public-tier assessment`);
        }
        if (layer === 'url' || layer === 'repo') {
          if (!RULES[unit.ruleId].layers.includes(layer)) fail(`${at}: ${unit.ruleId} has no ${layer}-layer checks`);
        }
      } else {
        fail(`${at}.status is not a known status`);
      }
    }
    for (const ruleId of RULE_IDS) {
      if (!covered.has(ruleId)) fail(`coverage is missing a unit for ${ruleId}`);
    }
  }

  // --- records: verdict contracts ---
  if (!Array.isArray(input.records)) {
    fail('records must be an array');
    return errors;
  }
  if (input.records.length > MAX_RECORDS) {
    fail(`records exceeds ${MAX_RECORDS} entries`);
    return errors;
  }
  const fingerprints = new Set<string>();
  for (const [i, record] of input.records.entries()) {
    const at = `records[${i}]`;
    if (!isObject(record)) {
      fail(`${at} must be an object`);
      continue;
    }
    const verdict = record.verdict;
    if (verdict !== 'confirmed' && verdict !== 'needs_validation' && verdict !== 'rejected') {
      fail(`${at}.verdict is not a known verdict`);
      continue;
    }
    const allowed = new Set<string>([...RECORD_KEYS.common, ...RECORD_KEYS[verdict]]);
    for (const key of Object.keys(record)) {
      if (!allowed.has(key)) fail(`${at}: a ${verdict} record must not have "${key}"`);
    }
    for (const key of ['code', 'checker', 'location', 'evidence'] as const) {
      if (!isString(record[key])) fail(`${at}.${key} must be a non-empty string`);
    }
    if (!isString(record.fingerprint) || !FINGERPRINT.test(record.fingerprint)) {
      fail(`${at}.fingerprint is malformed`);
    } else if (fingerprints.has(record.fingerprint)) {
      fail(`${at}: duplicate fingerprint ${record.fingerprint}`);
    } else {
      fingerprints.add(record.fingerprint);
    }
    if (record.layer !== layer) fail(`${at}.layer must match target.layer`);
    if (record.mode !== 'passive' && record.mode !== 'active') fail(`${at}.mode must be "passive" or "active"`);
    if (record.mode === 'active' && input.tier === 'public') {
      fail(`${at}: a record from an active check cannot appear in a public-tier assessment`);
    }

    if (!isRuleId(record.ruleId)) {
      fail(`${at}.ruleId is not a known rule`);
      continue;
    }
    // A record may only exist for a rule the ledger says was examined.
    const unit = covered.get(record.ruleId);
    if (unit && unit.status !== 'checked' && unit.status !== 'partial') {
      fail(`${at}: ${record.ruleId} has a record but its coverage status is ${String(unit.status)}`);
    }
    // ...and only in a mode the ledger says ran. Otherwise a record could be
    // labelled "active" to drop out of the public count, or the reverse.
    if (unit && (record.mode === 'passive' || record.mode === 'active')) {
      const modeRan = unit.mode === record.mode || (record.mode === 'passive' && unit.hasPassive);
      if (!modeRan) fail(`${at}: ${record.ruleId} has a ${record.mode} record but no ${record.mode} coverage`);
    }

    if (verdict === 'confirmed') {
      const severity = record.severity;
      if (typeof severity !== 'string' || !(SEVERITIES as readonly string[]).includes(severity)) {
        fail(`${at}: a confirmed record requires a severity`);
      } else if (exceedsRuleSeverity(record.ruleId, severity as Severity)) {
        fail(`${at}: severity ${severity} exceeds the maximum for ${record.ruleId}`);
      }
    } else if (verdict === 'needs_validation') {
      if (typeof record.blocker !== 'string' || !(BLOCKERS as readonly string[]).includes(record.blocker)) {
        fail(`${at}: a needs_validation record requires a known blocker`);
      }
    } else if (!isString(record.reason)) {
      fail(`${at}: a rejected record requires a reason`);
    }
  }
  return errors;
}
