// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto';
import type { CheckMode, Layer, RuleId, Severity } from './types';

/**
 * One record per distinct issue, with one of three verdicts:
 *
 *  confirmed         evidence was observed. Only this verdict has a severity.
 *  needs_validation  a concrete concern that this layer cannot decide. Names
 *                    the missing fact and is handed to the owner. No severity.
 *  rejected          a candidate that verification disproved. Kept so it is
 *                    not raised again without new evidence.
 *
 * "Not enough evidence" is therefore neither a finding nor silence.
 */

/** Why a layer could not decide. */
export const BLOCKERS = [
  'not_observable_from_outside',
  'requires_source',
  'requires_deployment_fact',
  /** The setting is visible, but only the owner can say whether it is intended (e.g. public read). */
  'requires_owner_intent',
] as const;
export type Blocker = (typeof BLOCKERS)[number];

interface RecordBase {
  /** Stable across runs for the same issue; see fingerprintOf(). */
  fingerprint: string;
  ruleId: RuleId;
  /** Stable machine code; display text lives in src/i18n. */
  code: string;
  layer: Layer;
  mode: CheckMode;
  /** Id of the checker that produced the record. */
  checker: string;
  /** Where it was found. Shown to verified owners only. */
  location: string;
  /** Redacted evidence. Never a full secret, never fetched data. */
  evidence: string;
}

export interface ConfirmedRecord extends RecordBase {
  verdict: 'confirmed';
  severity: Severity;
}

export interface NeedsValidationRecord extends RecordBase {
  verdict: 'needs_validation';
  blocker: Blocker;
}

export interface RejectedRecord extends RecordBase {
  verdict: 'rejected';
  reason: string;
}

export type AssessmentRecord = ConfirmedRecord | NeedsValidationRecord | RejectedRecord;

/**
 * Fingerprint = hash of (layer, rule, code, stable key).
 * The key must identify the issue without volatile detail (no byte offsets,
 * no ports) and must never contain secret material.
 */
export function fingerprintOf(layer: Layer, ruleId: RuleId, code: string, key: string): string {
  const digest = createHash('sha256').update([layer, ruleId, code, key].join('\u0000')).digest('hex');
  return `fp_${digest.slice(0, 24)}`;
}

/** What a checker supplies; the factory adds verdict, layer, mode, checker and fingerprint. */
export interface RecordInput {
  ruleId: RuleId;
  code: string;
  /** Stable identity of the issue within the target (see fingerprintOf). */
  key: string;
  location: string;
  evidence: string;
}

export interface RecordFactory {
  confirmed(input: RecordInput & { severity: Severity }): ConfirmedRecord;
  needsValidation(input: RecordInput & { blocker: Blocker }): NeedsValidationRecord;
}

export function recordFactory(checker: string, layer: Layer, mode: CheckMode): RecordFactory {
  const base = ({ key, ...rest }: RecordInput): RecordBase => ({
    fingerprint: fingerprintOf(layer, rest.ruleId, rest.code, key),
    ...rest,
    layer,
    mode,
    checker,
  });
  return {
    confirmed: ({ severity, ...input }) => ({ ...base(input), verdict: 'confirmed', severity }),
    needsValidation: ({ blocker, ...input }) => ({ ...base(input), verdict: 'needs_validation', blocker }),
  };
}

/** Same issue reported twice (two files, two checkers) is one record. */
export function dedupeByFingerprint<T extends AssessmentRecord>(records: T[]): T[] {
  const seen = new Set<string>();
  return records.filter((r) => (seen.has(r.fingerprint) ? false : (seen.add(r.fingerprint), true)));
}
