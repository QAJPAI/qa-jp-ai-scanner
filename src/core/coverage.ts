// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { RULES } from './rules';
import { RULE_IDS, type CheckMode, type Layer, type RuleId, type Tier } from './types';

/**
 * The coverage ledger: for every rule, what this assessment did and did not
 * examine. A result may only ever claim what the ledger shows. A rule that was
 * not examined is recorded as not_run with the reason — never as passed.
 */

export type CoverageStatus = 'checked' | 'partial' | 'not_run' | 'error';

export type NotRunReason = 'requires_owner_verification' | 'requires_source' | 'not_implemented';

/** Known limits of a check that did run. */
export type CoverageNote = 'html_referenced_scripts_only' | 'presence_hint_only';

export interface CoverageUnit {
  ruleId: RuleId;
  layer: Layer;
  status: CoverageStatus;
  /** Present when status is checked, partial or error. */
  mode?: CheckMode;
  checker?: string;
  /** Present when status is not_run. */
  reason?: NotRunReason;
  /** Present when status is partial. */
  note?: CoverageNote;
}

/** What a checker reports about the rules it covers. */
export interface CoverageReport {
  ruleId: RuleId;
  status: 'checked' | 'partial' | 'error';
  note?: CoverageNote;
}

export interface CheckerCoverage {
  checker: string;
  mode: CheckMode;
  reports: CoverageReport[];
}

/** A rule a checker of this layer could cover but that was not run this time. */
export interface DeferredRule {
  ruleId: RuleId;
  reason: NotRunReason;
}

const STATUS_RANK: Record<CoverageStatus, number> = { checked: 3, partial: 2, error: 1, not_run: 0 };

/**
 * Build the ledger for one layer. Always returns exactly one unit per rule,
 * so the ledger can be read as "N of 15 rules examined".
 */
export function buildLedger(layer: Layer, ran: CheckerCoverage[], deferred: DeferredRule[] = []): CoverageUnit[] {
  const best = new Map<RuleId, CoverageUnit>();
  for (const { checker, mode, reports } of ran) {
    for (const report of reports) {
      const unit: CoverageUnit = { ruleId: report.ruleId, layer, status: report.status, mode, checker };
      if (report.status === 'partial' && report.note) unit.note = report.note;
      const current = best.get(report.ruleId);
      if (!current || STATUS_RANK[unit.status] > STATUS_RANK[current.status]) best.set(report.ruleId, unit);
    }
  }
  const deferredReason = new Map(deferred.map((d) => [d.ruleId, d.reason]));

  return RULE_IDS.map((ruleId) => {
    const unit = best.get(ruleId);
    if (unit) return unit;
    const reason: NotRunReason =
      deferredReason.get(ruleId) ?? (RULES[ruleId].layers.includes(layer) ? 'not_implemented' : 'requires_source');
    return { ruleId, layer, status: 'not_run', reason };
  });
}

export interface CoverageCounts {
  total: number;
  checked: number;
  partial: number;
  notRun: number;
  error: number;
}

/**
 * Count the ledger as seen by a tier. For 'public', units covered by an
 * active check are counted as not run, so the summary never reveals that an
 * owner-only check took place.
 */
export function countCoverage(units: CoverageUnit[], tier: Tier): CoverageCounts {
  const counts: CoverageCounts = { total: units.length, checked: 0, partial: 0, notRun: 0, error: 0 };
  for (const unit of units) {
    const hidden = tier === 'public' && unit.mode === 'active';
    if (hidden || unit.status === 'not_run') counts.notRun++;
    else if (unit.status === 'checked') counts.checked++;
    else if (unit.status === 'partial') counts.partial++;
    else counts.error++;
  }
  return counts;
}
