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

export const NOT_RUN_REASONS = [
  'requires_owner_verification',
  'requires_source',
  /** A repo-layer assessment: this rule is answered by checking the deployed site. */
  'requires_deployed_site',
  /** The checker ran and found nothing the rule applies to (e.g. no Supabase or Firebase in the project). */
  'not_applicable',
  'not_implemented',
  /** The operator of a service has switched this kind of check off (e.g. active checks). */
  'disabled_by_operator',
] as const;
export type NotRunReason = (typeof NOT_RUN_REASONS)[number];

/** Known limits of a check that did run. */
export const COVERAGE_NOTES = [
  'html_referenced_scripts_only',
  /** The page's scripts and the scripts those load, as far as they are named in the code. */
  'scripts_and_their_imports',
  'presence_hint_only',
  /** Names written in the site's code were listed for the owner; nothing behind them was requested. */
  'names_in_code_only',
  'some_content_not_read',
  'record_limit_reached',
  'some_probes_failed',
  /** Repo layer: settings written in code were examined; settings changed in a dashboard were not. */
  'code_only',
  /** Repo layer: some files were too large, too many, unreadable or symbolic links. */
  'some_files_not_read',
] as const;
export type CoverageNote = (typeof COVERAGE_NOTES)[number];

/** How far one mode of checking got on a rule. */
export interface ModeCoverage {
  status: 'checked' | 'partial' | 'error';
  checker: string;
  /** Present exactly when status is partial. */
  note?: CoverageNote;
}

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
  /**
   * Present only when the unit above comes from an active check and a passive
   * check also covered the rule. The public view is built from this, so it
   * neither changes nor reveals anything when an owner-only check runs.
   */
  passive?: ModeCoverage;
}

/**
 * Why a rule that a site check did not examine can still be reviewed today:
 * in the source code. Either it cannot be seen from outside at all, or the
 * site check has no inspector for it yet.
 */
export const SOURCE_REVIEW_REASONS = ['requires_source', 'not_implemented'] as const satisfies readonly NotRunReason[];
export type SourceReviewReason = (typeof SOURCE_REVIEW_REASONS)[number];
export type SourceReviewUnit = CoverageUnit & { status: 'not_run'; reason: SourceReviewReason };

/** The rules of a site check that are left to a review of the source code. Empty for any other layer. */
export function leftToSourceReview(coverage: readonly CoverageUnit[]): SourceReviewUnit[] {
  const reasons: readonly NotRunReason[] = SOURCE_REVIEW_REASONS;
  return coverage.filter(
    (u): u is SourceReviewUnit =>
      u.layer === 'url' && u.status === 'not_run' && u.reason !== undefined && reasons.includes(u.reason),
  );
}

/** What a checker reports about one rule it covers. A partial result must say why. */
export type CoverageReport =
  | { ruleId: RuleId; status: 'checked' | 'error' }
  | { ruleId: RuleId; status: 'partial'; note: CoverageNote };

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

const STATUS_RANK: Record<ModeCoverage['status'], number> = { checked: 3, partial: 2, error: 1 };

function better(a: ModeCoverage | undefined, b: ModeCoverage): ModeCoverage {
  return !a || STATUS_RANK[b.status] > STATUS_RANK[a.status] ? b : a;
}

/**
 * Build the ledger for one layer. Always returns exactly one unit per rule,
 * so the ledger can be read as "N of 15 rules examined".
 */
export function buildLedger(layer: Layer, ran: CheckerCoverage[], deferred: DeferredRule[] = []): CoverageUnit[] {
  const best: Record<CheckMode, Map<RuleId, ModeCoverage>> = { passive: new Map(), active: new Map() };
  for (const { checker, mode, reports } of ran) {
    for (const report of reports) {
      const entry: ModeCoverage = { status: report.status, checker };
      if (report.status === 'partial') entry.note = report.note;
      best[mode].set(report.ruleId, better(best[mode].get(report.ruleId), entry));
    }
  }
  const deferredReason = new Map(deferred.map((d) => [d.ruleId, d.reason]));

  return RULE_IDS.map((ruleId): CoverageUnit => {
    const passive = best.passive.get(ruleId);
    const active = best.active.get(ruleId);
    const winner = active && (!passive || STATUS_RANK[active.status] > STATUS_RANK[passive.status]) ? active : passive;

    if (!winner) {
      const otherLayer: NotRunReason = layer === 'url' ? 'requires_source' : 'requires_deployed_site';
      const reason: NotRunReason =
        deferredReason.get(ruleId) ?? (RULES[ruleId].layers.includes(layer) ? 'not_implemented' : otherLayer);
      return { ruleId, layer, status: 'not_run', reason };
    }
    const unit: CoverageUnit = {
      ruleId,
      layer,
      status: winner.status,
      mode: winner === active ? 'active' : 'passive',
      checker: winner.checker,
    };
    if (winner.note) unit.note = winner.note;
    if (winner === active && passive) unit.passive = passive;
    return unit;
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
 * Count the ledger as seen by a tier. The 'public' view counts passive
 * coverage only: a rule covered solely by an active check counts as not run,
 * and a rule covered by both counts by its passive result. The public summary
 * is therefore identical whether or not owner-only checks ran.
 */
export function countCoverage(units: CoverageUnit[], tier: Tier): CoverageCounts {
  const counts: CoverageCounts = { total: units.length, checked: 0, partial: 0, notRun: 0, error: 0 };
  for (const unit of units) {
    let status: CoverageStatus = unit.status;
    if (tier === 'public' && unit.mode === 'active') status = unit.passive?.status ?? 'not_run';

    if (status === 'not_run') counts.notRun++;
    else if (status === 'checked') counts.checked++;
    else if (status === 'partial') counts.partial++;
    else counts.error++;
  }
  return counts;
}
