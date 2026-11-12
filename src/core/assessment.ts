// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { countCoverage, type CoverageCounts, type CoverageUnit } from './coverage';
import type { AssessmentRecord, ConfirmedRecord } from './records';
import { RULES } from './rules';
import type { ASSESSMENT_SCHEMA, Grade, Layer, Severity, Tier } from './types';

/**
 * The one result format for every layer. Reports, badges and re-verification
 * all start from this object, so prose can never disagree with the data.
 */
export interface Assessment {
  schema: typeof ASSESSMENT_SCHEMA;
  engineVersion: string;
  rulesVersion: string;
  target: AssessmentTarget;
  tier: Tier;
  startedAt: string;
  records: AssessmentRecord[];
  coverage: CoverageUnit[];
}

export type AssessmentTarget = { layer: 'url'; host: string } | { layer: 'repo'; ref: string };

export type SeverityCounts = Record<Severity, number>;

export interface Summary {
  layer: Layer;
  grade: Grade;
  /** Confirmed records only. */
  counts: SeverityCounts;
  /** Items handed to the owner to check. */
  needsValidation: number;
  coverage: CoverageCounts;
}

export function countBySeverity(records: ConfirmedRecord[]): SeverityCounts {
  const counts: SeverityCounts = { P0: 0, P1: 0, P2: 0 };
  for (const r of records) counts[r.severity]++;
  return counts;
}

/** Any P0 fails outright. A grade never means "safe", only "nothing found in what was examined". */
export function gradeFor(counts: SeverityCounts): Grade {
  if (counts.P0 > 0) return 'E';
  if (counts.P1 > 0) return 'D';
  if (counts.P2 >= 4) return 'C';
  if (counts.P2 >= 1) return 'B';
  return 'A';
}

/**
 * Summarize an assessment as seen by a tier.
 *
 * The 'public' view counts only passive records under rules whose findings may
 * be disclosed to anyone (basic configuration). For every other rule the
 * public view carries nothing at all — not a count, not a hint — so it is the
 * same for a site with a leaked key as for a site without one.
 */
export function summarize(assessment: Assessment, as: Tier = assessment.tier): Summary {
  const visible = assessment.records.filter(
    (r) => as === 'owner' || (r.mode === 'passive' && RULES[r.ruleId].disclosure === 'public'),
  );
  const confirmed = visible.filter((r): r is ConfirmedRecord => r.verdict === 'confirmed');
  const counts = countBySeverity(confirmed);
  return {
    layer: assessment.target.layer,
    grade: gradeFor(counts),
    counts,
    needsValidation: visible.filter((r) => r.verdict === 'needs_validation').length,
    coverage: countCoverage(assessment.coverage, as),
  };
}
