// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CoverageReport } from './coverage';
import type { AssessmentRecord, RecordFactory } from './records';
import type { CheckMode, Layer, RuleId } from './types';

/**
 * A checker is a pluggable inspector. It produces evidence; it does not judge.
 * The core decides what a set of records means (verdict contracts, coverage,
 * grade) and validates the result, whichever checker or vendor produced it.
 *
 * `Ctx` is whatever the layer provides: a fetched page for the URL layer, a
 * source tree for the repo layer.
 */
export interface Checker<Ctx> {
  /** Stable id, recorded on every record and coverage unit. */
  id: string;
  layer: Layer;
  mode: CheckMode;
  /** Rules this checker can produce evidence for. */
  rules: readonly RuleId[];
  run(ctx: Ctx, records: RecordFactory): Promise<CheckOutcome> | CheckOutcome;
}

export interface CheckOutcome {
  records: AssessmentRecord[];
  /** One entry per rule in `rules`, stating how far the check actually got. */
  coverage: CoverageReport[];
}
