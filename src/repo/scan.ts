// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from '../core/assessment';
import type { Checker } from '../core/checker';
import { buildLedger, type CheckerCoverage, type DeferredRule } from '../core/coverage';
import { dedupeByFingerprint, recordFactory, type AssessmentRecord } from '../core/records';
import { ASSESSMENT_SCHEMA, ENGINE_VERSION, RULES_VERSION } from '../core/types';
import { accessRulesChecker } from './checkers/access-rules';
import { repoSecretsChecker } from './checkers/secrets';
import type { RepoContext } from './context';
import { loadRepo, type LoadOptions } from './load';

/**
 * Entrance B: check a project's source code before it is deployed.
 *
 * The person running this has the code, which is all the ownership the
 * repository layer needs, so the result is owner tier. Nothing is executed and
 * nothing leaves the machine: checkers only read the files loadRepo() returns.
 */

export const REPO_CHECKERS: readonly Checker<RepoContext>[] = [accessRulesChecker, repoSecretsChecker];

export interface RepoScanOptions extends LoadOptions {
  now?: () => number;
  checkers?: readonly Checker<RepoContext>[];
}

export async function scanRepo(root: string, options: RepoScanOptions = {}): Promise<Assessment> {
  const now = options.now ?? Date.now;
  const ctx = await loadRepo(root, options);

  const records: AssessmentRecord[] = [];
  const ran: CheckerCoverage[] = [];
  const deferred: DeferredRule[] = [];

  for (const checker of options.checkers ?? REPO_CHECKERS) {
    try {
      const outcome = await checker.run(ctx, recordFactory(checker.id, checker.layer, checker.mode));
      for (const record of outcome.records) records.push(record);
      ran.push({ checker: checker.id, mode: checker.mode, reports: outcome.coverage });
      for (const ruleId of outcome.notApplicable ?? []) deferred.push({ ruleId, reason: 'not_applicable' });
    } catch {
      // A failed check is recorded as such; it must never read as "nothing found".
      ran.push({
        checker: checker.id,
        mode: checker.mode,
        reports: checker.rules.map((ruleId) => ({ ruleId, status: 'error' as const })),
      });
    }
  }

  return {
    schema: ASSESSMENT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    rulesVersion: RULES_VERSION,
    target: { layer: 'repo', ref: ctx.name },
    tier: 'owner',
    startedAt: new Date(now()).toISOString(),
    records: dedupeByFingerprint(records),
    coverage: buildLedger('repo', ran, deferred),
  };
}
