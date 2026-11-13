// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from './assessment';
import type { CoverageUnit } from './coverage';
import type { AssessmentRecord, ConfirmedRecord, NeedsValidationRecord } from './records';

/**
 * Compare a re-check with an earlier one, issue by issue (by fingerprint).
 *
 * "It is gone" is not "it is fixed". A problem counts as fixed only when the
 * same tool version re-examined its rule at least as fully as before, read the
 * file it was in, and found no problem of the same kind newly in that file.
 * Otherwise it is reported as gone but unverified, with the reason — so that
 * deleting, renaming or hiding a file never reads as a fix.
 *
 * What is still present comes from the current check alone. An earlier result
 * that was edited can at most invent a "fixed" item that never existed; it
 * cannot hide a problem the current check finds.
 */

export type UnverifiedReason =
  /** The two checks were made by different engine or rule versions. */
  | 'tool_changed'
  /** The rule was not examined, or the check failed, this time. */
  | 'rule_not_examined'
  /** The rule was examined less fully than before (files unread, limits hit). */
  | 'coverage_reduced'
  /** The file the problem was in was not read this time (deleted, moved, too large, a link). */
  | 'file_not_read'
  /** A new problem or question of the same kind is now reported in the same file. */
  | 'similar_finding_present';

export interface Comparison {
  previousAt: string;
  fixed: ConfirmedRecord[];
  stillPresent: ConfirmedRecord[];
  unverified: Array<{ record: ConfirmedRecord; reason: UnverifiedReason }>;
  newConfirmed: ConfirmedRecord[];
  /** Owner questions from before that no longer arise (same checks as above). */
  questionsResolved: NeedsValidationRecord[];
  questionsUnverified: Array<{ record: NeedsValidationRecord; reason: UnverifiedReason }>;
  questionsOpen: NeedsValidationRecord[];
  questionsNew: NeedsValidationRecord[];
  /** Engine or rule version differs: nothing is counted as fixed or resolved. */
  toolChanged: boolean;
}

export class ComparisonError extends Error {
  constructor(
    readonly code: 'different_target' | 'invalid_previous',
    message: string,
  ) {
    super(message);
    this.name = 'ComparisonError';
  }
}

export interface CompareOptions {
  /**
   * Repo layer: was this project-relative path read in full by the current
   * check? Paths come from the earlier result, which is untrusted, so this must
   * be a lookup in what the check read — never a file-system access.
   * Omit only where files do not apply.
   */
  wasRead?: (path: string) => boolean;
}

/** How fully a rule was examined. Higher is more. */
function depth(unit: CoverageUnit | undefined): number {
  if (!unit) return 0;
  if (unit.status === 'checked') return 3;
  if (unit.status === 'partial') {
    const limited = ['some_files_not_read', 'some_content_not_read', 'record_limit_reached', 'some_probes_failed'];
    return unit.note && limited.includes(unit.note) ? 1 : 2;
  }
  return 0;
}

/** Codes of one kind share the part before the first dot: "rls.not_enabled" and "rls.not_enabled_unclear". */
export const codeFamily = (code: string): string => code.slice(0, Math.max(0, code.indexOf('.'))) || code;

/** The file part of a repo-layer location: "path:12", "path" or "path (detail)". */
export function locationFile(location: string): string {
  return location.replace(/ \(.*\)$/, '').replace(/:\d+$/, '');
}

const isConfirmed = (r: AssessmentRecord): r is ConfirmedRecord => r.verdict === 'confirmed';
const isQuestion = (r: AssessmentRecord): r is NeedsValidationRecord => r.verdict === 'needs_validation';

function targetKey(a: Assessment): string {
  return a.target.layer === 'url' ? `url:${a.target.host}` : `repo:${a.target.ref}`;
}

export function compareAssessments(previous: Assessment, current: Assessment, options: CompareOptions = {}): Comparison {
  if (targetKey(previous) !== targetKey(current)) {
    throw new ComparisonError('different_target', 'The earlier result is for a different project or site');
  }

  const now = new Map(current.records.map((r) => [r.fingerprint, r]));
  const unitNow = new Map(current.coverage.map((u) => [u.ruleId, u]));
  const unitBefore = new Map(previous.coverage.map((u) => [u.ruleId, u]));
  // "New" is judged per verdict, so a problem turned into a question is a new question.
  const seenBefore = new Set(previous.records.map((r) => `${r.verdict}\u0000${r.fingerprint}`));
  const isNew = (r: AssessmentRecord) => r.verdict !== 'rejected' && !seenBefore.has(`${r.verdict}\u0000${r.fingerprint}`);
  const fileOf = (r: AssessmentRecord) => (r.layer === 'repo' ? locationFile(r.location) : r.location);

  const toolChanged =
    previous.engineVersion !== current.engineVersion || previous.rulesVersion !== current.rulesVersion;

  /** Why a record that disappeared cannot be called fixed, if there is a reason. */
  const doubt = (r: AssessmentRecord): UnverifiedReason | undefined => {
    if (toolChanged) return 'tool_changed';
    const dNow = depth(unitNow.get(r.ruleId));
    if (dNow === 0) return 'rule_not_examined';
    if (dNow < depth(unitBefore.get(r.ruleId))) return 'coverage_reduced';
    if (r.layer === 'repo' && options.wasRead && !options.wasRead(locationFile(r.location))) return 'file_not_read';
    // Renamed, rewritten or merely made ambiguous (a confirmed problem that is now
    // only a question) is not removed: any new record of the same kind in the
    // same place keeps the old one from counting as fixed.
    const file = fileOf(r);
    const similar = current.records.some(
      (c) => isNew(c) && c.ruleId === r.ruleId && codeFamily(c.code) === codeFamily(r.code) && fileOf(c) === file,
    );
    return similar ? 'similar_finding_present' : undefined;
  };

  const result: Comparison = {
    previousAt: previous.startedAt,
    fixed: [],
    stillPresent: [],
    unverified: [],
    newConfirmed: current.records.filter(isConfirmed).filter(isNew),
    questionsResolved: [],
    questionsUnverified: [],
    questionsOpen: [],
    questionsNew: current.records.filter(isQuestion).filter(isNew),
    toolChanged,
  };

  for (const r of previous.records.filter(isConfirmed)) {
    const still = now.get(r.fingerprint);
    if (still && isConfirmed(still)) {
      result.stillPresent.push(still);
      continue;
    }
    const reason = doubt(r);
    if (reason) result.unverified.push({ record: r, reason });
    else result.fixed.push(r);
  }

  for (const r of previous.records.filter(isQuestion)) {
    const still = now.get(r.fingerprint);
    if (still && isQuestion(still)) {
      result.questionsOpen.push(still);
      continue;
    }
    const reason = doubt(r);
    if (reason) result.questionsUnverified.push({ record: r, reason });
    else result.questionsResolved.push(r);
  }
  return result;
}
