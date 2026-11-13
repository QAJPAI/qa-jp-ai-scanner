// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from './core/assessment';
import type { Comparison } from './core/compare';
import type { ConfirmedRecord, NeedsValidationRecord } from './core/records';
import { SEVERITIES } from './core/types';
import {
  afterFixNoteFor,
  blockerLabel,
  comparison as c,
  coverageNoteLabel,
  findingTextFor,
  fixRequest as f,
  fixStepsFor,
  handoff as h,
  handoffComparison as hc,
  needsValidationText,
  notRunReasonLabel,
  report as t,
  ruleReviewFocus,
  ruleTitle,
  severityLabel,
  unverifiedReasonLabel,
} from './i18n/ja';
import { commandFor, RECHECK_COMMAND } from './invocation';
import { targetName } from './report';
import { cleanText } from './text';

/**
 * The hand-off from the scanner to an AI coding tool (`qa-scan check --for-ai`).
 *
 * It keeps three things apart, because they carry different weight:
 *  1. what the scanner confirmed with evidence — to be passed on unchanged;
 *  2. what only the owner can decide — to be asked, not answered;
 *  3. what the scanner did not examine — for the AI to review, labelled as its own judgement.
 *
 * Everything taken from the project is cleaned (cleanText) and the AI is told
 * that it is data, not instructions.
 *
 * On a re-check, section 0 says what the tool confirmed as fixed. That list,
 * not the AI's own impression, is what the AI may report as fixed.
 */
export interface HandoffOptions {
  /** This re-check compared with an earlier result. */
  comparison?: Comparison;
  /** This check's result was saved for a later re-check. */
  baselineSaved?: boolean;
}

function comparisonLines(cmp: Comparison): string[] {
  const line = (r: ConfirmedRecord) => {
    const text = findingTextFor(r.layer, r.code);
    return h.severityLine(r.severity, severityLabel[r.severity], text?.title ?? r.code, r.ruleId);
  };
  const lines = [hc.heading, '', hc.intro, ''];
  if (cmp.toolChanged) lines.push(c.toolChanged, '');

  lines.push(`### ${hc.fixed}（${cmp.fixed.length} 件）`);
  if (cmp.fixed.length === 0) lines.push(c.none);
  for (const r of cmp.fixed) {
    const note = afterFixNoteFor(r.layer, r.code);
    lines.push(line(r), h.field(h.id, r.fingerprint), h.field(t.location, cleanText(r.location)));
    if (note) lines.push(h.field(c.note, note));
  }

  lines.push('', `### ${hc.unverified}（${cmp.unverified.length} 件）`);
  if (cmp.unverified.length === 0) lines.push(c.none);
  for (const { record: r, reason } of cmp.unverified) {
    lines.push(
      line(r),
      h.field(h.id, r.fingerprint),
      h.field(t.location, cleanText(r.location)),
      h.field(c.reason, unverifiedReasonLabel[reason]),
    );
  }

  lines.push(
    '',
    `### ${hc.added}（${cmp.newConfirmed.length} 件）`,
    ...(cmp.newConfirmed.length === 0 ? [c.none] : cmp.newConfirmed.map(line)),
    '',
    `### ${hc.still}（${cmp.stillPresent.length} 件）`,
    ...(cmp.stillPresent.length === 0 ? [c.none] : cmp.stillPresent.map(line)),
    '',
    c.questionsLine(
      cmp.questionsResolved.length,
      cmp.questionsOpen.length,
      cmp.questionsNew.length,
      cmp.questionsUnverified.length,
    ),
    '',
  );
  return lines;
}

export function renderHandoff(assessment: Assessment, options: HandoffOptions = {}): string {
  if (assessment.target.layer !== 'repo') throw new Error('The AI hand-off is for source-code checks only');

  const confirmed = assessment.records
    .filter((r): r is ConfirmedRecord => r.verdict === 'confirmed')
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  const needsValidation = assessment.records.filter(
    (r): r is NeedsValidationRecord => r.verdict === 'needs_validation',
  );

  const lines: string[] = [
    `# ${h.title}`,
    '',
    h.meta(cleanText(targetName(assessment), 120), assessment.engineVersion, assessment.rulesVersion),
    '',
    h.dataWarning,
    '',
    ...(options.comparison ? comparisonLines(options.comparison) : []),
    h.confirmedHeading,
    '',
    h.confirmedIntro,
    '',
  ];
  if (confirmed.length === 0) lines.push(h.noneConfirmed);
  for (const r of confirmed) {
    const text = findingTextFor(r.layer, r.code);
    lines.push(
      h.severityLine(r.severity, severityLabel[r.severity], text?.title ?? r.code, r.ruleId),
      h.field(h.id, r.fingerprint),
      h.field(t.location, cleanText(r.location)),
      h.field(t.evidence, cleanText(r.evidence)),
      h.field(t.fix, text?.fix ?? '-'),
      `  - ${f.steps}:`,
      ...fixStepsFor(r.layer, r.code).map((step, n) => `    ${n + 1}. ${step}`),
    );
  }

  lines.push('', h.needsValidationHeading, '', h.needsValidationIntro, '');
  if (needsValidation.length === 0) lines.push(h.noneNeedsValidation);
  for (const r of needsValidation) {
    const text = needsValidationText[r.code];
    lines.push(
      h.plainLine(text?.title ?? r.code, r.ruleId),
      h.field(h.id, r.fingerprint),
      h.field(t.location, cleanText(r.location)),
      h.field(t.evidence, cleanText(r.evidence)),
      h.field(t.reason, blockerLabel[r.blocker]),
      h.field(t.whatToCheck, text?.plan ?? '-'),
    );
  }

  lines.push('', h.reviewHeading, '', h.reviewIntro, '');
  const notApplicable: string[] = [];
  for (const unit of assessment.coverage) {
    if (unit.status === 'checked') continue;
    if (unit.status === 'not_run' && unit.reason === 'not_applicable') {
      notApplicable.push(h.notApplicableLine(unit.ruleId, ruleTitle[unit.ruleId]));
      continue;
    }
    const status =
      unit.status === 'partial' && unit.note
        ? `${h.partialPrefix}（${coverageNoteLabel[unit.note]}）`
        : unit.status === 'not_run' && unit.reason
          ? `${h.notRunPrefix}（${notRunReasonLabel[unit.reason]}）`
          : `${h.notRunPrefix}`;
    lines.push(`- ${unit.ruleId} ${ruleTitle[unit.ruleId]}`, h.field(t.reason, status), h.field(h.focus, ruleReviewFocus[unit.ruleId]));
    if (unit.status === 'not_run' && unit.reason === 'requires_deployed_site') lines.push(h.field('補足', h.deployedNote));
  }

  if (notApplicable.length > 0) lines.push('', h.notApplicableHeading, '', ...notApplicable);

  const rules = [
    ...h.reportRules,
    h.recheckRule(Boolean(options.baselineSaved || options.comparison), commandFor('check . --baseline'), RECHECK_COMMAND),
  ];
  lines.push('', h.reportHeading, '', ...rules.map((rule, i) => `${i + 1}. ${rule}`), '');
  return lines.join('\n');
}
