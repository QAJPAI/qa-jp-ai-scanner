// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from './core/assessment';
import type { ConfirmedRecord, NeedsValidationRecord } from './core/records';
import { SEVERITIES } from './core/types';
import {
  blockerLabel,
  coverageNoteLabel,
  findingTextFor,
  handoff as h,
  needsValidationText,
  notRunReasonLabel,
  report as t,
  ruleReviewFocus,
  ruleTitle,
  severityLabel,
} from './i18n/ja';
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
 */
export function renderHandoff(assessment: Assessment): string {
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
      h.field(t.location, cleanText(r.location)),
      h.field(t.evidence, cleanText(r.evidence)),
      h.field(t.fix, text?.fix ?? '-'),
    );
  }

  lines.push('', h.needsValidationHeading, '', h.needsValidationIntro, '');
  if (needsValidation.length === 0) lines.push(h.noneNeedsValidation);
  for (const r of needsValidation) {
    const text = needsValidationText[r.code];
    lines.push(
      h.plainLine(text?.title ?? r.code, r.ruleId),
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

  lines.push('', h.reportHeading, '', ...h.reportRules.map((rule, i) => `${i + 1}. ${rule}`), '');
  return lines.join('\n');
}
