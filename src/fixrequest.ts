// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from './core/assessment';
import type { ConfirmedRecord, NeedsValidationRecord } from './core/records';
import { SEVERITIES } from './core/types';
import {
  afterFixNoteFor,
  blockerLabel,
  findingTextFor,
  fixRequest,
  fixRequestUrl,
  fixStepsFor,
  handoff as h,
  needsValidationText,
  report as t,
  severityLabel,
} from './i18n/ja';
import { RECHECK_COMMAND } from './invocation';
import { targetName } from './report';
import { cleanText } from './text';

/**
 * The fix request: one text the owner pastes into their AI coding tool. Every
 * confirmed problem, most serious first, with concrete steps, the conditions
 * the AI must keep, and how the result is re-checked — so "fixed" is decided
 * by the tool, not by the AI.
 *
 * For a project (`qa-scan check --fix-request`) the AI runs the re-check
 * command itself. For a published site there is no such command: the owner
 * publishes the fix and checks the site again, so the text says that instead.
 *
 * Owner questions are listed for the AI to ask, never to answer.
 *
 * It contains locations and evidence. For a site, show it only to a verified
 * owner — the same rule as the detailed report.
 */
export function renderFixRequest(assessment: Assessment): string {
  const site = assessment.target.layer === 'url';
  const f = site ? { ...fixRequest, ...fixRequestUrl } : fixRequest;
  const confirmed = assessment.records
    .filter((r): r is ConfirmedRecord => r.verdict === 'confirmed')
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  const questions = assessment.records.filter((r): r is NeedsValidationRecord => r.verdict === 'needs_validation');

  const lines: string[] = [
    `# ${f.title}`,
    '',
    f.intro,
    '',
    f.meta(cleanText(targetName(assessment), 120), assessment.engineVersion, assessment.rulesVersion),
    '',
    f.dataWarning,
    '',
    f.rulesHeading,
    '',
    ...f.rules.map((rule, i) => `${i + 1}. ${rule}`),
    '',
    f.itemsHeading(confirmed.length),
    '',
  ];

  if (confirmed.length === 0) lines.push(f.noItems, '');
  confirmed.forEach((r, i) => {
    const text = findingTextFor(r.layer, r.code);
    const note = afterFixNoteFor(r.layer, r.code);
    lines.push(
      f.item(i + 1, r.severity, severityLabel[r.severity], text?.title ?? r.code, r.ruleId),
      '',
      h.field(f.id, r.fingerprint),
      h.field(t.location, cleanText(r.location)),
      h.field(t.evidence, cleanText(r.evidence)),
      `  - ${f.steps}:`,
      ...fixStepsFor(r.layer, r.code).map((step, n) => `    ${n + 1}. ${step}`),
    );
    if (note) lines.push(h.field(f.afterFix, note));
    lines.push('');
  });

  if (questions.length > 0) {
    lines.push(f.questionsHeading(questions.length), '', f.questionsIntro, '');
    for (const r of questions) {
      const text = needsValidationText[r.code];
      lines.push(
        h.plainLine(text?.title ?? r.code, r.ruleId),
        h.field(f.id, r.fingerprint),
        h.field(t.location, cleanText(r.location)),
        h.field(t.reason, blockerLabel[r.blocker]),
        h.field(t.whatToCheck, text?.plan ?? '-'),
      );
    }
    lines.push('');
  }

  lines.push(f.recheckHeading, '', f.recheckIntro, '');
  if (!site) lines.push('```', RECHECK_COMMAND, '```', '');
  return lines.join('\n');
}
