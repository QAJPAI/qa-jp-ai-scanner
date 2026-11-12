// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { summarize, type Assessment, type Summary } from './core/assessment';
import type { CoverageUnit } from './core/coverage';
import type { ConfirmedRecord, NeedsValidationRecord } from './core/records';
import { SEVERITIES } from './core/types';
import { proofCovers, type OwnershipProof } from './ownership/proof';
import {
  blockerLabel,
  coverageNoteLabel,
  coverageStatusLabel,
  findingText,
  gradeLabel,
  needsValidationText,
  notRunReasonLabel,
  report as t,
  ruleTitle,
  severityLabel,
} from './i18n/ja';

/**
 * Reports are derived from an Assessment and from nothing else, so the text a
 * person reads cannot disagree with the data a machine can re-verify.
 */

/** What an unverified requester is allowed to see. */
export interface PublicSummary extends Summary {
  host: string;
  scannedAt: string;
  rulesVersion: string;
}

function targetName(assessment: Assessment): string {
  return assessment.target.layer === 'url' ? assessment.target.host : assessment.target.ref;
}

/**
 * Strip everything an unverified requester must not see. Always computed as
 * the public view, so a summary derived from an owner-tier assessment reveals
 * neither the outcome nor the existence of owner-only checks.
 */
export function toPublicSummary(assessment: Assessment): PublicSummary {
  return {
    host: targetName(assessment),
    scannedAt: assessment.startedAt,
    rulesVersion: assessment.rulesVersion,
    ...summarize(assessment, 'public'),
  };
}

const JST = new Intl.DateTimeFormat('ja-JP', {
  timeZone: 'Asia/Tokyo',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
});

function header(title: string, s: PublicSummary): string[] {
  const counts = SEVERITIES.map((sev) => `${sev}（${severityLabel[sev]}）${s.counts[sev]} ${t.countUnit}`).join(' / ');
  return [
    title,
    `${t.target}: ${s.host}`,
    `${t.scannedAt}: ${JST.format(new Date(s.scannedAt))}（日本時間）`,
    `${t.grade}: ${s.grade}（${gradeLabel[s.grade]}）`,
    `${t.counts}: ${counts}`,
    `${t.needsValidationCount}: ${s.needsValidation} ${t.countUnit}`,
    t.coverageLine(s.coverage.total, s.coverage.checked, s.coverage.partial),
  ];
}

/** A check that failed must be visible next to the grade it may have flattered. */
const incompleteLine = (s: PublicSummary): string[] => (s.coverage.error > 0 ? [t.incomplete(s.coverage.error)] : []);

export function renderPublicSummary(summary: PublicSummary): string {
  return [
    ...header(t.publicTitle, summary),
    ...incompleteLine(summary),
    t.checksPublic,
    '',
    t.detailsGated,
    t.disclaimer,
    `${t.rulesVersion}: v${summary.rulesVersion}`,
  ].join('\n');
}

function renderConfirmed(r: ConfirmedRecord, index: number): string[] {
  const text = findingText[r.code];
  return [
    `${index}. [${r.severity}・${severityLabel[r.severity]}] ${text?.title ?? r.code}（${r.ruleId}）`,
    `   ${t.location}: ${r.location}`,
    `   ${t.evidence}: ${r.evidence}`,
    `   ${t.fix}: ${text?.fix ?? '-'}`,
  ];
}

function renderNeedsValidation(r: NeedsValidationRecord, index: number): string[] {
  const text = needsValidationText[r.code];
  return [
    `${index}. ${text?.title ?? r.code}（${r.ruleId}）`,
    `   ${t.location}: ${r.location}`,
    `   ${t.evidence}: ${r.evidence}`,
    `   ${t.reason}: ${blockerLabel[r.blocker]}`,
    `   ${t.whatToCheck}: ${text?.plan ?? '-'}`,
  ];
}

function renderCoverage(unit: CoverageUnit): string {
  const detail =
    unit.status === 'not_run' && unit.reason
      ? notRunReasonLabel[unit.reason]
      : unit.status === 'partial' && unit.note
        ? coverageNoteLabel[unit.note]
        : unit.status === 'error' && unit.passive?.note
          ? coverageNoteLabel[unit.passive.note]
          : '';
  return `   ${unit.ruleId} ${ruleTitle[unit.ruleId]}: ${coverageStatusLabel[unit.status]}${detail ? `（${detail}）` : ''}`;
}

/**
 * Detailed report. The assessment is plain data and its `tier` field can be
 * edited, so the field alone is not trusted: the caller must present the
 * ownership proof again, and it must cover the assessed host and still be valid.
 */
export function renderOwnerReport(assessment: Assessment, proof: OwnershipProof, now: number = Date.now()): string {
  if (assessment.tier !== 'owner' || !proof || !proofCovers(proof, targetName(assessment), now)) {
    throw new Error('Detailed report requires a valid ownership proof for this target');
  }
  const summary: PublicSummary = {
    host: targetName(assessment),
    scannedAt: assessment.startedAt,
    rulesVersion: assessment.rulesVersion,
    ...summarize(assessment, 'owner'),
  };
  const confirmed = assessment.records
    .filter((r): r is ConfirmedRecord => r.verdict === 'confirmed')
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  const needsValidation = assessment.records.filter(
    (r): r is NeedsValidationRecord => r.verdict === 'needs_validation',
  );

  const lines = [...header(t.ownerTitle, summary), ...incompleteLine(summary), t.checksOwner, '', t.findingsHeading];
  if (confirmed.length === 0) lines.push(t.noFindings, '');
  else confirmed.forEach((r, i) => lines.push(...renderConfirmed(r, i + 1), ''));

  if (needsValidation.length > 0) {
    lines.push(t.needsValidationHeading);
    needsValidation.forEach((r, i) => lines.push(...renderNeedsValidation(r, i + 1), ''));
  }

  lines.push(t.coverageHeading, ...assessment.coverage.map(renderCoverage), '');
  lines.push(t.disclaimer, `${t.rulesVersion}: v${assessment.rulesVersion}`);
  return lines.join('\n');
}
