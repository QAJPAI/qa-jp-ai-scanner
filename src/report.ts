// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { summarize, type Assessment, type Summary } from './core/assessment';
import { leftToSourceReview, type CoverageUnit } from './core/coverage';
import { commandFor } from './invocation';
import type { ConfirmedRecord, NeedsValidationRecord } from './core/records';
import { SEVERITIES, type Severity } from './core/types';
import { proofCovers, type OwnershipProof } from './ownership/proof';
import { cleanText } from './text';
import {
  blockerLabel,
  coverageNoteLabel,
  coverageStatusLabel,
  findingTextFor,
  gradeLabel,
  needsValidationText,
  publicGradeLabel,
  notRunReasonLabel,
  report as t,
  ruleTitle,
  severityLabel,
} from './i18n/ja';

/**
 * Reports are derived from an Assessment and from nothing else, so the text a
 * person reads cannot disagree with the data a machine can re-verify.
 */

interface Headed {
  host: string;
  scannedAt: string;
  rulesVersion: string;
}

/**
 * What an unverified requester is allowed to see: the basic-configuration
 * grade and counts, and how much was examined. It has no field that could
 * carry anything about owner-only rules.
 */
export type PublicSummary = Headed & Omit<Summary, 'needsValidation'>;

type OwnerSummary = Headed & Summary;

export function targetName(assessment: Assessment): string {
  return assessment.target.layer === 'url' ? assessment.target.host : assessment.target.ref;
}

/**
 * Strip everything an unverified requester must not see. Always computed as
 * the public view, so a summary derived from an owner-tier assessment reveals
 * neither the outcome nor the existence of owner-only checks.
 */
export function toPublicSummary(assessment: Assessment): PublicSummary {
  const { needsValidation: _ownerOnly, ...summary } = summarize(assessment, 'public');
  return {
    host: targetName(assessment),
    scannedAt: assessment.startedAt,
    rulesVersion: assessment.rulesVersion,
    ...summary,
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

const countsText = (s: PublicSummary, severities: readonly Severity[]) =>
  severities.map((sev) => `${sev}（${severityLabel[sev]}）${s.counts[sev]} ${t.countUnit}`).join(' / ');

const headLines = (title: string, s: Headed): string[] => [
  title,
  `${t.target}: ${cleanText(s.host, 120)}`,
  `${t.scannedAt}: ${JST.format(new Date(s.scannedAt))}（日本時間）`,
];

/** A check that failed must be visible next to the grade it may have flattered. */
const incompleteLine = (s: PublicSummary): string[] => (s.coverage.error > 0 ? [t.incomplete(s.coverage.error)] : []);

/**
 * The public view. It reports basic configuration only and always carries the
 * same sentence about serious problems, whether or not any exist.
 */
export function renderPublicSummary(summary: PublicSummary): string {
  return [
    ...headLines(t.publicTitle, summary),
    `${t.basicGrade}: ${summary.grade}（${publicGradeLabel[summary.grade]}）`,
    // Basic-configuration rules cannot reach P0, so only P1 and P2 are listed.
    `${t.basicCounts}: ${countsText(summary, ['P1', 'P2'])}`,
    t.coverageLine(summary.coverage.total, summary.coverage.checked, summary.coverage.partial),
    ...incompleteLine(summary),
    t.checksPublic,
    '',
    t.seriousGated,
    t.sameForEverySite,
    t.disclaimer,
    `${t.rulesVersion}: v${summary.rulesVersion}`,
  ].join('\n');
}

function ownerHeader(s: OwnerSummary): string[] {
  return [
    ...headLines(t.ownerTitle, s),
    `${t.grade}: ${s.grade}（${gradeLabel[s.grade]}）`,
    `${t.counts}: ${countsText(s, SEVERITIES)}`,
    `${t.needsValidationCount}: ${s.needsValidation} ${t.countUnit}`,
    t.coverageLine(s.coverage.total, s.coverage.checked, s.coverage.partial),
  ];
}

function renderConfirmed(r: ConfirmedRecord, index: number): string[] {
  const text = findingTextFor(r.layer, r.code);
  return [
    `${index}. [${r.severity}・${severityLabel[r.severity]}] ${text?.title ?? r.code}（${r.ruleId}）`,
    `   ${t.location}: ${cleanText(r.location)}`,
    `   ${t.evidence}: ${cleanText(r.evidence)}`,
    `   ${t.fix}: ${text?.fix ?? '-'}`,
  ];
}

function renderNeedsValidation(r: NeedsValidationRecord, index: number): string[] {
  const text = needsValidationText[r.code];
  return [
    `${index}. ${text?.title ?? r.code}（${r.ruleId}）`,
    `   ${t.location}: ${cleanText(r.location)}`,
    `   ${t.evidence}: ${cleanText(r.evidence)}`,
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
  if (
    assessment.target.layer !== 'url' ||
    assessment.tier !== 'owner' ||
    !proof ||
    !proofCovers(proof, targetName(assessment), now)
  ) {
    throw new Error('Detailed report requires a valid ownership proof for this target');
  }
  const text = renderDetails(assessment, ownerHeader, t.checksOwner, t.needsValidationHeading);
  const routed = leftToSourceReview(assessment.coverage).length;
  return routed > 0 ? `${text}\n\n${t.sourceReviewHint(routed, commandFor('check . --for-ai'))}` : text;
}

/**
 * Report of a pre-deployment check on source code. Whoever ran it holds the
 * code, so no further proof is asked for. Only repo-layer assessments render here.
 */
export function renderLocalReport(assessment: Assessment): string {
  if (assessment.target.layer !== 'repo') throw new Error('Local report is for source-code checks only');
  const text = renderDetails(assessment, localHeader, t.checksLocal, t.needsValidationHeadingLocal);
  const hasProblems = assessment.records.some((r) => r.verdict === 'confirmed');
  return hasProblems ? `${text}\n\n${t.fixRequestHint}` : text;
}

function localHeader(s: OwnerSummary): string[] {
  return [
    t.localTitle,
    `${t.folder}: ${cleanText(s.host, 120)}`,
    `${t.scannedAt}: ${JST.format(new Date(s.scannedAt))}（日本時間）`,
    `${t.grade}: ${s.grade}（${gradeLabel[s.grade]}）`,
    `${t.counts}: ${countsText(s, SEVERITIES)}`,
    `${t.needsValidationCount}: ${s.needsValidation} ${t.countUnit}`,
    t.coverageLine(s.coverage.total, s.coverage.checked, s.coverage.partial),
  ];
}

function renderDetails(
  assessment: Assessment,
  header: (s: OwnerSummary) => string[],
  checksLine: string,
  needsValidationHeading: string,
): string {
  const summary: OwnerSummary = {
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

  const lines = [...header(summary), ...incompleteLine(summary), checksLine, '', t.findingsHeading];
  if (confirmed.length === 0) lines.push(t.noFindings, '');
  else confirmed.forEach((r, i) => lines.push(...renderConfirmed(r, i + 1), ''));

  if (needsValidation.length > 0) {
    lines.push(needsValidationHeading);
    needsValidation.forEach((r, i) => lines.push(...renderNeedsValidation(r, i + 1), ''));
  }

  lines.push(t.coverageHeading, ...assessment.coverage.map(renderCoverage), '');
  lines.push(t.disclaimer, `${t.rulesVersion}: v${assessment.rulesVersion}`);
  return lines.join('\n');
}
