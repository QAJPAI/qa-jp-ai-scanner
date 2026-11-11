// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { findingText, gradeLabel, report as t, severityLabel } from './i18n/ja';
import { countBySeverity, gradeFor } from './grade';
import type { Finding, PublicSummary, RuleId, ScanResult, Severity } from './types';

const SEVERITY_ORDER: Severity[] = ['P0', 'P1', 'P2'];

/** Rules that only read what the site serves to every visitor. */
const PASSIVE_RULES: RuleId[] = ['R02', 'R14'];

/**
 * Strip everything an unverified requester must not see. Counts and grade are
 * recomputed from passive rules only, so a summary derived from an owner-tier
 * scan never reveals the outcome of active checks.
 */
export function toPublicSummary(result: ScanResult): PublicSummary {
  const counts = countBySeverity(result.findings.filter((f) => PASSIVE_RULES.includes(f.ruleId)));
  return {
    host: result.host,
    scannedAt: result.scannedAt,
    rulesVersion: result.rulesVersion,
    checksRun: [...PASSIVE_RULES],
    grade: gradeFor(counts),
    counts,
  };
}

function countsLine(counts: PublicSummary['counts']): string {
  return SEVERITY_ORDER.map((s) => `${s}（${severityLabel[s]}）${counts[s]} ${t.countUnit}`).join(' / ');
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
  return [
    title,
    `${t.target}: ${s.host}`,
    `${t.scannedAt}: ${JST.format(new Date(s.scannedAt))}（日本時間）`,
    `${t.grade}: ${s.grade}（${gradeLabel[s.grade]}）`,
    `${t.counts}: ${countsLine(s.counts)}`,
  ];
}

export function renderPublicSummary(summary: PublicSummary): string {
  return [
    ...header(t.publicTitle, summary),
    `${t.checksPublic}（${summary.checksRun.join(', ')}）`,
    '',
    t.detailsGated,
    t.disclaimer,
    `${t.rulesVersion}: v${summary.rulesVersion}`,
  ].join('\n');
}

function renderFinding(f: Finding, index: number): string[] {
  const text = findingText[f.code];
  return [
    `${index}. [${f.severity}・${severityLabel[f.severity]}] ${text?.title ?? f.code}（${f.ruleId}）`,
    `   ${t.location}: ${f.location}`,
    `   ${t.evidence}: ${f.evidence}`,
    `   ${t.fix}: ${text?.fix ?? '-'}`,
  ];
}

/** Detailed report. Refuses to render a scan that was not owner-verified. */
export function renderOwnerReport(result: ScanResult): string {
  if (result.tier !== 'owner') {
    throw new Error('Detailed report requires a scan run with a valid ownership proof');
  }
  const sorted = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const lines = [
    ...header(t.ownerTitle, result),
    `${t.checksOwner}（${result.checksRun.join(', ')}）`,
    '',
  ];
  if (sorted.length === 0) {
    lines.push(t.noFindings);
  } else {
    sorted.forEach((f, i) => lines.push(...renderFinding(f, i + 1), ''));
  }
  lines.push(t.disclaimer, `${t.rulesVersion}: v${result.rulesVersion}`);
  return lines.join('\n');
}
