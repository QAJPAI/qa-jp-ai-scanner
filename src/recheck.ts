// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { countBySeverity, type Assessment } from './core/assessment';
import type { Comparison } from './core/compare';
import type { ConfirmedRecord } from './core/records';
import { SEVERITIES } from './core/types';
import {
  afterFixNoteFor,
  comparison as c,
  findingTextFor,
  report as t,
  severityLabel,
  unverifiedReasonLabel,
} from './i18n/ja';
import { targetName } from './report';
import { cleanText } from './text';

/**
 * The re-check report for people (`qa-scan check --compare`). Built from the
 * comparison and the current assessment only. What remains is always the
 * current check's own count, never something carried over from the earlier one.
 */

const JST = new Intl.DateTimeFormat('ja-JP', {
  timeZone: 'Asia/Tokyo',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
});

const bySeverity = (a: ConfirmedRecord, b: ConfirmedRecord) =>
  SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);

function item(r: ConfirmedRecord, index: number): string[] {
  const text = findingTextFor(r.layer, r.code);
  return [
    `${index}. [${r.severity}・${severityLabel[r.severity]}] ${text?.title ?? r.code}（${r.ruleId}）`,
    `   ${t.location}: ${cleanText(r.location)}`,
  ];
}

function section(heading: string, records: ConfirmedRecord[], extra: (r: ConfirmedRecord) => string[] = () => []): string[] {
  const lines = [heading];
  if (records.length === 0) lines.push(c.none);
  [...records].sort(bySeverity).forEach((r, i) => lines.push(...item(r, i + 1), ...extra(r)));
  lines.push('');
  return lines;
}

export function renderComparison(cmp: Comparison, current: Assessment): string {
  const reasons = new Map(cmp.unverified.map((u) => [u.record.fingerprint, u.reason]));
  const remaining = countBySeverity(current.records.filter((r): r is ConfirmedRecord => r.verdict === 'confirmed'));

  const lines = [
    c.title,
    `${t.folder}: ${cleanText(targetName(current), 120)}`,
    `${c.previousAt}: ${JST.format(new Date(cmp.previousAt))} / ${c.currentAt}: ${JST.format(new Date(current.startedAt))}（日本時間）`,
    c.remaining(remaining.P0, remaining.P1, remaining.P2, cmp.unverified.length),
    '',
  ];
  if (cmp.toolChanged) lines.push(c.toolChanged, '');

  lines.push(
    ...section(c.fixedHeading(cmp.fixed.length), cmp.fixed, (r) => {
      const note = afterFixNoteFor(r.layer, r.code);
      return note ? [`   ${c.note}: ${note}`] : [];
    }),
    ...section(c.stillHeading(cmp.stillPresent.length), cmp.stillPresent),
    ...section(
      c.unverifiedHeading(cmp.unverified.length),
      cmp.unverified.map((u) => u.record),
      (r) => [`   ${c.reason}: ${unverifiedReasonLabel[reasons.get(r.fingerprint)!]}`],
    ),
    ...section(c.newHeading(cmp.newConfirmed.length), cmp.newConfirmed),
    c.questionsHeading,
    c.questionsLine(
      cmp.questionsResolved.length,
      cmp.questionsOpen.length,
      cmp.questionsNew.length,
      cmp.questionsUnverified.length,
    ),
    '',
    c.meaning,
    `${t.rulesVersion}: v${current.rulesVersion}`,
  );
  return lines.join('\n');
}
