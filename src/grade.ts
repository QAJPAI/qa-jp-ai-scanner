// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Finding, Grade, SeverityCounts } from './types';

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { P0: 0, P1: 0, P2: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** Any P0 fails outright; the grade never means "safe", only "nothing found". */
export function gradeFor(counts: SeverityCounts): Grade {
  if (counts.P0 > 0) return 'E';
  if (counts.P1 > 0) return 'D';
  if (counts.P2 >= 4) return 'C';
  if (counts.P2 >= 1) return 'B';
  return 'A';
}
