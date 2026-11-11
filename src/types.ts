// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
export const RULES_VERSION = '0.1.0';

export type Severity = 'P0' | 'P1' | 'P2';

/** 'public' = anyone, passive checks only. 'owner' = ownership verified. */
export type Tier = 'public' | 'owner';

export type RuleId = 'R02' | 'R11' | 'R14';

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  /** Stable machine code; display text lives in src/i18n/ja.ts. */
  code: string;
  /** Where it was found (URL, header name, cookie name). Owner tier only. */
  location: string;
  /** Redacted evidence. Must never contain a full secret or any fetched data. */
  evidence: string;
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'E';

export interface SeverityCounts {
  P0: number;
  P1: number;
  P2: number;
}

export interface ScanResult {
  host: string;
  scannedAt: string;
  rulesVersion: string;
  tier: Tier;
  checksRun: RuleId[];
  grade: Grade;
  counts: SeverityCounts;
  /** Full findings. Only ever rendered through renderOwnerReport(). */
  findings: Finding[];
}

/** What an unverified requester is allowed to see. */
export interface PublicSummary {
  host: string;
  scannedAt: string;
  rulesVersion: string;
  checksRun: RuleId[];
  grade: Grade;
  counts: SeverityCounts;
}
