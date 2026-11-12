// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Version of the published rule set an assessment was made against. */
export const RULES_VERSION = '0.1.0';
export const ENGINE_VERSION = '0.5.0';
export const ASSESSMENT_SCHEMA = 'qa-jp-ai/assessment@1';

export type Severity = 'P0' | 'P1' | 'P2';
export const SEVERITIES: readonly Severity[] = ['P0', 'P1', 'P2'];

/** Where evidence comes from: a deployed site, or its source code. */
export type Layer = 'url' | 'repo';

/** 'public' = anyone. 'owner' = ownership verified. */
export type Tier = 'public' | 'owner';

/**
 * 'passive' = only what the target already hands to every visitor.
 * 'active'  = anything beyond that; allowed only for a verified owner.
 */
export type CheckMode = 'passive' | 'active';

export const RULE_IDS = [
  'R01', 'R02', 'R03', 'R04', 'R05', 'R06', 'R07', 'R08',
  'R09', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
] as const;
export type RuleId = (typeof RULE_IDS)[number];

export type Grade = 'A' | 'B' | 'C' | 'D' | 'E';
