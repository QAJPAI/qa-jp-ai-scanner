// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Layer, RuleId, Severity } from './types';

/**
 * The rule registry: the single machine-readable statement of what QA.JP.AI
 * checks. Display text lives in src/i18n. Checkers implement rules; they do not
 * define them.
 */
export interface RuleDef {
  id: RuleId;
  /** The most severe grade a confirmed record under this rule may carry. */
  maxSeverity: Severity;
  /** Layers able to produce evidence for this rule. */
  layers: readonly Layer[];
}

const def = (id: RuleId, maxSeverity: Severity, ...layers: Layer[]): RuleDef => ({ id, maxSeverity, layers });

export const RULES: Readonly<Record<RuleId, RuleDef>> = {
  R01: def('R01', 'P0', 'repo', 'url'), // database access rules not in effect
  R02: def('R02', 'P0', 'url', 'repo'), // privileged keys in front-end code
  R03: def('R03', 'P0', 'repo', 'url'), // auth enforced only in the front end
  R04: def('R04', 'P0', 'url', 'repo'), // user data reachable without login
  R05: def('R05', 'P0', 'repo'), // users can rewrite their own role or status
  R06: def('R06', 'P0', 'repo', 'url'), // sensitive files in public storage
  R07: def('R07', 'P1', 'repo'), // no rate limit or spend cap
  R08: def('R08', 'P1', 'repo'), // injection
  R09: def('R09', 'P1', 'repo'), // stated restriction not enforced server-side
  R10: def('R10', 'P1', 'repo'), // dependency risk
  R11: def('R11', 'P0', 'url'), // internal files and debug info exposed
  R12: def('R12', 'P1', 'repo'), // input drives an LLM to act beyond authority
  R13: def('R13', 'P1', 'repo'), // agent over-privileged, no stop channel
  R14: def('R14', 'P1', 'url'), // transport and response headers
  R15: def('R15', 'P2', 'repo'), // logging
};

const RANK: Record<Severity, number> = { P0: 0, P1: 1, P2: 2 };

/** True when `severity` is more severe than the rule allows. */
export function exceedsRuleSeverity(ruleId: RuleId, severity: Severity): boolean {
  return RANK[severity] < RANK[RULES[ruleId].maxSeverity];
}
