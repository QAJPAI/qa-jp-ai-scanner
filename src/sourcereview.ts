// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from './core/assessment';
import { leftToSourceReview, type SourceReviewUnit } from './core/coverage';
import { handoff as h, report as t, ruleReviewFocus, ruleTitle, sourceReview as s } from './i18n/ja';
import { commandFor } from './invocation';
import { targetName } from './report';
import { cleanText } from './text';

/**
 * What a check of a published site leaves to the source code.
 *
 * Most of the rules cannot be answered from outside: whether the server
 * checks a limit that the screen shows, whether an AI feature has a spend
 * cap, what is written to the logs. A site check lists them as "not
 * examined". That is honest, and leaves the owner with nothing to do.
 *
 * This gives them the next step: one text to paste into their AI coding tool,
 * in the project of the site. It runs the pre-release check (the tool's own
 * judgement, where the tool can judge) and then asks the AI to review each of
 * these rules in the code, reported as the AI's judgement and never as the
 * tool's.
 *
 * It names rules only: no record, location or evidence of the site. It is
 * still for the verified owner, like everything else about one site's result.
 */

/** The rules of a site check that were not examined and can be reviewed in the source code. */
export const sourceReviewRules = (assessment: Assessment): SourceReviewUnit[] => leftToSourceReview(assessment.coverage);

/** The request text. Throws for a result that leaves nothing to the source code. */
export function renderSourceReview(assessment: Assessment): string {
  if (assessment.target.layer !== 'url') throw new Error('The source review request is for site checks only');
  const units = sourceReviewRules(assessment);
  if (units.length === 0) throw new Error('This result leaves no rule to a source review');

  const host = cleanText(targetName(assessment), 120);
  const lines: string[] = [
    `# ${s.title}`,
    '',
    s.intro(units.length),
    '',
    h.meta(host, assessment.engineVersion, assessment.rulesVersion),
    '',
    s.projectCheck(host),
    '',
    s.commandHeading,
    '',
    s.commandIntro,
    '',
    '```',
    commandFor('check . --for-ai'),
    '```',
    '',
    s.commandFallback,
    '',
    s.itemsHeading(units.length),
    '',
    s.itemsIntro,
    '',
  ];
  for (const unit of units) {
    lines.push(
      `- ${unit.ruleId} ${ruleTitle[unit.ruleId]}`,
      h.field(t.reason, s.reason[unit.reason]),
      h.field(h.focus, ruleReviewFocus[unit.ruleId]),
    );
  }
  lines.push('', s.rulesHeading, '', ...s.rules.map((rule, i) => `${i + 1}. ${rule}`), '');
  return lines.join('\n');
}
