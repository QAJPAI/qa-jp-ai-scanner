// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from '../src/core/assessment';
import type { NotRunReason } from '../src/core/coverage';
import type { RuleId } from '../src/core/types';
import { WELL_KNOWN_PATH } from '../src/ownership/file';
import { mintVerificationToken } from '../src/ownership/token';
import { fake, html, startFixture, type Fixture, type Route } from './fixture';

/**
 * The case site: the ruler the free check is measured with.
 *
 * A small matching service for students, built quickly with an AI coding
 * tool, as it looks from outside. It has the six problems of the case
 * QA.JP.AI was started from. Each is a real mistake of this kind of site, and
 * each belongs to one rule.
 *
 * `vulnerable` has all six. `fixed` is the same site after a correct fix of
 * every one. A check is good when it reports the six on the first and none of
 * them on the second. The scoreboard (scoreCaseSite) says how far the check
 * is from that today; test/case-site.test.ts pins it, so the score can only
 * change on purpose.
 */

export type CaseVariant = 'vulnerable' | 'fixed';

export interface CaseProblem {
  id: 1 | 2 | 3 | 4 | 5 | 6;
  /** What is wrong, in one line. */
  summary: string;
  /** Rules a confirmed record for this problem would come under. */
  rules: readonly RuleId[];
  /** Rules whose owner question points at this problem without confirming it. */
  related: readonly RuleId[];
}

export const CASE_PROBLEMS: readonly CaseProblem[] = [
  { id: 1, summary: 'Every user\'s profile is returned by an API that asks for no login', rules: ['R04'], related: [] },
  { id: 2, summary: 'Identity documents are stored in a public storage bucket', rules: ['R06'], related: [] },
  { id: 3, summary: 'A user can mark their own account as verified', rules: ['R05', 'R03'], related: ['R01'] },
  { id: 4, summary: 'The database admin key is in the front-end code', rules: ['R02'], related: [] },
  { id: 5, summary: 'The student-only rule is enforced in the browser only', rules: ['R09'], related: [] },
  { id: 6, summary: 'The AI feature has no rate limit or spend cap', rules: ['R07'], related: [] },
];

/** A fixed token: the case site is only ever served from the local machine. */
export const CASE_TOKEN = mintVerificationToken('case-site-secret-0123456789', 'case-site', '127.0.0.1');

const SUPABASE_URL = 'https://abcdefghijklmnopqrst.supabase.co';

const VULNERABLE_APP = `
const SUPABASE_URL = "${SUPABASE_URL}";
const supabase = createClient(SUPABASE_URL, "${fake.supabaseJwt('anon')}");
const admin = createClient(SUPABASE_URL, "${fake.supabaseJwt('service_role')}");
async function listUsers() { return (await fetch("/api/users")).json(); }
const idImage = (userId) => SUPABASE_URL + "/storage/v1/object/public/id-cards/" + userId + ".jpg";
async function verifyMe(me) { await supabase.from("profiles").update({ verified: true, role: "member" }).eq("id", me.id); }
function canRegister(email) { return /@[a-z0-9.-]+\\.ac\\.jp$/.test(email); }
async function ask(prompt) { return fetch("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) }); }
`;

/**
 * After the fix: the admin key is gone from the browser, user data and
 * identity documents need a login, verification and the student-only rule are
 * decided by the server, and the AI endpoint is capped. The public key stays:
 * it is public by design.
 */
const FIXED_APP = `
const SUPABASE_URL = "${SUPABASE_URL}";
const supabase = createClient(SUPABASE_URL, "${fake.supabaseJwt('anon')}");
const authed = async (path, init = {}) => fetch(path, { ...init, headers: { authorization: "Bearer " + (await supabase.auth.getSession()).data.session.access_token } });
async function listMatches() { return (await authed("/api/matches")).json(); }
async function idImage() { return (await authed("/api/me/id-card-url")).json(); }
async function requestVerification(file) { return authed("/api/me/verification", { method: "POST", body: file }); }
async function register(email, password) { return fetch("/api/register", { method: "POST", body: JSON.stringify({ email, password }) }); }
async function ask(prompt) { return authed("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) }); }
`;

const json = (status: number, value: unknown): Route => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(value),
});

const USERS = [{ id: 1, name: '山田 太郎', email: 'taro@example.ac.jp', phone: '090-0000-0000', verified: true }];

export function caseSiteRoutes(variant: CaseVariant): Record<string, Route> {
  const vulnerable = variant === 'vulnerable';
  return {
    '/': { headers: { 'content-type': 'text/html' }, body: html(['/assets/app.js']) },
    '/assets/app.js': {
      headers: { 'content-type': 'application/javascript' },
      body: vulnerable ? VULNERABLE_APP : FIXED_APP,
    },
    '/api/users': vulnerable ? json(200, USERS) : json(401, { error: 'login required' }),
    '/api/matches': json(401, { error: 'login required' }),
    [WELL_KNOWN_PATH]: { body: CASE_TOKEN },
  };
}

export const startCaseSite = (variant: CaseVariant): Promise<Fixture> => startFixture(caseSiteRoutes(variant));

/**
 * How one problem of the case fares in a result.
 *
 *  confirmed     the check reported it as a problem
 *  question      the check asked the owner about something that points at it
 *  clear         the rule was examined and nothing was reported
 *  not_examined  the rule was not examined at all
 */
export type CaseStatus = 'confirmed' | 'question' | 'clear' | 'not_examined';

export interface CaseScore {
  problem: CaseProblem;
  status: CaseStatus;
  /** Why the rule was not examined, when it was not. */
  reason?: NotRunReason;
}

export function scoreCaseSite(assessment: Assessment): CaseScore[] {
  return CASE_PROBLEMS.map((problem) => {
    const under = (rules: readonly RuleId[], verdict: string) =>
      assessment.records.some((r) => r.verdict === verdict && rules.includes(r.ruleId));
    if (under(problem.rules, 'confirmed')) return { problem, status: 'confirmed' };
    if (under([...problem.rules, ...problem.related], 'needs_validation')) return { problem, status: 'question' };

    const units = assessment.coverage.filter((u) => problem.rules.includes(u.ruleId));
    const examined = units.some((u) => u.status === 'checked' || u.status === 'partial');
    if (examined) return { problem, status: 'clear' };
    const reason = units.find((u) => u.reason)?.reason;
    return { problem, status: 'not_examined', ...(reason ? { reason } : {}) };
  });
}
