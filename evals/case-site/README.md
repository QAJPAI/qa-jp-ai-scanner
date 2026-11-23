# The case site: how the free check is measured

One question decides whether the free check is strong: **if the site that
started this project were checked today, how many of its six problems would
its owner be told about?**

`test/case-site.ts` is that site, as it looks from outside: a small matching
service for students, built quickly with an AI coding tool. It comes in two
versions. `vulnerable` has the six problems. `fixed` is the same site after a
correct fix of each.

A good check reports the six on the first and none of them on the second.

## The six problems

| # | Problem | Rule |
|---|---|---|
| 1 | An API returns every user's profile without a login | R04 |
| 2 | Identity documents are stored in a public storage bucket | R06 |
| 3 | A user can mark their own account as verified | R05 (R03) |
| 4 | The database admin key is in the front-end code | R02 |
| 5 | The student-only rule is enforced in the browser only | R09 |
| 6 | The AI feature has no rate limit or spend cap | R07 |

## Score today (engine 0.11.0, rules 0.2.0)

Checked as the verified owner, so with every check the free service has.

| # | On the vulnerable site | Why |
|---|---|---|
| 1 | not examined | The URL layer can answer R04, but has no checker for it yet |
| 2 | not examined | The URL layer can answer R06, but has no checker for it yet |
| 3 | asked as a question | R05 needs the source code. The owner is asked to confirm the Supabase access rules (R01), which is where this problem lives |
| 4 | **confirmed, P0** | The key is in a script the page references |
| 5 | not examined | R09 needs the source code |
| 6 | not examined | R07 needs the source code |

**1 of 6 confirmed, 1 of 6 asked as a question, 4 of 6 not examined.**
Of the 15 rules, 4 are examined on a site (R14 and R11 in full, R02 and R01 in part).

On the fixed site: none of the six is reported as a problem. Problem 4 is
"examined, nothing found". The Supabase question stays, because the site still
talks to Supabase from the browser, and that is correct.

## Using it

```sh
npm test                           # the score above is pinned by test/case-site.test.ts
npx tsx evals/case-site/run.ts     # print what the owner sees: score, report, fix request, re-check
```

When a checker is added or changed, the score moves. Change the `TODAY` table
in `test/case-site.test.ts` and the table above in the same change, so that
the history of this file is the history of the free check getting stronger.
A line may move towards "confirmed" on the vulnerable site. It must not move
away from it, and the fixed site must never gain a confirmed problem.

## What the case site does not measure

It is one site. It says nothing about false alarms on ordinary sites, about
sites built on Firebase or without a hosted database, or about problems
outside these six. It is the first ruler, not the only one.
