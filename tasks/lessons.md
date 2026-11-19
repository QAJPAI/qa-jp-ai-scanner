# Lessons

Rules written after mistakes, so the same mistake is not made twice.

## Run the self-check before every commit

2026-11-13: committed step 2 while `qa-scan check .` on this repository showed a
P0 — the new `evals/` folder of deliberately bad examples was not treated as
test material. The number was on screen and was not read before committing.

- Rule: a commit is ready only when `npx tsx src/cli.ts check .` shows nothing.
- Guard: `test/integrations.test.ts` now fails if the repository's own check is
  not clean.

## A safeguard without a failing test is not verified

2026-11-12: two safeguards (function-body blanking in SQL, comment blanking in
Firebase rules) could be removed without any test failing. Strengthening the
fixtures exposed a real defect (Firestore match paths read only up to the first
`{`).

- Rule: for every new safeguard, remove it once and see a test fail.

## Escapes written to files can arrive as raw characters

2026-11-13: `\u2028` in a regular expression and `\u001b` / `\u202e` in a
test arrived in files as the raw characters. The first broke the parser; the
second would have hidden characters in the repository.

- Rule: build hidden or control characters at runtime, or write escapes from a
  script that verifies the bytes.
- Guard: `test/integrations.test.ts` fails if any file contains such characters.

## A check that reports on its own repository must be run on it

2026-11-12: the first self-check produced five false P0 from test files and from
the scanner's own source naming service domains.

- Rule: tests, fixtures, evals and documents are not evidence of use, and
  key-shaped values in them are questions, not leaks.

## "It is gone" has more causes than "it was fixed"

2026-11-13: while writing the comparison, the first design missed one way a
problem disappears: a comment containing "row level security" makes the SQL
replay treat RLS as dynamic, which turns a confirmed problem into a question
with a different code — and the old record looked fixed.

- Rule: before deciding that something disappeared because it was fixed, list
  every way the check can stop reporting it: the file was not read, the rule was
  examined less, the tool changed, the item was renamed, or it was downgraded to
  a weaker verdict. Each needs its own test that fails if the guard is removed.

## Prepare every input before launching an agent

2026-11-13: the fix-loop field test was launched with a prompt naming
`/tmp/eval-fix/SKILL.md` before the file was copied there. The agent looked
for it before it was placed and worked without the skill, so the planned run
(with the skill) became a different one (tool guidance only). It had to be run
again.

- Rule: create and list every file an agent's prompt names, then launch it.

## A negative from a lookup is only as good as the resolver (2026-11-20)
- The sandbox resolver answered "no data" to every TXT question, so github.com was told it had no DMARC. A filtered corporate resolver can do the same in production.
- Rule: before publishing "X is missing", run a positive control that a working source always passes (NS records for a live domain). If the control fails, record "could not check", never "missing".

## DMARC p=reject reaches subdomains (2026-11-20)
- I told the user to set `p=reject` on jp.ai because "jp.ai sends no mail". His main mailbox is on email.jp.ai; p=reject is inherited by subdomains (sp defaults to p), and his outgoing mail was rejected.
- Rule: before advising any DNS change that can stop mail, ask which domains AND subdomains send mail. Default to `p=none` first, or `sp=none` when subdomains are in use. Changes that can break someone's mail are not "a few minutes, done".
