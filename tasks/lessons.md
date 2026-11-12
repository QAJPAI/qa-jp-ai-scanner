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
