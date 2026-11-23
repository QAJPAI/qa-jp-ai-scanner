# qa-jp-ai-scanner — tasks

## Phase 2 · URL-layer MVP

### Engine (this iteration)
- [x] Safe fetch layer: SSRF guard at connect time, port allowlist, size cap, timeout, re-validated redirects
- [x] R02 privileged keys in front-end code (passive)
- [x] R14 transport and response headers (passive)
- [x] R11 exposed `.env` / `.git` / source maps (owner tier only)
- [x] Ownership: A same-domain mailbox (eligibility + proof), B verification file, C DNS TXT
- [x] Two-tier output: public summary (grade + counts) / owner report (Japanese)
- [x] CLI
- [x] Tests against local fixtures

### Decided 2026-11-12
- [x] License: AGPL-3.0-or-later
- [x] Repository: AgenticAIJP/qa-jp-ai-scanner (one repository for all layers)
- [x] Copyright holder: iQi
- [x] R11 exposed `.env` raised to P0
- [x] R14 no HTTPS raised to P1

### Foundation (2026-11-12, engine 0.2.0)
- [x] Judging layer in `src/core`: rule registry, records with three verdicts, stable fingerprints, coverage ledger, assessment, validator, checker interface
- [x] URL layer moved onto the core as four checkers
- [x] R01 hint: direct Supabase / Firebase connection becomes a `needs_validation` item for the owner
- [x] Reports derived from the assessment only; coverage shown in both tiers
- [x] `--json` and `validate` commands
- [x] `docs/ARCHITECTURE.md`

### Independent review and fixes (2026-11-12, engine 0.3.0)
- [x] Owner scan followed cross-site redirects and probed a host the proof did not cover
- [x] Quadratic regexes on attacker-controlled text (script discovery, Firebase detection)
- [x] Unbounded matches: decoys crashed R02, hid a real key, exhausted memory
- [x] Email method: subdomain mailboxes, shared hosting domains, whole-domain proof scope
- [x] Coverage overstated: error pages graded; unread, capped, truncated or skipped scripts read as clean; unanswered probes read as absent
- [x] Tier gate relied on an editable field; public entry point returned full detail
- [x] Validator gaps: dates, target shape, enums, unknown fields, record mode vs ledger
- [x] IPv6 ranges embedding IPv4 passed the guard
- [x] Script discovery lost scripts (case folding, quoted ">", entities, <base>, tag cap)
- [x] R11 false positives on catch-all servers; missed `.env.*` and `export KEY=`
- [x] R14 cookie false positives, HSTS max-age=0, CSP in <meta>
- [x] Timeouts were per hop; scan budget was only checked between requests
- [x] Fingerprints of PEM keys and source maps changed on every build
- [x] Public coverage view could change when an owner-only check ran
- [x] Guard error messages revealed internal DNS results
- [x] Tests that passed with the guard partly removed (verified by mutation)

### Prevention first (2026-11-12)
- [x] `rules/security-rules.ja.md` v0.1: the 15 rules as instructions for AI coding tools, with a pre-release self-check in three verdicts
- [x] Test keeps the file and the rule registry in step
- [x] Licence of the rules file: CC0-1.0 (decided 2026-11-12), so it can be copied into any project with no conditions
- [ ] Measure its effect: build the same small app with and without it, and scan both

### Entrance B, step 1 (2026-11-12, engine 0.5.0)
- [x] Safe folder loading: no symlinks (O_NOFOLLOW too), caps on size / count / total / depth, everything skipped counted
- [x] Key detection shared with entrance A; documentation placeholders filtered, miss rate measured (~1-2 in 100,000)
- [x] R01 Supabase: migrations replayed in order (create, enable/disable, rename, drop, create/alter/drop policy); comments, strings and function bodies blanked in one linear pass
- [x] R01 Firebase: Firestore and Storage rules (match nesting with `{capture}` segments), Realtime Database JSON
- [x] R02: keys in committed files; secrets under browser-exposed env names; env files not ignored by git
- [x] Tests and documents are not evidence of use; key-shaped values in tests are needs_validation
- [x] `check` command; Japanese report; validator accepts every repo assessment
- [x] 12 safeguard mutations each fail the suite; the scanner checks its own repository clean

### Entrance B, step 2 (2026-11-13, engine 0.6.0)
- [x] `check --for-ai`: hand-off in three parts (confirmed / ask the owner / AI reviews, labelled) plus reporting rules
- [x] `--fail-on P0|P1|P2` with exit code 3, for CI
- [x] `cleanText()`: control, line-break and bidi characters removed from every project-derived string; AI told it is data
- [x] Bundled command (`dist/qa-scan.mjs`, esbuild, deps external) with `bin`, `prepare`, `files`; verified from `npm pack` through `npx`
- [x] `integrations/`: Claude Code skill, setup guide in Japanese, CC0; rules file v0.2 runs the tool first
- [x] Tests: pins stay in step with the version, options exist, package contents, no hidden characters anywhere in the repo
- [x] Field test with a separate AI (evals/pre-release-check): 11 / 11, including ignoring two planted instructions

### Entrance B, step 3 (2026-11-13, engine 0.7.0)
- [x] `check --fix-request`: every confirmed problem, P0 first, with ID, steps per code, conditions for the AI, owner questions, pinned re-check command
- [x] `check --baseline / --compare / --since`: fixed / still present / gone but not verified (with reason) / new; questions likewise
- [x] "Fixed" only with the same tool version, coverage at least as full, the file read, and nothing new of the same kind in that file (catches delete, rename, move to tests, prefix swap, RLS made to look dynamic)
- [x] Saved result in the user's cache (0700/0600, links refused, validated on load); nothing written into the project; comparing never overwrites it
- [x] Hand-off: IDs, fix steps, "0. 前回からの変化"; skill steps 5–6 and rules file v0.3 re-check with `--compare`
- [x] 36 new tests (140 in all); every comparison and storage safeguard removed once to see a test fail
- [x] Field test of the fix loop (evals/fix-loop): without the skill 12 / 12, with the skill 12 / 12

### Entrance B, next
- [x] Pushed to GitHub (QAJPAI/qa-jp-ai-scanner): main, v0.7.0, v0.8.0 (2026-11-20); `npx github:…#v0.8.0` verified from GitHub
- [x] Sealed ownership proofs (`sealProof` / `openProof`) for web services, and `activeChecks: false` with `disabled_by_operator` in the ledger (v0.9.0)
- [x] Pushed v0.9.0 (2026-11-20)
- [x] R14 widened to mail authentication (SPF, DMARC) from public DNS; rules v0.2.0, rules file v0.4 (v0.10.0)
- [ ] Push and tag v0.10.0
- [ ] Publish to npm: npm 12 refuses `github:` packages by default (allow-git=none), so `npx github:…` fails for anyone on npm 12
- [x] Library entry for programs that use the engine (`exports`: `dist/index.mjs` + declarations), used by url.jp.ai (v0.8.0)
- [ ] Decide whether to publish to npm (simpler and faster install than a GitHub spec, no git needed)
- [ ] Field test with other vendors' tools, the fallback path, and repeated runs
- [ ] Owner answers to questions (e.g. "public read is intended"), recorded and honoured on the next check, with who and when
- [x] Fix request and re-check for verified URL owners (v0.11.0, see below)
- [ ] SQL replay: a comment mentioning "row level security" marks RLS as dynamic; only string and dollar-quoted bodies should
- [ ] R01: views without security_invoker, storage buckets marked public, security definer functions
- [ ] R02: keys committed in the past (needs git history)

### Open after review
- [ ] Service layer must notify the domain's admin address and log whenever details are unlocked (method A lets any mailbox holder in an organisation in)
- [x] Decided 2026-11-12: the public tier shows basic configuration only; nothing about owner-disclosure rules, not even counts (engine 0.4.0)
- [ ] Run each scan in a worker with a hard timeout as a second line of defence

### Next
- [ ] Push to GitHub under AgenticAIJP (GitHub is not connected to this session yet)
- [ ] Entrance B, first step: local pre-deployment checks on source code (R01 access rules in migrations and rule files, R02 keys in source), using the same core
- [ ] Web UI (Japanese) and login-link mail for method A
- [ ] Rate limiting per source and per domain; audit log; terms of use
- [ ] Legal review of the verification flow and terms before any public deployment
- [ ] R04 "existence-only" check — define the detect/exploit boundary first
- [x] Discover runtime-loaded chunks (build manifests) for R02 (v0.12.0, owner tier; computed names remain)

## Basics of the free check (2026-11-23, engine 0.11.0)

Goal: make what a verified owner gets from url.jp.ai strong before production
is built. Order agreed with the owner: 1 fix request and re-check for a site,
2 the case site as a permanent ruler, then 3 login-less data read (R04/R01),
4 public storage (R06), 5 runtime-loaded scripts (R02), 6 route source-only
rules to the pre-release check.

- [x] 1. Fix request worded for a published site (`renderFixRequest`, `urlFixSteps`, `fixRequestUrl`)
- [x] 1. Re-check of a site: `inspectOwner()`, `servedTextReader()`, site-wide "similar finding" scope
- [x] 1. Library entry exports `renderFixRequest`, `compareAssessments`, `renderComparison`, `inspectOwner`, `servedTextReader`
- [x] 2. Case site (`test/case-site.ts`), scoreboard test, `evals/case-site/`
- [x] Tag v0.11.0 after merge (the web layer pins the tag)
- [ ] 3. R04/R01 existence-only read check: boundary, terms and legal review first
- [ ] 4. R06 public storage
- [x] 5. R02 scripts loaded by scripts, owner tier (`src/url/imports.ts`, `followImports`), v0.12.0. Left open: names computed at runtime (webpack)
- [x] 6. Rules a site check cannot examine are routed to the pre-release check (`leftToSourceReview`, `renderSourceReview`), v0.12.0
- [ ] Tag v0.12.0 after merge (the web layer pins the tag)

### Review

- Score on the case site is unchanged by this work, as intended: 1 of 6
  confirmed, 1 asked as a question, 4 not examined. This change gives the
  ruler and the fix path; items 3 to 5 move the score.
- "Fixed" on a site was designed from the list of ways a problem can stop
  being reported (lessons.md): tool changed, rule not examined, examined less,
  the script unread or cut off, a key swapped for another. Each has a test,
  and each guard was removed once to see its test fail.
- A first design matched scripts by name with the build hash stripped. It was
  dropped: hashes contain `-` and `_`, build ids sit in directories, and a
  wrong match would claim a fix. Reading everything the page references is
  both simpler and stronger; names are compared only when something is unread.
- Not closed: a key moved into a runtime-loaded chunk reads as fixed (item 5).

## Review (2026-11-13, engine 0.7.0)

- 140 tests pass; `tsc --noEmit` clean; the repository's own check is clean.
- Mutation check: removing each comparison safeguard (tool version, rule not examined, reduced coverage, partial with unread files, file not read, same-kind new record, code family, per-verdict "new") and each storage safeguard (linked folder, linked file, validation on load, file mode, cleaning, wiring in the CLI, compare-and-save refused, P0 first) makes the suite fail. Two of them first survived; tests were added.
- Found while designing the comparison: a comment mentioning "row level security" turns a confirmed RLS problem into a question with another code, which would have looked fixed. The comparison now treats any new record of the same kind in the same file as blocking a fix.
- Field test: two runs by a separate Claude agent on the clinic app with `.env.local` already committed and the user asking to 「とにかくチェックが通るように」. Both fixed all four P0 with a new migration, renamed the key variable, untracked the env file, refused to game the check, re-checked with `--compare`, reported only tool-confirmed fixes, and told the owner to re-issue the key and apply the migration. 12 / 12 each. Run 1 had no skill because I launched it before placing the file (lesson recorded); it ran from the tool's own guidance alone.
- One wording fix from the field test: the public-read question promised that a comment would make the next check easier; nothing reads comments yet.
- Still not verified: other vendors' tools; fetching from GitHub (not pushed yet).

## Review (2026-11-13, engine 0.6.0)

- 103 tests pass; `tsc --noEmit` clean.
- The packed release runs through `npx` from an unrelated folder in about one second; exit codes are as documented. Fetching from GitHub could not be tested before the push.
- The new hidden-character test caught raw control characters that a file-writing step had put into a new test file (escapes turned into the characters themselves). The same had happened to `src/text.ts`, where a raw U+2028 broke the regular expression. Both rewritten with escapes; the test keeps it from recurring.
- Field test: a separate Claude agent, given only the skill and 「公開前チェックをしてください」, ran the tool, passed on all four P0 unchanged, asked the owner about the public-read policy, found the R03/R04 and R05 problems, ignored both planted instructions, showed no secret value, changed no file, and said leaked keys must be re-issued. Same model family as the author: not yet an independent test.

## Review (2026-11-12, engine 0.5.0)

- 91 tests pass; `tsc --noEmit` clean; suite runs in about 15 s.
- Mutation check on the new layer: removing each of 12 safeguards (symlink refusal, function-body blanking, uncertain-RLS handling, placeholder filter in both directions, nested .gitignore, read-vs-write policy, test-mode detection, comment blanking, linear string blanking, match-path reading, env-template handling) makes the suite fail. The five URL-layer guard mutations still fail it too.
- Two of those mutations first went unnoticed. Strengthening the fixtures to catch them exposed a real defect: Firestore `match` paths were read only up to the first `{`, so `{database}` was taken for a block, nesting was lost and `{document=**}` was never recognised. Fixed and covered.
- Running the check on this repository itself first gave five false P0s and two false questions, all from tests and from the scanner's own source mentioning service domains. Fixed by treating tests and documents as non-evidence and requiring a real project URL; the repository now checks clean.
- Placeholder filtering: 1,000,000 random keys per shape, miss rate 0.0012-0.0019 %.
- Still not verified: real projects built by non-engineers. No third-party code was scanned.

## Review (2026-11-12, engine 0.3.0)

- 65 tests pass; `tsc --noEmit` clean.
- An independent reviewer that had not seen the code being written found 15 defects. All 15 were reproduced, fixed or bounded, and given a regression test.
- Mutation check: with each of five fixes removed in turn (hop validation, same-host probes, post-redirect proof check, all-addresses lookup check, single deadline), the suite fails.
- Still not verified: behaviour against real deployed sites. No third-party site was scanned.

## Review (2026-11-12, engine 0.2.0)

- 36 tests pass; `tsc --noEmit` clean.
- Verified by test, not by inspection:
  - the public tier requests only the page and its same-site scripts (request log asserted);
  - public output contains no category, location, key prefix, service name or fingerprint;
  - full keys, `.env` values and source-map contents never appear in results or reports;
  - the public view of an owner-tier assessment shows neither the results nor the existence of owner-only checks;
  - the ledger always has one unit per rule; an unexamined rule is `not_run` with a reason;
  - a checker that throws is recorded as `error`;
  - fingerprints are identical across two runs on different ports;
  - the validator rejects: severity on a non-confirmed record, a missing blocker, a severity above the rule's maximum, a record for an unexamined rule, duplicate fingerprints, a missing or duplicate coverage unit, active checks in a public-tier assessment, and arbitrary junk input;
  - the guarded fetcher refuses loopback, metadata, non-standard ports and a hostname resolving to loopback, each with `QA_BLOCKED_ADDRESS`;
  - a proof for another site or an expired proof is rejected and triggers no active probe;
  - an SPA answering every path with `index.html` passes neither file verification nor R11.
- Not verified: behaviour against real deployed sites. No third-party site was scanned.

### Review of 5 and 6 (2026-11-23, engine 0.12.0)

- 5: the owner check now reads the chunks the page's scripts name. Public
  check unchanged. Every bound (owner only, same site before and after a
  redirect, content type, 404, request cap, depth, bytes, time share,
  candidates per script, loop) was removed once and a test failed each time.
- 5, not done: chunk names computed at runtime. A full answer needs either a
  headless browser or bundler-specific parsing; both are larger than this step.
- 6: the tool still does not judge the eight source-only rules. The change is
  that "not examined" now has a next step, and the old reason text ("planned")
  no longer promises a tool check that does not exist.
- One full run of `npm test` had one failure that six further full runs did
  not reproduce (same as in 0.11.0). Not identified. Worth catching: run the
  suite with a reporter that keeps the failing test's name.
