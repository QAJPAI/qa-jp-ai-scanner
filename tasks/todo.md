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

### Next
- [ ] Push to GitHub under AgenticAIJP (GitHub is not connected to this session yet)
- [ ] Entrance B, first step: local pre-deployment checks on source code (R01 access rules in migrations and rule files, R02 keys in source), using the same core
- [ ] Web UI (Japanese) and login-link mail for method A
- [ ] Rate limiting per source and per domain; audit log; terms of use
- [ ] Legal review of the verification flow and terms before any public deployment
- [ ] R04 "existence-only" check — define the detect/exploit boundary first
- [ ] Discover runtime-loaded chunks (build manifests) for R02

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
