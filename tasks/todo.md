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

### Next
- [ ] Push to GitHub under AgenticAIJP (GitHub is not connected to this session yet)
- [ ] Web UI (Japanese) and login-link mail for method A
- [ ] Rate limiting per source and per domain; audit log; terms of use
- [ ] Legal review of the verification flow and terms before any public deployment
- [ ] R01 / R04 "existence-only" checks — define the detect/exploit boundary per rule first
- [ ] Discover runtime-loaded chunks (build manifests) for R02

## Review (2026-11-12)

- 23 tests pass; `tsc --noEmit` clean.
- Verified by test, not by inspection:
  - the public tier requests only the page and its same-site scripts (request log asserted);
  - public output contains no category, location, key prefix or service name;
  - full keys, `.env` values and source-map contents never appear in results or reports;
  - the guarded fetcher refuses loopback, metadata, non-standard ports and a hostname resolving to loopback, each with `QA_BLOCKED_ADDRESS` (not a connection error);
  - a proof for another site or an expired proof is rejected and triggers no active probe;
  - an SPA answering every path with `index.html` passes neither file verification nor R11.
- Not verified: behaviour against real deployed sites. No third-party site was scanned.
