# qa-jp-ai-scanner

The QA.JP.AI scanner for AI-generated web apps.

This repository is the home for every layer of the scanner. What exists today
is the URL layer. The repository layer (deep review of source code) and the
public benchmark will be added here as they are built.

## URL layer

Anyone can run a passive check on a URL and get a grade and counts. What the
problems are, where they are, and how to fix them is shown only to someone who
has proved they own the site.

Code and identifiers are English. Everything a user reads is Japanese
(`src/i18n/ja.ts`).

## Design rules

| Rule | How the code enforces it |
|---|---|
| Unverified requesters get counts only | `toPublicSummary()` drops findings; `renderOwnerReport()` throws unless the scan ran with a valid proof |
| Unverified scans are passive | Only the page and the same-site scripts it references are fetched. Active probes (R11) run only when `scan()` receives an `OwnershipProof` |
| Detect, never exploit | A detected key is never sent anywhere. Evidence keeps a 6-character prefix and a length. File probes keep a boolean and a count, not contents |
| The scanner cannot be aimed at internal networks | `src/net/guard.ts` blocks loopback, private, link-local and metadata addresses at connect time (covers DNS rebinding), plus non-standard ports |
| Details are unlocked by ownership, not by contact details | The only way to obtain an `OwnershipProof` is one of the three verification methods |

## Ownership verification

| Method | For whom | Module |
|---|---|---|
| A. Mailbox on the site's own domain | Businesses with a domain mailbox | `ownership/email.ts` |
| B. Verification file placed by the owner's AI coding tool | Sites on platform subdomains; owners who use free mail | `ownership/file.ts` |
| C. DNS TXT record | People comfortable with DNS | `ownership/dns.ts` |

Method A refuses free and carrier mail, refuses hosting-platform subdomains,
and accepts only admin mailboxes (`admin@`, `administrator@`, `webmaster@`,
`hostmaster@`, `postmaster@`) on large shared domains such as `ac.jp` and `go.jp`.

## Rules implemented (v0.1.0)

| ID | What | Severity | Tier |
|---|---|---|---|
| R02 | Privileged keys shipped to the browser (Supabase service_role / secret, OpenAI, Anthropic, Stripe, AWS, GitHub, Slack, SendGrid, private keys) | P0 (Stripe test key, AWS key ID: P1) | public |
| R14 | HTTPS, HSTS, CSP, nosniff, clickjacking protection, cookie attributes | No HTTPS: P1. Others: P2 | public |
| R11 | Exposed `.env`, `.git`, source maps | `.env`: P0. `.git`: P1. Source maps: P2 | owner |

P0 = any one fails the check. P1 = serious. P2 = should improve.

Keys that are public by design are not findings: Supabase anon / publishable
keys, Firebase web API keys, Stripe publishable keys.

## Use

```sh
npm install
npm test
npm run typecheck

# Public summary
npm run scan -- https://example.jp

# Show the ownership token, the prompt to paste into an AI coding tool, and the DNS record
QA_JP_AI_SECRET=... npm run scan -- token https://example.jp --account acct-1

# Verify, then show the detailed report
QA_JP_AI_SECRET=... npm run scan -- https://example.jp --account acct-1 --verify file
```

Only check sites you own or have permission to check.

## Known limits

- Script discovery reads the HTML only. Chunks loaded later at runtime are not seen.
- Method A decides eligibility and issues the proof; sending the login link is the service layer's job and is not built yet.
- No web UI, rate limiting or audit log yet. These are required before any public deployment.
- A grade of A means nothing was found in the checks that ran. It does not mean the site is safe.

## Acknowledgements

This project builds on the published work of others and says so.

- **[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)**
  (MIT, Copyright (c) 2025-2026 Cloudflare, Inc.) — the reference for the planned
  repository layer: three distinct verdicts, verification by an agent that did not
  make the finding, a coverage ledger, and machine-validated records. The URL layer
  in this repository contains no code from it yet. When its files are incorporated,
  they will be kept in a separate directory together with its original license.
- **CodeRabbit** — its public descriptions of a sandboxed, evidence-filtered review
  pipeline informed the design.

Improvements made here that are useful upstream will be offered back.

## License

Copyright (C) 2026 iQi

AGPL-3.0-or-later. See `LICENSE`.

Anyone may use, study, change and redistribute this checker. If you run a
modified version as a network service, you must offer the source of that
version to the people who use the service.

## Contact

Questions and security reports: qa@email.jp.ai
