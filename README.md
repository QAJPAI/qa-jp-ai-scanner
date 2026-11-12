# qa-jp-ai-scanner

The QA.JP.AI scanner for AI-generated web apps.

Many small businesses want their own site or tool, build it with AI, and cannot
tell whether it is safe to put online. This scanner is meant to tell them, for
free, before an attacker finds out first.

**QA.JP.AI owns the judging layer; inspectors are pluggable.** The rules, the
verdict contracts, the coverage ledger and the validator are public and the same
for every inspector. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

There are two entrances. Both produce the same result format.

| Entrance | Status |
|---|---|
| A. URL of a deployed site | Built (this document) |
| B. Source code, before deployment | Planned |

## Results

Every result has three parts, and none is shown without the others.

- **Problems found** (`confirmed`): evidence was observed. Graded P0 / P1 / P2.
- **Items for the owner to check** (`needs_validation`): a concrete concern that
  cannot be decided from outside. Not graded. Example: a site that connects to
  Supabase from the browser is asked to confirm row-level security is on.
- **Coverage**: for each of the 15 rules, whether it was examined, partly
  examined, or not examined and why. A rule that was not examined is never
  reported as passed.

## Entrance A: URL

Anyone can run a passive check on a URL and get a grade and counts. What the
problems are, where they are, and how to fix them is shown only to someone who
has proved they own the site.

Code and identifiers are English. Everything a user reads is Japanese
(`src/i18n/ja.ts`).

## Design rules

| Rule | How the code enforces it |
|---|---|
| Unverified requesters get counts only | `scanPublic()` returns the grade, counts and coverage totals and nothing else; `renderOwnerReport()` requires the ownership proof again and checks it against the assessed host |
| Unverified scans are passive | Only the page and the same-site scripts it references are fetched. For an https site there is one more request, to its http:// address, to see whether it redirects. Active checkers run only with an `OwnershipProof`, and the public summary does not reveal that they ran |
| Detect, never exploit | A detected key is never sent anywhere. Evidence keeps a 6-character prefix and a length. File probes keep a boolean and a count, not contents |
| The scanner cannot be aimed at internal networks | `src/url/net/guard.ts` refuses loopback, private, link-local and metadata addresses and every IPv6 range that embeds IPv4, at connect time (covers DNS rebinding) and on every redirect hop, plus non-standard ports. Error messages are the same for every cause |
| A hostile page cannot stall or crash the scanner | Text from the target is scanned in linear time with bounded matches; one deadline covers every request of a scan |
| A result is about one site | A redirect to a different site is refused, for both tiers; an owner's proof must cover the host actually reached |
| An error page is not graded | A non-2xx page stops the scan |
| Details are unlocked by ownership, not by contact details | The only way to obtain an `OwnershipProof` is one of the three verification methods |
| A result can be checked by someone else | `--json` emits the full assessment for a verified owner; `validate` checks any assessment for consistency |

## Ownership verification

| Method | For whom | Module |
|---|---|---|
| A. Mailbox on the site's own domain | Businesses with a domain mailbox | `ownership/email.ts` |
| B. Verification file placed by the owner's AI coding tool | Sites on platform subdomains; owners who use free mail | `ownership/file.ts` |
| C. DNS TXT record | People comfortable with DNS | `ownership/dns.ts` |

Method A requires a mailbox directly on the site's registrable domain
(`info@example.jp`, not `info@mail.example.jp`). It refuses free and carrier
mail and sites on shared hosting domains, and accepts only admin mailboxes
(`admin@`, `administrator@`, `webmaster@`, `hostmaster@`, `postmaster@`) on
large shared domains such as `ac.jp` and `go.jp`. Its proof covers the one host
that was asked for.

What method A establishes is that the person can read mail at the site's own
domain. In a small business that is the owner. In a larger organisation it is
any member. A service built on this engine should therefore notify the domain's
admin address whenever a detailed report is unlocked, and keep an audit log.

## Rules implemented (rules v0.1.0)

| ID | What | Severity | Tier |
|---|---|---|---|
| R01 | Direct browser connection to Supabase or Firebase detected: asks the owner to confirm the access rules | Not graded (`needs_validation`) | public |
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

# Machine-readable assessment (verified owner), and checking one
QA_JP_AI_SECRET=... npm run scan -- https://example.jp --account acct-1 --verify file --json > assessment.json
npm run scan -- validate assessment.json
```

Only check sites you own or have permission to check.

## Known limits

- Script discovery reads the HTML only. Chunks loaded later at runtime are not seen.
- Method A decides eligibility and issues the proof; sending the login link is the service layer's job and is not built yet. `issueEmailProofAfterLinkClick()` trusts its caller to have confirmed the click.
- The lower-level `scan()` returns every detail at either tier. It is not exported from the package entry point; a service must use `scanPublic()` for unverified requesters.
- `.env` files that start with more than 8 KB of comments, and source maps not referenced from a script, are not found.
- No web UI, rate limiting or audit log yet. These are required before any public deployment.
- A grade of A means nothing was found in the checks that ran. It does not mean the site is safe.

## Acknowledgements

This project builds on the published work of others and says so.

- **[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)**
  (MIT, Copyright (c) 2025-2026 Cloudflare, Inc.) — the source of several ideas in
  the judging layer: three distinct verdicts, a coverage ledger, stable
  fingerprints, and machine-validated records. Those ideas are implemented here
  independently; this repository contains no code or text from it. It is also the
  reference for the planned source-code entrance. When its files are incorporated,
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
