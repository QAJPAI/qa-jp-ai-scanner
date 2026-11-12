// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from '../core/assessment';
import type { Checker } from '../core/checker';
import { buildLedger, type CheckerCoverage, type DeferredRule } from '../core/coverage';
import { dedupeByFingerprint, recordFactory, type AssessmentRecord } from '../core/records';
import { ASSESSMENT_SCHEMA, ENGINE_VERSION, RULES_VERSION, type Tier } from '../core/types';
import { domainInfo, proofCovers, type OwnershipProof } from '../ownership/proof';
import { baasHintChecker } from './checkers/baas-hint';
import { exposedFilesChecker } from './checkers/exposed-files';
import { secretsChecker } from './checkers/secrets';
import { transportChecker } from './checkers/transport';
import type { ServedText, UrlContext } from './context';
import { safeFetch, type FetchOptions } from './net/fetcher';

/** The URL layer's inspectors. Adding a check means adding an entry here. */
export const URL_CHECKERS: readonly Checker<UrlContext>[] = [
  secretsChecker,
  baasHintChecker,
  transportChecker,
  exposedFilesChecker,
];

export interface ScanOptions {
  /** A valid proof for the target switches the scan to the owner tier. */
  proof?: OwnershipProof;
  fetch?: FetchOptions;
  maxScripts?: number;
  now?: () => number;
  /** Override the checker set (tests, experiments). */
  checkers?: readonly Checker<UrlContext>[];
}

const SCRIPT_MAX_BYTES = 3 * 1024 * 1024;
const DEFAULT_MAX_SCRIPTS = 20;

const SCRIPT_SRC = /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
const MODULE_PRELOAD = /<link\b(?=[^>]*\brel\s*=\s*["']?modulepreload)[^>]*?\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;

export function normalizeTarget(input: string): URL {
  const trimmed = input.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const url = new URL(withScheme);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http(s) URLs can be checked');
  }
  url.hash = '';
  return url;
}

function sameSite(a: URL, b: URL): boolean {
  if (a.hostname === b.hostname) return true;
  const da = domainInfo(a.hostname).registrable;
  return da !== null && da === domainInfo(b.hostname).registrable;
}

/** Script URLs the page itself tells every browser to load. */
export function extractScriptUrls(html: string, pageUrl: URL): string[] {
  const urls = new Set<string>();
  for (const pattern of [SCRIPT_SRC, MODULE_PRELOAD]) {
    pattern.lastIndex = 0;
    for (const m of html.matchAll(pattern)) {
      const raw = m[1] ?? m[2] ?? m[3];
      if (!raw) continue;
      try {
        const resolved = new URL(raw, pageUrl);
        if ((resolved.protocol === 'http:' || resolved.protocol === 'https:') && sameSite(resolved, pageUrl)) {
          urls.add(resolved.href);
        }
      } catch {
        // malformed src: skip
      }
    }
  }
  return [...urls];
}

async function httpRedirectsToHttps(host: string, options: FetchOptions): Promise<boolean | undefined> {
  try {
    const res = await safeFetch(`http://${host}/`, { ...options, maxBytes: 1024 });
    return new URL(res.finalUrl).protocol === 'https:';
  } catch {
    return undefined; // port 80 closed or unreachable: nothing to report
  }
}

/** The requests a browser makes when opening the page — nothing more. */
async function loadContext(target: URL, fetchOptions: FetchOptions, maxScripts: number): Promise<UrlContext> {
  const page = await safeFetch(target.href, fetchOptions);
  const finalUrl = new URL(page.finalUrl);

  const scripts: ServedText[] = [];
  for (const url of extractScriptUrls(page.body, finalUrl).slice(0, maxScripts)) {
    try {
      const res = await safeFetch(url, { ...fetchOptions, maxBytes: SCRIPT_MAX_BYTES });
      if (res.status === 200) scripts.push({ url: res.finalUrl, body: res.body });
    } catch {
      // an unreachable script is not a finding
    }
  }

  return {
    page,
    finalUrl,
    scripts,
    texts: [{ url: page.finalUrl, body: page.body }, ...scripts],
    httpRedirectsToHttps:
      finalUrl.protocol === 'https:' ? await httpRedirectsToHttps(finalUrl.host, fetchOptions) : undefined,
    fetch: fetchOptions,
  };
}

export async function scan(input: string, options: ScanOptions = {}): Promise<Assessment> {
  const now = options.now ?? Date.now;
  const target = normalizeTarget(input);

  let tier: Tier = 'public';
  if (options.proof) {
    if (!proofCovers(options.proof, target.hostname, now())) {
      throw new Error('Ownership proof does not cover this host or has expired');
    }
    tier = 'owner';
  }

  const ctx = await loadContext(target, options.fetch ?? {}, options.maxScripts ?? DEFAULT_MAX_SCRIPTS);

  const records: AssessmentRecord[] = [];
  const ran: CheckerCoverage[] = [];
  const deferred: DeferredRule[] = [];

  for (const checker of options.checkers ?? URL_CHECKERS) {
    // Active checks run only after ownership has been verified.
    if (checker.mode === 'active' && tier !== 'owner') {
      for (const ruleId of checker.rules) deferred.push({ ruleId, reason: 'requires_owner_verification' });
      continue;
    }
    try {
      const outcome = await checker.run(ctx, recordFactory(checker.id, checker.layer, checker.mode));
      records.push(...outcome.records);
      ran.push({ checker: checker.id, mode: checker.mode, reports: outcome.coverage });
    } catch {
      // A failed check is recorded as such; it must never read as "nothing found".
      ran.push({
        checker: checker.id,
        mode: checker.mode,
        reports: checker.rules.map((ruleId) => ({ ruleId, status: 'error' as const })),
      });
    }
  }

  return {
    schema: ASSESSMENT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    rulesVersion: RULES_VERSION,
    target: { layer: 'url', host: target.hostname },
    tier,
    startedAt: new Date(now()).toISOString(),
    records: dedupeByFingerprint(records),
    coverage: buildLedger('url', ran, deferred),
  };
}
