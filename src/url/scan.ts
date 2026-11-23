// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Assessment } from '../core/assessment';
import type { Checker } from '../core/checker';
import { buildLedger, type CheckerCoverage, type DeferredRule } from '../core/coverage';
import { lookUpMailAuth, type MailDns, mailDomainFor } from './mailauth';
import { dedupeByFingerprint, recordFactory, type AssessmentRecord } from '../core/records';
import { ASSESSMENT_SCHEMA, ENGINE_VERSION, RULES_VERSION, type Tier } from '../core/types';
import { domainInfo, proofCovers, type OwnershipProof } from '../ownership/proof';
import { toPublicSummary, type PublicSummary } from '../report';
import { baasHintChecker } from './checkers/baas-hint';
import { exposedFilesChecker } from './checkers/exposed-files';
import { secretsChecker } from './checkers/secrets';
import { transportChecker } from './checkers/transport';
import type { ServedTextsRead } from './compare';
import { everythingRead, type LoadStats, type ServedText, type UrlContext } from './context';
import { referencedScripts } from './imports';
import { safeFetch, type FetchOptions, type FetchResult } from './net/fetcher';

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
  /**
   * Owner tier: how many requests may be made for scripts that the page's
   * scripts load. 0 switches following off.
   */
  maxFollowedScripts?: number;
  /** Wall-clock budget for all requests of one scan. A slow target cannot hold a worker for long. */
  maxDurationMs?: number;
  now?: () => number;
  /** Override the checker set (tests, experiments). */
  checkers?: readonly Checker<UrlContext>[];
  /** DNS lookups for mail authentication (tests pass their own). */
  mailDns?: MailDns;
  /**
   * Owner tier only: false keeps active checks from running even for a
   * verified owner (a service's off switch). The ledger then says so; it
   * never reads as "passed".
   */
  activeChecks?: boolean;
}

export type ScanErrorCode = 'page_unavailable' | 'redirected_elsewhere' | 'proof_mismatch';

/** A scan that cannot honestly produce a result. Reported to the requester by code. */
export class ScanError extends Error {
  constructor(
    readonly code: ScanErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ScanError';
  }
}

const SCRIPT_MAX_BYTES = 3 * 1024 * 1024;
const DEFAULT_MAX_SCRIPTS = 20;
/**
 * Scripts that other scripts load (owner tier): how many requests are made
 * for them, how deep the chain is followed, how much text is kept, and how
 * much of the scan's time they may take. The rest of the time belongs to the
 * checks that come after.
 */
const DEFAULT_MAX_FOLLOWED_SCRIPTS = 60;
const MAX_FOLLOW_DEPTH = 5;
const MAX_FOLLOWED_BYTES = 30 * 1024 * 1024;
const FOLLOW_TIME_SHARE = 0.5;
const DEFAULT_MAX_DURATION_MS = 60_000;
const MAX_INPUT_LENGTH = 2048;
const MAX_TAGS = 2000;
const MAX_TAG_LENGTH = 4096;

// The attribute name must stand alone: `src`, not `data-src`.
const attr = (name: string) =>
  new RegExp(`(?<=[\\s"'/])${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
const SRC = attr('src');
const HREF = attr('href');
const REL = attr('rel');

const ENTITIES: Record<string, string> = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>' };

/** Decode the few character references that occur in URLs. */
function decodeEntities(value: string): string {
  return value.replace(/&(?:(amp|quot|apos|lt|gt)|#(\d{1,6})|#x([0-9a-f]{1,5}));/gi, (whole, named, dec, hex) => {
    if (named) return ENTITIES[String(named).toLowerCase()] ?? whole;
    const code = dec ? Number(dec) : parseInt(String(hex), 16);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
  });
}

function attrValue(tag: string, pattern: RegExp): string | undefined {
  const m = pattern.exec(tag);
  const raw = m ? (m[1] ?? m[2] ?? m[3]) : undefined;
  return raw === undefined ? undefined : decodeEntities(raw.trim());
}

/** Index of the `>` that closes a tag, ignoring any `>` inside a quoted attribute value. */
function tagEnd(window: string): number {
  let quote = 0;
  for (let i = 0; i < window.length; i++) {
    const c = window.charCodeAt(i);
    if (quote) {
      if (c === quote) quote = 0;
    } else if (c === 0x22 || c === 0x27) {
      quote = c;
    } else if (c === 0x3e) {
      return i;
    }
  }
  return -1;
}

/**
 * Opening tags of one element, found by a linear scan.
 *
 * The page is attacker-controlled, so this must not be one regex over the
 * whole document: a pattern like /<script[^>]*src=/ takes quadratic time on a
 * page made of unterminated tags. The tag name is found with a fixed-string
 * search, each tag is cut to a bounded window, and the number of candidates
 * examined is capped (and reported when hit).
 */
function openingTags(html: string, name: string): { tags: string[]; limitHit: boolean } {
  const start = new RegExp(`<${name}(?=[\\s/>])`, 'gi');
  const tags: string[] = [];
  let examined = 0;
  for (let m = start.exec(html); m; m = start.exec(html)) {
    if (examined >= MAX_TAGS) return { tags, limitHit: true };
    examined++;
    const window = html.slice(m.index, m.index + MAX_TAG_LENGTH);
    const end = tagEnd(window);
    if (end >= 0) tags.push(window.slice(0, end));
  }
  return { tags, limitHit: false };
}

export function normalizeTarget(input: string): URL {
  const trimmed = input.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_INPUT_LENGTH) {
    throw new Error('URL is empty or too long');
  }
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

/** Same-site script URLs the page itself tells every browser to load. */
export function discoverScripts(html: string, pageUrl: URL): { urls: string[]; tagLimitHit: boolean; base: URL } {
  const scripts = openingTags(html, 'script');
  const links = openingTags(html, 'link');
  const bases = openingTags(html, 'base');

  // <base href> changes what relative URLs mean.
  let base = pageUrl;
  const baseHref = bases.tags.map((tag) => attrValue(tag, HREF)).find((v) => v);
  if (baseHref) {
    try {
      base = new URL(baseHref, pageUrl);
    } catch {
      // malformed base: ignore it
    }
  }

  const raw: string[] = [];
  for (const tag of scripts.tags) {
    const src = attrValue(tag, SRC);
    if (src) raw.push(src);
  }
  for (const tag of links.tags) {
    if (attrValue(tag, REL)?.toLowerCase().includes('modulepreload')) {
      const href = attrValue(tag, HREF);
      if (href) raw.push(href);
    }
  }

  const urls = new Set<string>();
  for (const value of raw) {
    try {
      const resolved = new URL(value, base);
      if ((resolved.protocol === 'http:' || resolved.protocol === 'https:') && sameSite(resolved, pageUrl)) {
        urls.add(resolved.href);
      }
    } catch {
      // malformed src: skip
    }
  }
  return { urls: [...urls], tagLimitHit: scripts.limitHit || links.limitHit, base };
}

export const extractScriptUrls = (html: string, pageUrl: URL): string[] => discoverScripts(html, pageUrl).urls;

async function httpRedirectsToHttps(host: string, options: FetchOptions): Promise<boolean | undefined> {
  try {
    const res = await safeFetch(`http://${host}/`, { ...options, maxBytes: 1024 });
    return new URL(res.finalUrl).protocol === 'https:';
  } catch {
    return undefined; // port 80 closed or unreachable: nothing to report
  }
}

const isJavaScript = (res: FetchResult): boolean =>
  (res.headers['content-type'] ?? []).some((v) => /javascript|ecmascript/i.test(v));

/**
 * Read the scripts that the page's scripts load, and the ones those load,
 * breadth first. Appends to `scripts` and counts in `load`.
 *
 * A reference is a guess until it is fetched: a path-shaped string in a script
 * need not be a script. So an address that answers "not found", or with
 * something that is not JavaScript (an app that serves its page for every
 * path), is dropped without counting as unread. Anything else that could not
 * be read does count: an unread script is not a clean script.
 *
 * Bounded four ways: the number of requests, the depth of the chain, the
 * amount of text kept, and a share of the scan's time budget. What falls
 * outside is counted as skipped.
 */
async function followImports(
  scripts: ServedText[],
  known: Set<string>,
  pageUrl: URL,
  pageBase: URL,
  load: LoadStats,
  fetchOptions: FetchOptions,
  maxRequests: number,
  outOfTime: () => boolean,
): Promise<void> {
  for (const s of scripts) known.add(s.url);
  let requests = 0;
  let bytes = 0;
  let level = [...scripts];
  for (let depth = 1; level.length > 0; depth++) {
    const next: ServedText[] = [];
    for (const script of level) {
      const refs = referencedScripts(script.body, new URL(script.url), pageBase);
      if (refs.limitHit) load.scriptsSkipped++;
      for (const url of refs.urls) {
        if (known.has(url)) continue;
        known.add(url);
        if (!sameSite(new URL(url), pageUrl)) continue;
        if (depth > MAX_FOLLOW_DEPTH || requests >= maxRequests || bytes >= MAX_FOLLOWED_BYTES || outOfTime()) {
          load.scriptsSkipped++;
          continue;
        }
        requests++;
        try {
          const res = await safeFetch(url, { ...fetchOptions, maxBytes: SCRIPT_MAX_BYTES });
          if (res.status === 404 || res.status === 410) continue;
          if (res.status !== 200) {
            load.scriptsFailed++;
            continue;
          }
          // The address may have redirected: it must still be this site, and a script.
          if (!sameSite(new URL(res.finalUrl), pageUrl) || !isJavaScript(res)) continue;
          if (res.finalUrl !== url) {
            if (known.has(res.finalUrl)) continue;
            known.add(res.finalUrl);
          }
          const text: ServedText = { url: res.finalUrl, body: res.body, ...(res.truncated ? { truncated: true } : {}) };
          scripts.push(text);
          next.push(text);
          bytes += res.body.length;
          load.scriptsRead++;
          load.scriptsFound++;
          if (res.truncated) load.scriptsTruncated++;
        } catch {
          load.scriptsFailed++;
        }
      }
    }
    level = next;
  }
}

/**
 * The requests a browser makes when opening the page, plus one request to the
 * http:// address of an https site to see whether it redirects. For a verified
 * owner, also the scripts that the page's scripts load: what a browser
 * requests as the app is used. Nothing more.
 */
async function loadContext(
  target: URL,
  fetchOptions: FetchOptions,
  maxScripts: number,
  follow: { maxRequests: number; outOfTime: () => boolean },
  outOfTime: () => boolean,
  mailDns: MailDns | undefined,
): Promise<UrlContext> {
  const page = await safeFetch(target.href, fetchOptions);
  const finalUrl = new URL(page.finalUrl);

  // A result is about one site. If the address hands the visitor to a different
  // site, grading that site under this name — or probing it with this site's
  // ownership proof — would be wrong.
  if (!sameSite(target, finalUrl)) {
    throw new ScanError('redirected_elsewhere', `The address redirects to another site (${finalUrl.hostname})`);
  }
  // An error page is not the site: do not grade it.
  if (page.status < 200 || page.status >= 300) {
    throw new ScanError('page_unavailable', `The page answered with status ${page.status}`);
  }

  const found = discoverScripts(page.body, finalUrl);
  const load: LoadStats = {
    pageTruncated: page.truncated,
    tagLimitHit: found.tagLimitHit,
    scriptsFound: found.urls.length,
    scriptsRead: 0,
    scriptsFailed: 0,
    scriptsTruncated: 0,
    scriptsSkipped: Math.max(0, found.urls.length - maxScripts),
    importsFollowed: follow.maxRequests > 0,
  };

  const scripts: ServedText[] = [];
  for (const url of found.urls.slice(0, maxScripts)) {
    if (outOfTime()) {
      load.scriptsSkipped++;
      continue;
    }
    try {
      const res = await safeFetch(url, { ...fetchOptions, maxBytes: SCRIPT_MAX_BYTES });
      if (res.status !== 200) {
        load.scriptsFailed++;
        continue;
      }
      scripts.push({ url: res.finalUrl, body: res.body, ...(res.truncated ? { truncated: true } : {}) });
      load.scriptsRead++;
      if (res.truncated) load.scriptsTruncated++;
    } catch {
      load.scriptsFailed++;
    }
  }

  if (follow.maxRequests > 0) {
    await followImports(
      scripts,
      new Set(found.urls),
      finalUrl,
      found.base,
      load,
      fetchOptions,
      follow.maxRequests,
      follow.outOfTime,
    );
  }

  const mailDomain = mailDomainFor(finalUrl.hostname);
  const mailAuth: UrlContext['mailAuth'] = !mailDomain
    ? 'not_applicable'
    : outOfTime()
      ? undefined
      : await lookUpMailAuth(mailDomain, mailDns);

  return {
    page,
    finalUrl,
    mailAuth,
    scripts,
    texts: [{ url: page.finalUrl, body: page.body, ...(page.truncated ? { truncated: true } : {}) }, ...scripts],
    load,
    httpRedirectsToHttps:
      finalUrl.protocol === 'https:' && !outOfTime()
        ? await httpRedirectsToHttps(finalUrl.host, fetchOptions)
        : undefined,
    fetch: fetchOptions,
    outOfTime,
  };
}

/** A scan's result together with what it read, for comparing with an earlier check. */
export interface UrlInspection extends ServedTextsRead {
  assessment: Assessment;
}

/**
 * Run a scan and return the full assessment.
 *
 * The returned object holds every detail, at either tier. A service must not
 * hand it to an unverified requester: use scanPublic() for that. This function
 * is for the owner path, for tests, and for tools that post-process results.
 */
export async function scan(input: string, options: ScanOptions = {}): Promise<Assessment> {
  return (await inspect(input, options)).assessment;
}

async function inspect(input: string, options: ScanOptions): Promise<UrlInspection> {
  const now = options.now ?? Date.now;
  const target = normalizeTarget(input);

  let tier: Tier = 'public';
  if (options.proof) {
    if (!proofCovers(options.proof, target.hostname, now())) {
      throw new ScanError('proof_mismatch', 'Ownership proof does not cover this host or has expired');
    }
    tier = 'owner';
  }

  const startedMs = Date.now();
  const budgetMs = options.maxDurationMs ?? DEFAULT_MAX_DURATION_MS;
  const outOfTime = () => Date.now() - startedMs >= budgetMs;
  // Every request of this scan, including active probes, shares one deadline.
  const fetchOptions: FetchOptions = { ...options.fetch, deadlineAt: startedMs + Math.max(budgetMs, 1) };

  const ctx = await loadContext(
    target,
    fetchOptions,
    options.maxScripts ?? DEFAULT_MAX_SCRIPTS,
    {
      // Reading further than the page itself points is for the verified owner only.
      maxRequests: tier === 'owner' ? (options.maxFollowedScripts ?? DEFAULT_MAX_FOLLOWED_SCRIPTS) : 0,
      outOfTime: () => Date.now() - startedMs >= budgetMs * FOLLOW_TIME_SHARE,
    },
    outOfTime,
    options.mailDns,
  );

  // The proof must cover the host that was actually reached, not only the one
  // that was typed: example.jp may answer as www.example.jp.
  if (options.proof && !proofCovers(options.proof, ctx.finalUrl.hostname, now())) {
    throw new ScanError('proof_mismatch', 'Ownership proof does not cover the host this address leads to');
  }

  const records: AssessmentRecord[] = [];
  const ran: CheckerCoverage[] = [];
  const deferred: DeferredRule[] = [];

  for (const checker of options.checkers ?? URL_CHECKERS) {
    // Active checks run only after ownership has been verified.
    if (checker.mode === 'active' && tier !== 'owner') {
      for (const ruleId of checker.rules) deferred.push({ ruleId, reason: 'requires_owner_verification' });
      continue;
    }
    if (checker.mode === 'active' && options.activeChecks === false) {
      for (const ruleId of checker.rules) deferred.push({ ruleId, reason: 'disabled_by_operator' });
      continue;
    }
    try {
      // Out of time before an active check could start: say so rather than skip silently.
      if (checker.mode === 'active' && outOfTime()) throw new Error('scan time budget exhausted');
      const outcome = await checker.run(ctx, recordFactory(checker.id, checker.layer, checker.mode));
      for (const record of outcome.records) records.push(record);
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

  const assessment: Assessment = {
    schema: ASSESSMENT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    rulesVersion: RULES_VERSION,
    target: { layer: 'url', host: ctx.finalUrl.hostname },
    tier,
    startedAt: new Date(now()).toISOString(),
    records: dedupeByFingerprint(records),
    coverage: buildLedger('url', ran, deferred),
  };
  return {
    assessment,
    everythingRead: everythingRead(ctx.load),
    textsRead: new Set(ctx.texts.filter((t) => !t.truncated).map((t) => t.url)),
  };
}

/**
 * The entry point for an unverified requester. Only the summary leaves this
 * function: no record, location or evidence exists in what it returns.
 */
export async function scanPublic(input: string, options: Omit<ScanOptions, 'proof'> = {}): Promise<PublicSummary> {
  return toPublicSummary(await scan(input, { ...options, proof: undefined }));
}

/** The entry point for a verified owner. A proof is required, not optional. */
export async function scanOwner(
  input: string,
  proof: OwnershipProof,
  options: Omit<ScanOptions, 'proof'> = {},
): Promise<Assessment> {
  return scan(input, { ...options, proof });
}

/**
 * scanOwner(), together with what was read. A service that offers a re-check
 * keeps the earlier assessment and compares:
 * compareAssessments(earlier, now.assessment, { wasRead: servedTextReader(now) }).
 */
export async function inspectOwner(
  input: string,
  proof: OwnershipProof,
  options: Omit<ScanOptions, 'proof'> = {},
): Promise<UrlInspection> {
  return inspect(input, { ...options, proof });
}
