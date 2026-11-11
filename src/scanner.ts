// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { safeFetch, type FetchOptions } from './net/fetcher';
import { domainInfo, proofCovers, type OwnershipProof } from './ownership/proof';
import { scanTextForSecrets } from './rules/r02-secrets';
import { probeExposedFiles, type ServedScript } from './rules/r11-exposed-files';
import { checkTransport } from './rules/r14-transport';
import { countBySeverity, gradeFor } from './grade';
import { RULES_VERSION, type Finding, type RuleId, type ScanResult } from './types';

export interface ScanOptions {
  /** Presence of a valid proof for the target switches the scan to the owner tier. */
  proof?: OwnershipProof;
  fetch?: FetchOptions;
  maxScripts?: number;
  now?: () => number;
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

export async function scan(input: string, options: ScanOptions = {}): Promise<ScanResult> {
  const now = options.now ?? Date.now;
  const fetchOptions = options.fetch ?? {};
  const target = normalizeTarget(input);

  let tier: ScanResult['tier'] = 'public';
  if (options.proof) {
    if (!proofCovers(options.proof, target.hostname, now())) {
      throw new Error('Ownership proof does not cover this host or has expired');
    }
    tier = 'owner';
  }

  // --- Passive: the same requests a browser makes when opening the page ---
  const page = await safeFetch(target.href, fetchOptions);
  const finalUrl = new URL(page.finalUrl);

  const scripts: ServedScript[] = [];
  const scriptUrls = extractScriptUrls(page.body, finalUrl).slice(0, options.maxScripts ?? DEFAULT_MAX_SCRIPTS);
  for (const url of scriptUrls) {
    try {
      const res = await safeFetch(url, { ...fetchOptions, maxBytes: SCRIPT_MAX_BYTES });
      if (res.status === 200) scripts.push({ url: res.finalUrl, body: res.body });
    } catch {
      // an unreachable script is not a finding
    }
  }

  const findings: Finding[] = [];
  const checksRun: RuleId[] = ['R02', 'R14'];

  const seen = new Set<string>();
  findings.push(...scanTextForSecrets(page.finalUrl, page.body, seen));
  for (const script of scripts) findings.push(...scanTextForSecrets(script.url, script.body, seen));

  findings.push(
    ...checkTransport({
      finalUrl: page.finalUrl,
      headers: page.headers,
      httpRedirectsToHttps:
        finalUrl.protocol === 'https:' ? await httpRedirectsToHttps(finalUrl.host, fetchOptions) : undefined,
    }),
  );

  // --- Active: only after ownership has been verified ---
  if (tier === 'owner') {
    checksRun.push('R11');
    findings.push(...(await probeExposedFiles(finalUrl.origin, scripts, fetchOptions)));
  }

  const counts = countBySeverity(findings);
  return {
    host: target.hostname,
    scannedAt: new Date(now()).toISOString(),
    rulesVersion: RULES_VERSION,
    tier,
    checksRun,
    grade: gradeFor(counts),
    counts,
    findings,
  };
}
