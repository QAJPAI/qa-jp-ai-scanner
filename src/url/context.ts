// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { MailAuthFacts } from './mailauth';
import type { FetchOptions, FetchResult } from './net/fetcher';

/** A text the site serves to every visitor: the page or one of its scripts. */
export interface ServedText {
  url: string;
  body: string;
  /** Read only up to the size cap: the rest of it was not seen. */
  truncated?: boolean;
}

/**
 * How much of what the page references was actually read. A checker that
 * inspects served text must report these in its coverage: an unread script is
 * not a clean script.
 */
export interface LoadStats {
  pageTruncated: boolean;
  /** More opening tags than the scanner examines. */
  tagLimitHit: boolean;
  scriptsFound: number;
  scriptsRead: number;
  /** Fetch failed or did not answer 200. */
  scriptsFailed: number;
  /** Read only up to the size cap. */
  scriptsTruncated: number;
  /** Not requested: over the script cap, or the time budget ran out. */
  scriptsSkipped: number;
  /**
   * Scripts loaded by other scripts were looked for and read too (owner tier).
   * Of those, `scriptsRead`, `scriptsFailed`, `scriptsTruncated` and
   * `scriptsSkipped` count them like any other script.
   */
  importsFollowed: boolean;
}

export const everythingRead = (load: LoadStats): boolean =>
  !load.pageTruncated &&
  !load.tagLimitHit &&
  load.scriptsFailed === 0 &&
  load.scriptsTruncated === 0 &&
  load.scriptsSkipped === 0;

/** Everything a URL-layer checker may look at. */
export interface UrlContext {
  page: FetchResult;
  finalUrl: URL;
  /** Same-site scripts referenced by the page and, for a verified owner, the scripts those load. */
  scripts: ServedText[];
  /** The page HTML followed by `scripts`. */
  texts: ServedText[];
  load: LoadStats;
  /** Whether http:// redirects to https://; undefined when not probed. */
  httpRedirectsToHttps?: boolean;
  /**
   * SPF / DMARC of the site's domain from public DNS; 'not_applicable' where
   * the owner cannot set DNS (IP address, hosting platform subdomain);
   * undefined when not looked up (out of time).
   */
  mailAuth?: MailAuthFacts | 'not_applicable';
  /** Options active checkers must use for any request they make. Carries the scan deadline. */
  fetch: FetchOptions;
  /** True once the scan's time budget is spent: make no further requests. */
  outOfTime: () => boolean;
}
