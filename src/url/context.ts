// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FetchOptions, FetchResult } from './net/fetcher';

/** A text the site serves to every visitor: the page or one of its scripts. */
export interface ServedText {
  url: string;
  body: string;
}

/** Everything a URL-layer checker may look at. */
export interface UrlContext {
  page: FetchResult;
  finalUrl: URL;
  /** Same-site scripts referenced by the page. */
  scripts: ServedText[];
  /** The page HTML followed by `scripts`. */
  texts: ServedText[];
  /** Whether http:// redirects to https://; undefined when not probed. */
  httpRedirectsToHttps?: boolean;
  /** Options active checkers must use for any request they make. */
  fetch: FetchOptions;
}
