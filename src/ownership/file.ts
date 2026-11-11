// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { safeFetch, type FetchOptions } from '../net/fetcher';
import { issueProof, type OwnershipProof } from './proof';
import { tokensEqual } from './token';

/**
 * Method B — a verification file the owner asks their AI coding tool to add.
 * Works on hosting-platform subdomains, where no same-domain mailbox exists.
 */

export const WELL_KNOWN_PATH = '/.well-known/qa-jp-ai.txt';

export async function verifyByFile(
  origin: string,
  expectedToken: string,
  options: FetchOptions = {},
  now: number = Date.now(),
): Promise<OwnershipProof | undefined> {
  const url = new URL(WELL_KNOWN_PATH, origin);
  let body: string;
  try {
    const res = await safeFetch(url.href, {
      ...options,
      maxBytes: 512,
      sameHostRedirectsOnly: true,
    });
    if (res.status !== 200 || res.truncated) return undefined;
    body = res.body;
  } catch {
    return undefined;
  }
  // Exact match after trimming: an SPA fallback page can never pass.
  if (!tokensEqual(body.trim(), expectedToken)) return undefined;
  return issueProof('file', 'host', url.hostname, now);
}
