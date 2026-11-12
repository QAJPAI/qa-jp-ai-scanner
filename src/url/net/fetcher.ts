// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { Agent, request } from 'undici';
import { isIP } from 'node:net';
import { BlockedAddressError, guardedLookup, isBlockedAddress } from './guard';

export const USER_AGENT = 'QA.JP.AI-Scanner/0.1 (+https://qa.jp.ai)';

export interface FetchOptions {
  /** Tests only: allow loopback/private targets and non-standard ports. */
  allowPrivate?: boolean;
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
  /** Refuse redirects that leave the original hostname. */
  sameHostRedirectsOnly?: boolean;
}

export interface FetchResult {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  /** Lower-cased header names; every value as a list. */
  headers: Record<string, string[]>;
  body: string;
  truncated: boolean;
  redirectChain: string[];
}

const DEFAULTS = {
  maxBytes: 2 * 1024 * 1024,
  timeoutMs: 10_000,
  maxRedirects: 5,
};

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

let guardedAgent: Agent | undefined;
let openAgent: Agent | undefined;

function agentFor(allowPrivate: boolean): Agent {
  if (allowPrivate) {
    openAgent ??= new Agent({ connect: { timeout: 5_000 } });
    return openAgent;
  }
  guardedAgent ??= new Agent({
    connect: { timeout: 5_000, lookup: guardedLookup as never },
  });
  return guardedAgent;
}

/** Close pooled connections (lets test processes exit promptly). */
export async function closeAgents(): Promise<void> {
  await Promise.all([guardedAgent?.close(), openAgent?.close()]);
  guardedAgent = undefined;
  openAgent = undefined;
}

function assertAllowedUrl(url: URL, allowPrivate: boolean): void {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BlockedAddressError(`Unsupported protocol: ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new BlockedAddressError('URLs with credentials are not accepted');
  }
  if (allowPrivate) return;

  if (url.port !== '' && url.port !== '80' && url.port !== '443') {
    throw new BlockedAddressError(`Port ${url.port} is not allowed`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  // IP literals never reach the DNS lookup hook, so check them here.
  if (isIP(host) !== 0 && isBlockedAddress(host)) {
    throw new BlockedAddressError('Target is a non-public address');
  }
}

function normalizeHeaders(raw: Record<string, string | string[] | undefined>): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [name, value] of Object.entries(raw)) {
    if (value === undefined) continue;
    out[name.toLowerCase()] = Array.isArray(value) ? value : [value];
  }
  return out;
}

/**
 * GET a URL with SSRF protection, a response-size cap, a timeout, and
 * manually followed redirects (each hop is re-validated).
 */
export async function safeFetch(input: string, options: FetchOptions = {}): Promise<FetchResult> {
  const allowPrivate = options.allowPrivate ?? false;
  const maxBytes = options.maxBytes ?? DEFAULTS.maxBytes;
  const timeoutMs = options.timeoutMs ?? DEFAULTS.timeoutMs;
  const maxRedirects = options.maxRedirects ?? DEFAULTS.maxRedirects;

  const first = new URL(input);
  let current = first;
  const redirectChain: string[] = [];

  for (let hop = 0; ; hop++) {
    assertAllowedUrl(current, allowPrivate);

    const res = await request(current, {
      method: 'GET',
      dispatcher: agentFor(allowPrivate),
      headers: { 'user-agent': USER_AGENT, accept: '*/*' },
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
      signal: AbortSignal.timeout(timeoutMs * 2),
    });

    const headers = normalizeHeaders(res.headers);
    const location = headers['location']?.[0];

    if (REDIRECT_STATUS.has(res.statusCode) && location) {
      await res.body.dump();
      if (hop >= maxRedirects) throw new Error('Too many redirects');
      const next = new URL(location, current);
      if (options.sameHostRedirectsOnly && next.hostname !== first.hostname) {
        throw new Error('Redirect left the original host');
      }
      redirectChain.push(next.href);
      current = next;
      continue;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    let truncated = false;
    for await (const chunk of res.body as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > maxBytes) {
        chunks.push(chunk.subarray(0, chunk.length - (size - maxBytes)));
        truncated = true;
        break; // leaving the loop destroys the stream
      }
      chunks.push(chunk);
    }

    return {
      requestedUrl: first.href,
      finalUrl: current.href,
      status: res.statusCode,
      headers,
      body: Buffer.concat(chunks).toString('utf8'),
      truncated,
      redirectChain,
    };
  }
}
