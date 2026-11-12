// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { ConfirmedRecord, RecordFactory } from '../../core/records';
import type { Severity } from '../../core/types';
import { evidence } from '../../i18n/ja';
import type { UrlContext } from '../context';

/**
 * R14 — transport and response-header basics.
 * Passive: reads only the headers of the page a visitor would load.
 *
 * Missing headers are hardening advice (P2), not vulnerabilities. Only the
 * absence of encryption itself is graded P1.
 */

export interface TransportInput {
  finalUrl: string;
  headers: Record<string, string[]>;
  /** Result of loading the http:// version; undefined when not probed. */
  httpRedirectsToHttps?: boolean;
  /** Page HTML, to recognise a policy delivered by a <meta> element. */
  html?: string;
}

const MAX_COOKIES = 50;

/**
 * Cookies that carry a login. Matched as whole words within the name, so
 * "sid" does not match "consider_banner".
 */
const SESSION_WORD = /(?:^|[_.\-])(?:sid|sess|session|auth|token|jwt|login)(?:$|[_.\-])/i;
const SESSION_ID = /sess(?:ion)?_?id/i;
/** Double-submit CSRF cookies must be readable by script: HttpOnly would break them. */
const CSRF = /csrf|xsrf/i;

const looksLikeSession = (name: string) => !CSRF.test(name) && (SESSION_WORD.test(name) || SESSION_ID.test(name));

const META_CSP = /http-equiv\s{0,8}=\s{0,8}["']?content-security-policy/i;

/** HSTS with max-age=0 switches the protection off. */
function hstsEnabled(values: string[] | undefined): boolean {
  return (values ?? []).some((v) => {
    const age = /max-age\s*=\s*"?(\d+)/i.exec(v)?.[1];
    return age !== undefined && Number(age) > 0;
  });
}

function has(headers: Record<string, string[]>, name: string): boolean {
  return (headers[name]?.length ?? 0) > 0;
}

export function checkTransport(input: TransportInput, make: RecordFactory): ConfirmedRecord[] {
  const { finalUrl, headers } = input;
  const found: ConfirmedRecord[] = [];
  const isHttps = new URL(finalUrl).protocol === 'https:';

  const add = (code: string, ev: string, severity: Severity = 'P2', location = finalUrl, key = code) =>
    found.push(make.confirmed({ ruleId: 'R14', code, severity, key, location, evidence: ev }));

  if (!isHttps) {
    add('transport.no_https', evidence.finalUrlNotHttps(), 'P1');
  } else {
    if (input.httpRedirectsToHttps === false) add('transport.no_https_redirect', evidence.httpNotRedirected());
    if (!hstsEnabled(headers['strict-transport-security'])) {
      add('header.hsts_missing', evidence.missingHeader('Strict-Transport-Security'));
    }
  }

  const csp = (headers['content-security-policy'] ?? []).join(';').toLowerCase();
  if (!csp && !(input.html && META_CSP.test(input.html))) {
    add('header.csp_missing', evidence.missingHeader('Content-Security-Policy'));
  }

  const nosniff = (headers['x-content-type-options'] ?? []).some((v) => v.toLowerCase().includes('nosniff'));
  if (!nosniff) add('header.nosniff_missing', evidence.missingHeader('X-Content-Type-Options'));

  if (!has(headers, 'x-frame-options') && !csp.includes('frame-ancestors')) {
    add('header.clickjacking', evidence.missingHeader('X-Frame-Options / frame-ancestors'));
  }

  for (const raw of (headers['set-cookie'] ?? []).slice(0, MAX_COOKIES)) {
    const [pair = '', ...attrParts] = raw.split(';');
    const name = pair.split('=')[0]?.trim() ?? '';
    if (!name) continue;
    const attrs = new Set(attrParts.map((a) => a.trim().split('=')[0]?.toLowerCase() ?? ''));
    const session = looksLikeSession(name);

    const missing: string[] = [];
    if (isHttps && !attrs.has('secure')) missing.push('Secure');
    if (session && !attrs.has('httponly')) missing.push('HttpOnly');
    if (session && !attrs.has('samesite')) missing.push('SameSite');

    if (missing.length > 0) {
      // Cookie name only — never the value.
      add('cookie.insecure', evidence.cookieMissingAttrs(missing), 'P2', `Cookie: ${name}`, `cookie:${name}`);
    }
  }

  return found;
}

export const transportChecker: Checker<UrlContext> = {
  id: 'url.transport',
  layer: 'url',
  mode: 'passive',
  rules: ['R14'],
  run(ctx, make) {
    return {
      records: checkTransport(
        {
          finalUrl: ctx.page.finalUrl,
          headers: ctx.page.headers,
          httpRedirectsToHttps: ctx.httpRedirectsToHttps,
          html: ctx.page.body,
        },
        make,
      ),
      coverage: [{ ruleId: 'R14', status: 'checked' }],
    };
  },
};
