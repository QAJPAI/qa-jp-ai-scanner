// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { ConfirmedRecord, RecordFactory } from '../../core/records';
import type { Severity } from '../../core/types';
import { evidence } from '../../i18n/ja';
import type { UrlContext } from '../context';
import { dmarcPolicy, type MailAuthFacts, recordsOf, spfAll } from '../mailauth';

/**
 * R14 — basic configuration: transport, response headers, and the mail
 * authentication of the site's domain.
 * Passive: reads the headers of the page a visitor would load, and public DNS.
 *
 * Missing headers are hardening advice (P2), not vulnerabilities. P1 is for the
 * absence of encryption, and for a domain anyone can send forged mail as
 * (no DMARC, or SPF that allows every sender).
 */

export interface TransportInput {
  finalUrl: string;
  headers: Record<string, string[]>;
  /** Result of loading the http:// version; undefined when not probed. */
  httpRedirectsToHttps?: boolean;
  /** Page HTML, to recognise a policy delivered by a <meta> element. */
  html?: string;
  /** SPF / DMARC lookups for the site's domain; omitted where they do not apply. */
  mailAuth?: MailAuthFacts;
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

  if (input.mailAuth) checkMailAuth(input.mailAuth, add);
  return found;
}

/** Findings for one domain's SPF and DMARC. Lookups that got no answer produce none. */
function checkMailAuth(
  facts: MailAuthFacts,
  add: (code: string, ev: string, severity: Severity, location: string, key: string) => void,
): void {
  const { domain } = facts;
  const spfAt = `DNS: ${domain}（TXT）`;
  const dmarcAt = `DNS: _dmarc.${domain}（TXT）`;

  if (facts.spf.status !== 'failed') {
    const spf = recordsOf(facts.spf, 'v=spf1');
    if (spf.length === 0) add('email.spf_missing', evidence.spfMissing(domain), 'P2', spfAt, `spf:${domain}`);
    else if (spf.length > 1) add('email.spf_multiple', evidence.spfMultiple(spf.length), 'P2', spfAt, `spf:${domain}`);
    else {
      const all = spfAll(spf[0]!);
      if (all === '+') add('email.spf_allows_all', evidence.spfRecord(spf[0]!), 'P1', spfAt, `spf:${domain}`);
      else if (all === '?' || all === 'none') add('email.spf_neutral', evidence.spfRecord(spf[0]!), 'P2', spfAt, `spf:${domain}`);
    }
  }

  if (facts.dmarc.status !== 'failed') {
    const dmarc = recordsOf(facts.dmarc, 'v=DMARC1');
    // More than one record counts as none (RFC 7489).
    if (dmarc.length !== 1) {
      add('email.dmarc_missing', evidence.dmarcMissing(domain, dmarc.length), 'P1', dmarcAt, `dmarc:${domain}`);
    } else {
      const policy = dmarcPolicy(dmarc[0]!);
      if (policy !== 'quarantine' && policy !== 'reject') {
        add('email.dmarc_monitor_only', evidence.dmarcRecord(dmarc[0]!), 'P2', dmarcAt, `dmarc:${domain}`);
      }
    }
  }
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
          mailAuth: ctx.mailAuth === 'not_applicable' ? undefined : ctx.mailAuth,
        },
        make,
      ),
      // A DNS lookup that got no answer (or never ran for lack of time) leaves the rule partly examined.
      coverage: [
        ctx.mailAuth === undefined || (ctx.mailAuth !== 'not_applicable' && (ctx.mailAuth.spf.status === 'failed' || ctx.mailAuth.dmarc.status === 'failed'))
          ? { ruleId: 'R14', status: 'partial', note: 'some_probes_failed' }
          : { ruleId: 'R14', status: 'checked' },
      ],
    };
  },
};
