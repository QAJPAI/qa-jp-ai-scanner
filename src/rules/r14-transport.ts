// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Finding, Severity } from '../types';
import { evidence } from '../i18n/ja';

/**
 * R14 — transport and response-header basics.
 * Passive: reads only the headers of the page a visitor would load.
 */

export interface TransportInput {
  finalUrl: string;
  headers: Record<string, string[]>;
  /** Result of loading the http:// version; undefined when not probed. */
  httpRedirectsToHttps?: boolean;
}

const SESSION_COOKIE_NAME = /sess|auth|token|sid|jwt|login/i;

function finding(code: string, location: string, ev: string, severity: Severity = 'P2'): Finding {
  return { ruleId: 'R14', severity, code, location, evidence: ev };
}

function has(headers: Record<string, string[]>, name: string): boolean {
  return (headers[name]?.length ?? 0) > 0;
}

export function checkTransport(input: TransportInput): Finding[] {
  const { finalUrl, headers } = input;
  const findings: Finding[] = [];
  const isHttps = new URL(finalUrl).protocol === 'https:';

  if (!isHttps) {
    // No encryption at all is P1; the individual header gaps below stay P2.
    findings.push(finding('transport.no_https', finalUrl, evidence.finalUrlNotHttps(), 'P1'));
  } else {
    if (input.httpRedirectsToHttps === false) {
      findings.push(finding('transport.no_https_redirect', finalUrl, evidence.httpNotRedirected()));
    }
    if (!has(headers, 'strict-transport-security')) {
      findings.push(
        finding('header.hsts_missing', finalUrl, evidence.missingHeader('Strict-Transport-Security')),
      );
    }
  }

  const csp = (headers['content-security-policy'] ?? []).join(';').toLowerCase();
  if (!csp) {
    findings.push(
      finding('header.csp_missing', finalUrl, evidence.missingHeader('Content-Security-Policy')),
    );
  }

  const nosniff = (headers['x-content-type-options'] ?? []).some((v) => v.toLowerCase().includes('nosniff'));
  if (!nosniff) {
    findings.push(
      finding('header.nosniff_missing', finalUrl, evidence.missingHeader('X-Content-Type-Options')),
    );
  }

  if (!has(headers, 'x-frame-options') && !csp.includes('frame-ancestors')) {
    findings.push(
      finding('header.clickjacking', finalUrl, evidence.missingHeader('X-Frame-Options / frame-ancestors')),
    );
  }

  for (const raw of headers['set-cookie'] ?? []) {
    const [pair = '', ...attrParts] = raw.split(';');
    const name = pair.split('=')[0]?.trim() ?? '';
    if (!name) continue;
    const attrs = new Set(attrParts.map((a) => a.trim().split('=')[0]?.toLowerCase() ?? ''));
    const looksLikeSession = SESSION_COOKIE_NAME.test(name);

    const missing: string[] = [];
    if (isHttps && !attrs.has('secure')) missing.push('Secure');
    if (looksLikeSession && !attrs.has('httponly')) missing.push('HttpOnly');
    if (looksLikeSession && !attrs.has('samesite')) missing.push('SameSite');

    if (missing.length > 0) {
      // Cookie name only — never the value.
      findings.push(finding('cookie.insecure', `Cookie: ${name}`, evidence.cookieMissingAttrs(missing)));
    }
  }

  return findings;
}
