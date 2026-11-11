// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Finding, Severity } from '../types';
import { evidence } from '../i18n/ja';

/**
 * R02 — privileged keys shipped to the browser.
 *
 * Passive: only inspects text the site already serves to every visitor.
 * Detect-only: a match is never used to call the service it belongs to, and
 * the full value is never stored — evidence keeps a short prefix and a length.
 *
 * Deliberately NOT findings (public by design): Supabase anon / publishable
 * keys, Firebase web API keys, Stripe publishable keys.
 */

interface Detector {
  code: string;
  severity: Severity;
  pattern: RegExp;
  /** Extra validation of a regex match; return false to discard it. */
  accept?: (match: string) => boolean;
  describe?: (match: string) => string;
}

const NOT_TOKEN_CHAR_BEFORE = '(?<![A-Za-z0-9_-])';
const NOT_TOKEN_CHAR_AFTER = '(?![A-Za-z0-9_-])';

function token(body: string): RegExp {
  return new RegExp(`${NOT_TOKEN_CHAR_BEFORE}${body}${NOT_TOKEN_CHAR_AFTER}`, 'g');
}

function jwtRole(jwt: string): string | undefined {
  const payload = jwt.split('.')[1];
  if (!payload) return undefined;
  try {
    const json: unknown = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof json === 'object' && json !== null && 'role' in json) {
      const role = (json as { role: unknown }).role;
      return typeof role === 'string' ? role : undefined;
    }
  } catch {
    // not a JSON payload: not a JWT we care about
  }
  return undefined;
}

const redact = (match: string) => evidence.redactedSecret(match.slice(0, 6), match.length);

const DETECTORS: Detector[] = [
  {
    code: 'secret.supabase_service_role',
    severity: 'P0',
    pattern: token('eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}'),
    accept: (m) => jwtRole(m) === 'service_role',
  },
  {
    code: 'secret.supabase_secret_key',
    severity: 'P0',
    pattern: token('sb_secret_[A-Za-z0-9_-]{20,}'),
  },
  {
    code: 'secret.anthropic',
    severity: 'P0',
    pattern: token('sk-ant-[A-Za-z0-9_-]{20,}'),
  },
  {
    code: 'secret.openai',
    severity: 'P0',
    pattern: token('sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{48})'),
  },
  {
    code: 'secret.stripe_live',
    severity: 'P0',
    pattern: token('[sr]k_live_[A-Za-z0-9]{16,}'),
  },
  {
    code: 'secret.stripe_test',
    severity: 'P1',
    pattern: token('sk_test_[A-Za-z0-9]{16,}'),
  },
  {
    code: 'secret.aws_access_key',
    severity: 'P1',
    pattern: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/g,
  },
  {
    code: 'secret.private_key',
    severity: 'P0',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    describe: () => evidence.privateKeyHeader(),
  },
  {
    code: 'secret.github_token',
    severity: 'P0',
    pattern: token('(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})'),
  },
  {
    code: 'secret.slack_token',
    severity: 'P0',
    pattern: token('xox[baprs]-[A-Za-z0-9-]{20,}'),
  },
  {
    code: 'secret.sendgrid',
    severity: 'P0',
    pattern: token('SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}'),
  },
];

/**
 * Scan one served text (HTML or a script) for privileged keys.
 * `seen` de-duplicates the same key across several files of one scan.
 */
export function scanTextForSecrets(sourceUrl: string, text: string, seen = new Set<string>()): Finding[] {
  const findings: Finding[] = [];

  for (const detector of DETECTORS) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      const value = match[0];
      if (detector.accept && !detector.accept(value)) continue;

      const key = `${detector.code}\u0000${value}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        ruleId: 'R02',
        severity: detector.severity,
        code: detector.code,
        location: `${sourceUrl} (offset ${match.index})`,
        evidence: detector.describe ? detector.describe(value) : redact(value),
      });
    }
  }
  return findings;
}
