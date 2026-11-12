// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto';
import type { Severity } from '../core/types';
import { evidence } from '../i18n/ja';

/**
 * Privileged-key detection shared by every layer: text served by a site (URL
 * layer) and files in a project (repo layer).
 *
 * Detect-only: a match is never used to call the service it belongs to, and
 * the full value is never kept — evidence holds a short prefix and a length.
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
  /** Evidence for matches that carry no key material of their own (PEM headers). */
  describe?: () => string;
  /** Skip the placeholder filter (structured values such as JWTs are validated by `accept`). */
  exact?: boolean;
}

const NOT_TOKEN_CHAR_BEFORE = '(?<![A-Za-z0-9_-])';
const NOT_TOKEN_CHAR_AFTER = '(?![A-Za-z0-9_-])';

function token(body: string): RegExp {
  return new RegExp(`${NOT_TOKEN_CHAR_BEFORE}${body}${NOT_TOKEN_CHAR_AFTER}`, 'g');
}

export const JWT_PATTERN = token('eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}');

/** The `role` claim of a JWT, without verifying it. */
export function jwtRole(jwt: string): string | undefined {
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

const DETECTORS: Detector[] = [
  {
    code: 'secret.supabase_service_role',
    severity: 'P0',
    pattern: JWT_PATTERN,
    accept: (m) => jwtRole(m) === 'service_role',
    exact: true,
  },
  { code: 'secret.supabase_secret_key', severity: 'P0', pattern: token('sb_secret_[A-Za-z0-9_-]{20,}') },
  { code: 'secret.anthropic', severity: 'P0', pattern: token('sk-ant-[A-Za-z0-9_-]{20,}') },
  {
    code: 'secret.openai',
    severity: 'P0',
    pattern: token('sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{48})'),
  },
  { code: 'secret.stripe_live', severity: 'P0', pattern: token('[sr]k_live_[A-Za-z0-9]{16,}') },
  { code: 'secret.stripe_test', severity: 'P1', pattern: token('sk_test_[A-Za-z0-9]{16,}') },
  { code: 'secret.aws_access_key', severity: 'P1', pattern: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/g },
  {
    code: 'secret.private_key',
    severity: 'P0',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    describe: () => evidence.privateKeyHeader(),
    exact: true,
  },
  {
    code: 'secret.github_token',
    severity: 'P0',
    pattern: token('(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})'),
  },
  { code: 'secret.slack_token', severity: 'P0', pattern: token('xox[baprs]-[A-Za-z0-9-]{20,}') },
  { code: 'secret.sendgrid', severity: 'P0', pattern: token('SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}') },
];

const KNOWN_PREFIX =
  /^(?:sk-ant-|sk-proj-|sk-svcacct-|sk-admin-|sk-|[sr]k_live_|sk_test_|sb_secret_|gh[pousr]_|github_pat_|xox[baprs]-|SG\.|AKIA)/;
/**
 * Words that mark a placeholder. Matched only at the start of the value or
 * after a separator (`your-key-here`, `sk_live_your_secret`), so that a random
 * key that happens to contain the letters is not dismissed. `EXAMPLE` in
 * capitals is the form used in AWS documentation (`AKIAIOSFODNN7EXAMPLE`).
 */
const PLACEHOLDER_WORD =
  /(?:^|[-_.])(?:your|YOUR|Your|example|Example|dummy|DUMMY|sample|SAMPLE|placeholder|PLACEHOLDER|redacted|REDACTED|replace|REPLACE|insert|INSERT|changeme|CHANGEME)|EXAMPLE|xxxx|XXXX/;

/**
 * True for values that only look like keys: documentation and template
 * placeholders such as `sk_live_xxxxxxxxxxxxxxxx` or `sk-proj-your-key-here`.
 * A random key has many distinct characters and no long runs.
 *
 * Measured miss rate on random keys of the real shapes: about 1 to 2 in
 * 100,000 (see test/placeholder.test.ts, which fails if it rises).
 */
export function isPlaceholder(value: string): boolean {
  const body = value.replace(KNOWN_PREFIX, '');
  if (PLACEHOLDER_WORD.test(body)) return true;
  if (/(.)\1{7}/.test(body)) return true;
  return new Set(body).size < 6;
}

/**
 * Stable identity of one key: a truncated hash, so the same key found in two
 * places is one issue. It is hashed again inside the fingerprint and cannot be
 * turned back into the key.
 */
export const keyIdentity = (value: string): string => createHash('sha256').update(value).digest('hex').slice(0, 16);

/**
 * A PEM header has no key material in the match itself. Identify the key by
 * the start of its body instead — not by file name or byte offset, which
 * change on every build.
 */
function pemIdentity(text: string, afterHeader: number): string {
  const body = text
    .slice(afterHeader, afterHeader + 256)
    .replace(/\\[nr]/g, '')
    .replace(/[^A-Za-z0-9+/=]/g, '')
    .slice(0, 48);
  return body.length >= 16 ? keyIdentity(body) : 'pem-header-only';
}

/** Upper bound on distinct keys reported per scan. Bounds memory against text full of decoys. */
export const MAX_SECRET_RECORDS = 100;

export interface SecretScanState {
  /** `code\0key` of every key already reported in this scan. */
  seen: Set<string>;
  /** Set when the cap was reached and matching stopped early. */
  limitHit: boolean;
}

export const newSecretScanState = (): SecretScanState => ({ seen: new Set(), limitHit: false });

export interface SecretMatch {
  code: string;
  severity: Severity;
  /** Offset of the match in the text. */
  index: number;
  /** Stable identity for the fingerprint. Never the key itself. */
  key: string;
  /** Redacted evidence. */
  evidence: string;
}

/**
 * Find privileged keys in one text. Each distinct key is reported once per
 * scan (shared `state`); matching stops at MAX_SECRET_RECORDS.
 */
export function findSecrets(text: string, state: SecretScanState = newSecretScanState()): SecretMatch[] {
  const found: SecretMatch[] = [];
  for (const detector of DETECTORS) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      if (state.seen.size >= MAX_SECRET_RECORDS) {
        state.limitHit = true;
        return found;
      }
      const value = match[0];
      if (detector.accept && !detector.accept(value)) continue;
      if (!detector.exact && isPlaceholder(value)) continue;

      const key = detector.describe ? pemIdentity(text, match.index + value.length) : keyIdentity(value);
      const seenKey = `${detector.code}\u0000${key}`;
      if (state.seen.has(seenKey)) continue;
      state.seen.add(seenKey);
      found.push({
        code: detector.code,
        severity: detector.severity,
        index: match.index,
        key,
        evidence: detector.describe ? detector.describe() : evidence.redactedSecret(value.slice(0, 6), value.length),
      });
    }
  }
  return found;
}
