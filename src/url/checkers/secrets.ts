// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto';
import type { Checker } from '../../core/checker';
import type { ConfirmedRecord, RecordFactory } from '../../core/records';
import type { Severity } from '../../core/types';
import { evidence } from '../../i18n/ja';
import { everythingRead, type UrlContext } from '../context';

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

const redact = (match: string) => evidence.redactedSecret(match.slice(0, 6), match.length);

const DETECTORS: Detector[] = [
  {
    code: 'secret.supabase_service_role',
    severity: 'P0',
    pattern: JWT_PATTERN,
    accept: (m) => jwtRole(m) === 'service_role',
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
  },
  {
    code: 'secret.github_token',
    severity: 'P0',
    pattern: token('(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})'),
  },
  { code: 'secret.slack_token', severity: 'P0', pattern: token('xox[baprs]-[A-Za-z0-9-]{20,}') },
  { code: 'secret.sendgrid', severity: 'P0', pattern: token('SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}') },
];

/**
 * Stable identity of one key: a truncated hash, so the same key found in two
 * files is one issue. It is hashed again inside the fingerprint and cannot be
 * turned back into the key.
 */
const keyIdentity = (value: string) => createHash('sha256').update(value).digest('hex').slice(0, 16);

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

/** Upper bound on distinct keys reported per scan. Bounds memory against a page full of decoys. */
export const MAX_SECRET_RECORDS = 100;

export interface SecretScanState {
  /** Fingerprints already reported in this scan. */
  seen: Set<string>;
  /** Set when the cap was reached and matching stopped early. */
  limitHit: boolean;
}

export const newSecretScanState = (): SecretScanState => ({ seen: new Set(), limitHit: false });

/**
 * Scan one served text (HTML or a script) for privileged keys. Each distinct
 * key is reported once per scan; matching stops at MAX_SECRET_RECORDS.
 */
export function scanTextForSecrets(
  sourceUrl: string,
  text: string,
  make: RecordFactory,
  state: SecretScanState = newSecretScanState(),
): ConfirmedRecord[] {
  const found: ConfirmedRecord[] = [];
  for (const detector of DETECTORS) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      if (state.seen.size >= MAX_SECRET_RECORDS) {
        state.limitHit = true;
        return found;
      }
      const value = match[0];
      if (detector.accept && !detector.accept(value)) continue;

      const record = make.confirmed({
        ruleId: 'R02',
        code: detector.code,
        severity: detector.severity,
        key: detector.describe ? pemIdentity(text, match.index + value.length) : keyIdentity(value),
        location: `${sourceUrl} (offset ${match.index})`,
        evidence: detector.describe ? detector.describe(value) : redact(value),
      });
      if (state.seen.has(record.fingerprint)) continue;
      state.seen.add(record.fingerprint);
      found.push(record);
    }
  }
  return found;
}

export const secretsChecker: Checker<UrlContext> = {
  id: 'url.secrets',
  layer: 'url',
  mode: 'passive',
  rules: ['R02'],
  run(ctx, make) {
    const state = newSecretScanState();
    const records: ConfirmedRecord[] = [];
    for (const text of ctx.texts) {
      for (const record of scanTextForSecrets(text.url, text.body, make, state)) records.push(record);
      if (state.limitHit) break;
    }
    // Never "checked": code loaded later at runtime is not seen. Say which limit applied.
    const note = state.limitHit
      ? 'record_limit_reached'
      : everythingRead(ctx.load)
        ? 'html_referenced_scripts_only'
        : 'some_content_not_read';
    return { records, coverage: [{ ruleId: 'R02', status: 'partial', note }] };
  },
};
