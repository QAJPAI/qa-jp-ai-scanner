// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac, timingSafeEqual } from 'node:crypto';

export const TOKEN_PREFIX = 'qa-jp-ai-verify-';

/**
 * Deterministic verification token for (account, subject). Stateless: the
 * service can re-derive it at check time, so nothing has to be stored.
 */
export function mintVerificationToken(secret: string, accountId: string, subject: string): string {
  if (secret.length < 16) throw new Error('Verification secret must be at least 16 characters');
  if (!accountId) throw new Error('accountId is required');
  const mac = createHmac('sha256', secret)
    .update(`${accountId}\n${subject.toLowerCase()}`)
    .digest('base64url');
  return `${TOKEN_PREFIX}${mac.slice(0, 32)}`;
}

export function tokensEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
