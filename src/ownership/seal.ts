// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac, timingSafeEqual } from 'node:crypto';
import { type OwnershipProof, type ProofMethod, restoreProof } from './proof';

/**
 * Carry a proof between requests of a web service.
 *
 * A proof can only be created by a verification function, so a service cannot
 * rebuild one from what it stored. Instead it stores the sealed form: the
 * proof's facts with an HMAC under the service's secret. Only openProof() can
 * turn it back into a proof, and only unchanged, under the same secret, and
 * before it expires. Its life is never extended.
 *
 * Store the sealed text server-side (a session record), not in a cookie: a
 * session can be revoked, a copied token cannot.
 */

const VERSION = 'qa1';
const METHODS: readonly ProofMethod[] = ['email', 'file', 'dns'];
const MIN_SECRET = 32;

interface Sealed {
  m: ProofMethod;
  s: 'host' | 'domain';
  sub: string;
  va: number;
  ea: number;
}

const mac = (secret: string, payload: string) =>
  createHmac('sha256', secret).update(`${VERSION}.${payload}`).digest('base64url');

function checkSecret(secret: string): void {
  if (typeof secret !== 'string' || secret.length < MIN_SECRET) {
    throw new Error(`The sealing secret must be at least ${MIN_SECRET} characters`);
  }
}

export function sealProof(proof: OwnershipProof, secret: string): string {
  checkSecret(secret);
  const body: Sealed = { m: proof.method, s: proof.scope, sub: proof.subject, va: proof.verifiedAt, ea: proof.expiresAt };
  const payload = Buffer.from(JSON.stringify(body)).toString('base64url');
  return `${VERSION}.${payload}.${mac(secret, payload)}`;
}

export function openProof(sealed: string, secret: string, now: number = Date.now()): OwnershipProof | undefined {
  checkSecret(secret);
  if (typeof sealed !== 'string' || sealed.length > 2048) return undefined;
  const [version, payload, signature, ...rest] = sealed.split('.');
  if (version !== VERSION || !payload || !signature || rest.length > 0) return undefined;

  const expected = Buffer.from(mac(secret, payload));
  const given = Buffer.from(signature);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return undefined;

  let body: Sealed;
  try {
    body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
  const valid =
    METHODS.includes(body.m) &&
    (body.s === 'host' || body.s === 'domain') &&
    typeof body.sub === 'string' &&
    body.sub.length > 0 &&
    Number.isFinite(body.va) &&
    Number.isFinite(body.ea);
  if (!valid || now >= body.ea) return undefined;
  return restoreProof(body.m, body.s, body.sub, body.va, body.ea);
}
