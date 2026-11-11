// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { parse } from 'tldts';

/**
 * An OwnershipProof is the only thing that unlocks the owner tier.
 * It can only be created by the verification functions in this directory.
 */

const BRAND: unique symbol = Symbol('qa-jp-ai.ownership-proof');

export type ProofMethod = 'email' | 'file' | 'dns';

export interface OwnershipProof {
  readonly [BRAND]: true;
  readonly method: ProofMethod;
  /** 'host' covers exactly one hostname; 'domain' covers it and its subdomains. */
  readonly scope: 'host' | 'domain';
  readonly subject: string;
  readonly verifiedAt: number;
  readonly expiresAt: number;
}

export const PROOF_TTL_MS = 24 * 60 * 60 * 1000;

/** Internal: call only from a verification function that has just succeeded. */
export function issueProof(
  method: ProofMethod,
  scope: 'host' | 'domain',
  subject: string,
  now: number = Date.now(),
): OwnershipProof {
  return Object.freeze({
    [BRAND]: true as const,
    method,
    scope,
    subject: subject.toLowerCase(),
    verifiedAt: now,
    expiresAt: now + PROOF_TTL_MS,
  });
}

export interface DomainInfo {
  hostname: string;
  /** Registrable domain, treating hosting platforms (vercel.app …) as suffixes. */
  registrable: string | null;
  publicSuffix: string | null;
  /** True when the suffix is a hosting platform's shared domain. */
  isPlatformSuffix: boolean;
  isIp: boolean;
}

export function domainInfo(hostname: string): DomainInfo {
  const parsed = parse(hostname, { allowPrivateDomains: true });
  return {
    hostname: hostname.toLowerCase(),
    registrable: parsed.domain,
    publicSuffix: parsed.publicSuffix,
    isPlatformSuffix: parsed.isPrivate === true,
    isIp: parsed.isIp === true,
  };
}

/** The name ownership is established for: registrable domain, else the host itself. */
export function ownershipSubject(hostname: string): string {
  return (domainInfo(hostname).registrable ?? hostname).toLowerCase();
}

export function proofCovers(proof: OwnershipProof, hostname: string, now: number = Date.now()): boolean {
  if (proof[BRAND] !== true) return false;
  if (now >= proof.expiresAt) return false;
  const host = hostname.toLowerCase();
  if (proof.scope === 'host') return proof.subject === host;
  return host === proof.subject || host.endsWith(`.${proof.subject}`);
}
