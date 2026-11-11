// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { domainInfo, issueProof, type OwnershipProof } from './proof';

/**
 * Method A — a mailbox on the site's own domain.
 *
 * This module only decides whether an address CAN prove ownership of a host.
 * Sending the login link and confirming the click is the service's job;
 * confirmEmailOwnership() must be called only after that click.
 */

export type EmailDecision =
  | { status: 'eligible' }
  | {
      status: 'ineligible';
      reason: 'invalid' | 'domain_mismatch' | 'free_mail' | 'platform_subdomain' | 'ip_address' | 'admin_only';
    };

/** Same set certificate authorities accept for domain validation. */
const ADMIN_LOCAL_PARTS = new Set(['admin', 'administrator', 'webmaster', 'hostmaster', 'postmaster']);

/** Mail anyone can obtain: proves nothing about a website. */
const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.co.jp', 'yahoo.com', 'ymail.com',
  'outlook.com', 'outlook.jp', 'hotmail.com', 'hotmail.co.jp', 'live.com', 'live.jp', 'msn.com',
  'icloud.com', 'me.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com',
  'gmx.com', 'zoho.com', 'mail.com', 'qq.com', '163.com', 'naver.com',
  'docomo.ne.jp', 'ezweb.ne.jp', 'au.com', 'softbank.ne.jp', 'i.softbank.jp', 'ymobile.ne.jp',
  'rakuten.jp', 'rakumail.jp', 'nifty.com', 'biglobe.ne.jp', 'ocn.ne.jp', 'so-net.ne.jp', 'plala.or.jp',
]);

/** Suffix labels of large shared organisations (universities, government). */
const SHARED_ORG_LABELS = new Set(['ac', 'edu', 'go', 'gov', 'lg', 'ed', 'mil']);
const SHARED_ORG_TLDS = new Set(['edu', 'gov', 'mil']);

const EMAIL = /^([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$/;

function isSharedOrgSuffix(publicSuffix: string | null): boolean {
  if (!publicSuffix) return false;
  const labels = publicSuffix.split('.');
  if (labels.length === 1) return SHARED_ORG_TLDS.has(labels[0]!);
  return SHARED_ORG_LABELS.has(labels[0]!);
}

export function evaluateEmailOwnership(email: string, targetHost: string): EmailDecision {
  const match = EMAIL.exec(email.trim());
  if (!match) return { status: 'ineligible', reason: 'invalid' };
  const local = match[1]!.toLowerCase();
  const emailDomain = match[2]!.toLowerCase();

  const target = domainInfo(targetHost);
  if (target.isIp) return { status: 'ineligible', reason: 'ip_address' };
  if (target.isPlatformSuffix || !target.registrable) {
    return { status: 'ineligible', reason: 'platform_subdomain' };
  }

  const mail = domainInfo(emailDomain);
  if (FREE_MAIL_DOMAINS.has(emailDomain) || (mail.registrable && FREE_MAIL_DOMAINS.has(mail.registrable))) {
    return { status: 'ineligible', reason: 'free_mail' };
  }
  if (mail.isPlatformSuffix || mail.registrable !== target.registrable) {
    return { status: 'ineligible', reason: 'domain_mismatch' };
  }

  if (isSharedOrgSuffix(target.publicSuffix) && !ADMIN_LOCAL_PARTS.has(local)) {
    return { status: 'ineligible', reason: 'admin_only' };
  }
  return { status: 'eligible' };
}

/**
 * Issue a proof for an address whose login link has just been clicked.
 * Returns undefined when the address is not eligible for the host.
 */
export function confirmEmailOwnership(
  email: string,
  targetHost: string,
  now: number = Date.now(),
): OwnershipProof | undefined {
  if (evaluateEmailOwnership(email, targetHost).status !== 'eligible') return undefined;
  const registrable = domainInfo(targetHost).registrable;
  if (!registrable) return undefined;
  return issueProof('email', 'domain', registrable, now);
}
