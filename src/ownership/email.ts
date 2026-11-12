// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { domainInfo, issueProof, type OwnershipProof } from './proof';

/**
 * Method A — a mailbox on the site's own domain.
 *
 * This module only decides whether an address CAN prove ownership of a host.
 * Sending the login link and confirming the click is the service's job;
 * issueEmailProofAfterLinkClick() must be called only after that click.
 *
 * What this method does and does not establish: the person can read mail at
 * the site's own domain. In a small business that is the owner. In a large
 * organisation it is any member, which is why large shared domains are held to
 * admin mailboxes, and why a service should also notify the domain's admin
 * address whenever a detailed report is unlocked.
 */

export type EmailDecision =
  | { status: 'eligible' }
  | {
      status: 'ineligible';
      reason:
        | 'invalid'
        | 'domain_mismatch'
        | 'mailbox_not_on_main_domain'
        | 'free_mail'
        | 'platform_subdomain'
        | 'ip_address'
        | 'admin_only';
    };

/** The mailboxes certificate authorities accept for domain validation. Required here for large shared domains. */
const ADMIN_LOCAL_PARTS = new Set(['admin', 'administrator', 'webmaster', 'hostmaster', 'postmaster']);

/** Mail anyone can obtain: proves nothing about a website. */
const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.co.jp', 'yahoo.com', 'yahoo.ne.jp', 'ymail.com',
  'outlook.com', 'outlook.jp', 'outlook.co.jp', 'hotmail.com', 'hotmail.co.jp', 'live.com', 'live.jp', 'msn.com',
  'icloud.com', 'me.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com', 'pm.me',
  'gmx.com', 'gmx.net', 'zoho.com', 'mail.com', 'fastmail.com', 'fastmail.fm', 'yandex.com', 'yandex.ru',
  'qq.com', '163.com', '126.com', 'naver.com', 'hanmail.net', 'tutanota.com', 'tuta.io',
  'docomo.ne.jp', 'ezweb.ne.jp', 'au.com', 'softbank.ne.jp', 'i.softbank.jp', 'ymobile.ne.jp', 'uqmobile.jp',
  'rakuten.jp', 'rakumail.jp', 'nifty.com', 'biglobe.ne.jp', 'ocn.ne.jp', 'so-net.ne.jp', 'plala.or.jp',
  'dion.ne.jp', 'infoweb.ne.jp', 'asahi-net.or.jp', 'excite.co.jp', 'goo.jp', 'mail.goo.ne.jp',
]);

/**
 * Domains where many unrelated customers each get a subdomain, for the cases
 * the public suffix list does not (or may not) know. A site here has no
 * same-domain mailbox of its own, so it must use the verification file.
 */
const SHARED_HOSTING_DOMAINS = new Set([
  'xsrv.jp', 'lolipop.jp', 'sakura.ne.jp', 'heteml.jp', 'glitch.me', 'jimdofree.com', 'jimdosite.com',
  'studio.site', 'thebase.in', 'base.shop', 'stores.jp', 'kintone.com', 'cybozu.com', 'wixsite.com',
  'weebly.com', 'webnode.jp', 'peraichi.com', 'hp.peraichi.com', 'amebaownd.com', 'themedia.jp',
  'shopinfo.jp', 'storeinfo.jp', 'crayonsite.net', 'crayonsite.com', 'goope.jp', 'bubbleapps.io', 'replit.app',
  'lovable.app', 'netlify.app', 'vercel.app', 'pages.dev', 'web.app', 'firebaseapp.com', 'github.io',
]);

/** Suffix labels of large shared organisations (universities, government). */
const SHARED_ORG_LABELS = new Set(['ac', 'edu', 'go', 'gov', 'lg', 'ed', 'mil', 'sch']);
const SHARED_ORG_TLDS = new Set(['edu', 'gov', 'mil']);

const EMAIL = /^([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$/;

function isSharedOrgSuffix(publicSuffix: string | null): boolean {
  if (!publicSuffix) return false;
  const labels = publicSuffix.split('.');
  if (labels.length === 1) return SHARED_ORG_TLDS.has(labels[0]!);
  return SHARED_ORG_LABELS.has(labels[0]!);
}

export function evaluateEmailOwnership(email: string, targetHost: string): EmailDecision {
  const trimmed = email.trim();
  // 254 is the longest deliverable address; anything longer is not an address.
  if (trimmed.length > 254) return { status: 'ineligible', reason: 'invalid' };
  const match = EMAIL.exec(trimmed);
  if (!match) return { status: 'ineligible', reason: 'invalid' };
  const local = match[1]!.toLowerCase();
  const emailDomain = match[2]!.toLowerCase();

  const target = domainInfo(targetHost);
  if (target.isIp) return { status: 'ineligible', reason: 'ip_address' };
  if (target.isPlatformSuffix || !target.registrable || SHARED_HOSTING_DOMAINS.has(target.registrable)) {
    return { status: 'ineligible', reason: 'platform_subdomain' };
  }

  const mail = domainInfo(emailDomain);
  if (FREE_MAIL_DOMAINS.has(emailDomain) || (mail.registrable && FREE_MAIL_DOMAINS.has(mail.registrable))) {
    return { status: 'ineligible', reason: 'free_mail' };
  }
  if (mail.isPlatformSuffix || mail.registrable !== target.registrable) {
    return { status: 'ineligible', reason: 'domain_mismatch' };
  }
  // The mailbox must sit on the registrable domain itself. A provider that
  // gives each customer a mail subdomain (user@ma.isp.example) would otherwise
  // let one customer speak for every site under that provider's domain.
  if (emailDomain !== target.registrable) {
    return { status: 'ineligible', reason: 'mailbox_not_on_main_domain' };
  }

  if (isSharedOrgSuffix(target.publicSuffix) && !ADMIN_LOCAL_PARTS.has(local)) {
    return { status: 'ineligible', reason: 'admin_only' };
  }
  return { status: 'eligible' };
}

/**
 * Issue a proof for an address whose login link has just been clicked.
 *
 * The engine cannot see the click. Calling this without one grants access to
 * a site's security details to whoever typed an address: the caller is the
 * only safeguard. The proof covers the one host that was asked for, not the
 * whole domain.
 */
export function issueEmailProofAfterLinkClick(
  email: string,
  targetHost: string,
  now: number = Date.now(),
): OwnershipProof | undefined {
  if (evaluateEmailOwnership(email, targetHost).status !== 'eligible') return undefined;
  return issueProof('email', 'host', targetHost, now);
}
