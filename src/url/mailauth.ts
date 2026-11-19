// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { Resolver } from 'node:dns/promises';
import { domainInfo } from '../ownership/proof';

/**
 * Mail authentication (SPF, DMARC) of the site's domain, read from public DNS.
 *
 * Not the website itself, but its reputation: without these, anyone can send
 * mail that claims to come from this domain, and the receiving side cannot tell
 * it is forged. For a small business, its mail is its name.
 *
 * Only public TXT records are read, through the server's own resolver; nothing
 * is sent to the site.
 *
 * "No record" is only believed from a resolver that can see the domain at all:
 * every live domain has NS records, so they are asked for as a control. A
 * filtered or broken resolver that answers "no data" to everything would
 * otherwise make us tell the public that a domain has no DMARC when it does.
 */

export type TxtResolver = (name: string) => Promise<string[][]>;
export type NsResolver = (name: string) => Promise<string[]>;

/** The DNS questions mail authentication asks (tests pass their own). */
export interface MailDns {
  txt: TxtResolver;
  ns: NsResolver;
}

export interface TxtLookup {
  /** found: records exist; none: the name has no TXT records; failed: no answer. */
  status: 'found' | 'none' | 'failed';
  records: string[];
}

export interface MailAuthFacts {
  domain: string;
  spf: TxtLookup;
  dmarc: TxtLookup;
}

/** Codes that mean "there is no such record", as opposed to "no answer". */
const NO_RECORD = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN']);
const MAX_RECORDS = 20;
const MAX_RECORD_LENGTH = 2048;

let defaultResolver: Resolver | undefined;
const system = (): Resolver => (defaultResolver ??= new Resolver({ timeout: 3000, tries: 1 }));
const systemDns: MailDns = {
  txt: (name) => system().resolveTxt(name),
  ns: (name) => system().resolveNs(name),
};

/**
 * The domain whose mail settings apply to a host: its registrable domain.
 * Undefined where the owner cannot set DNS records (an IP address, a hosting
 * platform's shared domain).
 */
export function mailDomainFor(hostname: string): string | undefined {
  const info = domainInfo(hostname);
  if (info.isIp || info.isPlatformSuffix || !info.registrable) return undefined;
  return info.registrable;
}

async function lookup(resolveTxt: TxtResolver, name: string): Promise<TxtLookup> {
  try {
    const answer = await resolveTxt(name);
    const records = answer
      .slice(0, MAX_RECORDS)
      .map((chunks) => chunks.join('').slice(0, MAX_RECORD_LENGTH).trim())
      .filter(Boolean);
    return { status: records.length > 0 ? 'found' : 'none', records };
  } catch (err) {
    const code = (err as { code?: string }).code;
    return { status: code && NO_RECORD.has(code) ? 'none' : 'failed', records: [] };
  }
}

async function resolverSeesDomain(ns: NsResolver, domain: string): Promise<boolean> {
  try {
    return (await ns(domain)).length > 0;
  } catch {
    return false;
  }
}

export async function lookUpMailAuth(domain: string, dns: MailDns = systemDns): Promise<MailAuthFacts> {
  const [seen, spf, dmarc] = await Promise.all([
    resolverSeesDomain(dns.ns, domain),
    lookup(dns.txt, domain),
    lookup(dns.txt, `_dmarc.${domain}`),
  ]);
  // A record that was returned is evidence either way; an absence is evidence
  // only from a resolver that passed the control.
  const trusted = (l: TxtLookup): TxtLookup => (seen || l.status !== 'none' ? l : { status: 'failed', records: [] });
  return { domain, spf: trusted(spf), dmarc: trusted(dmarc) };
}

/** Records of one kind ("v=spf1", "v=DMARC1"): the tag must be the first term. */
export function recordsOf(lookup: TxtLookup, version: 'v=spf1' | 'v=DMARC1'): string[] {
  const head = new RegExp(`^${version.replace('=', '\\s*=\\s*')}(?:\\s|;|$)`, 'i');
  return lookup.records.filter((r) => head.test(r));
}

/** The qualifier of SPF's final "all", or undefined when there is none (and no redirect). */
export function spfAll(record: string): '+' | '-' | '~' | '?' | 'none' | 'redirect' {
  const terms = record.split(/\s+/).slice(1);
  for (const term of terms) {
    const m = /^([+\-~?]?)all$/i.exec(term);
    if (m) return ((m[1] || '+') as '+' | '-' | '~' | '?');
  }
  return terms.some((t) => /^redirect=/i.test(t)) ? 'redirect' : 'none';
}

/** DMARC's p= policy, lower-cased, or undefined. */
export function dmarcPolicy(record: string): string | undefined {
  const m = /(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(record);
  return m?.[1]?.toLowerCase();
}
