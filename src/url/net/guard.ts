// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { BlockList, isIP } from 'node:net';
import { lookup as dnsLookup, type LookupAddress } from 'node:dns';

/**
 * SSRF guard. The scanner fetches URLs supplied by strangers, so it must never
 * be usable to reach loopback, private networks or cloud metadata endpoints.
 */

const v4Blocked = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  v4Blocked.addSubnet(net, prefix, 'ipv4');
}

/**
 * IPv6 is an allow-list: only global unicast (2000::/3), minus the ranges
 * inside it that tunnel or translate to IPv4 or are reserved. Everything else
 * — loopback, link-local, unique-local, NAT64, IPv4-compatible forms — is
 * refused without having to be enumerated.
 */
const v6Global = new BlockList();
v6Global.addSubnet('2000::', 3, 'ipv6');

const v6Special = new BlockList();
for (const [net, prefix] of [
  ['2001::', 23], // IETF protocol assignments, including Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4: embeds an IPv4 address
  ['3fff::', 20], // documentation
] as const) {
  v6Special.addSubnet(net, prefix, 'ipv6');
}

const V4_MAPPED = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;

/**
 * Thrown for anything the guard refuses. The message is deliberately the same
 * for every cause: a public service must not let a stranger learn which names
 * resolve inside the operator's network. The cause is in `detail`, for logs.
 */
export class BlockedAddressError extends Error {
  readonly code = 'QA_BLOCKED_ADDRESS';
  readonly detail: string;
  constructor(detail: string) {
    super('This address cannot be scanned');
    this.name = 'BlockedAddressError';
    this.detail = detail;
  }
}

/** True when the address must not be contacted. Unparseable input is blocked. */
export function isBlockedAddress(address: string): boolean {
  const mapped = V4_MAPPED.exec(address);
  if (mapped?.[1]) return isBlockedAddress(mapped[1]);

  const family = isIP(address);
  if (family === 4) return v4Blocked.check(address, 'ipv4');
  if (family === 6) {
    // Any other IPv4-mapped spelling is refused outright.
    if (/^::ffff:/i.test(address)) return true;
    return !v6Global.check(address, 'ipv6') || v6Special.check(address, 'ipv6');
  }
  return true;
}

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address?: string | LookupAddress[],
  family?: number,
) => void;

type Resolve = (
  hostname: string,
  options: { family?: number; hints?: number; all: true },
  callback: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void,
) => void;

/**
 * Build a drop-in replacement for dns.lookup used at connect time. Validating
 * here, and not only before the request, closes the DNS-rebinding gap: the
 * address that is checked is the address that is connected to. If ANY resolved
 * address is non-public the name is refused.
 */
export function makeGuardedLookup(resolve: Resolve = dnsLookup as Resolve) {
  return function guardedLookup(hostname: string, options: unknown, callback?: LookupCallback): void {
    const cb = (typeof options === 'function' ? options : callback) as LookupCallback;
    const opts = (typeof options === 'object' && options !== null ? options : {}) as {
      all?: boolean;
      family?: number;
      hints?: number;
    };

    resolve(hostname, { family: opts.family, hints: opts.hints, all: true }, (err, addresses) => {
      if (err) return cb(new BlockedAddressError(`lookup failed for ${hostname}: ${err.code ?? err.message}`));
      if (addresses.length === 0) return cb(new BlockedAddressError(`no address for ${hostname}`));
      if (addresses.some((a) => isBlockedAddress(a.address))) {
        return cb(new BlockedAddressError(`${hostname} resolves to a non-public address`));
      }
      if (opts.all) return cb(null, addresses);
      const first = addresses[0]!;
      cb(null, first.address, first.family);
    });
  };
}

export const guardedLookup = makeGuardedLookup();
