// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { BlockList, isIP } from 'node:net';
import { lookup as dnsLookup, type LookupAddress } from 'node:dns';

/**
 * SSRF guard. The scanner fetches URLs supplied by strangers, so it must never
 * be usable to reach loopback, private networks or cloud metadata endpoints.
 */

const blocked = new BlockList();

const V4_BLOCKED: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const V6_BLOCKED: Array<[string, number]> = [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
];

for (const [net, prefix] of V4_BLOCKED) blocked.addSubnet(net, prefix, 'ipv4');
for (const [net, prefix] of V6_BLOCKED) blocked.addSubnet(net, prefix, 'ipv6');

const V4_MAPPED = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;

export class BlockedAddressError extends Error {
  readonly code = 'QA_BLOCKED_ADDRESS';
  constructor(message: string) {
    super(message);
    this.name = 'BlockedAddressError';
  }
}

/** True when the address must not be contacted. Unparseable input is blocked. */
export function isBlockedAddress(address: string): boolean {
  const mapped = V4_MAPPED.exec(address);
  if (mapped?.[1]) return isBlockedAddress(mapped[1]);

  const family = isIP(address);
  if (family === 4) return blocked.check(address, 'ipv4');
  if (family === 6) {
    // Any other IPv4-mapped / IPv4-compatible form is refused outright.
    if (/^::ffff:/i.test(address)) return true;
    return blocked.check(address, 'ipv6');
  }
  return true;
}

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address?: string | LookupAddress[],
  family?: number,
) => void;

/**
 * Drop-in replacement for dns.lookup used at connect time. Validating here,
 * and not only before the request, closes the DNS-rebinding gap: the address
 * that is checked is the address that is connected to.
 */
export function guardedLookup(
  hostname: string,
  options: unknown,
  callback?: LookupCallback,
): void {
  const cb = (typeof options === 'function' ? options : callback) as LookupCallback;
  const opts = (typeof options === 'object' && options !== null ? options : {}) as {
    all?: boolean;
    family?: number;
    hints?: number;
  };

  dnsLookup(hostname, { family: opts.family, hints: opts.hints, all: true }, (err, addresses) => {
    if (err) return cb(err);
    if (addresses.length === 0) {
      return cb(new BlockedAddressError(`No address found for ${hostname}`));
    }
    const bad = addresses.find((a) => isBlockedAddress(a.address));
    if (bad) {
      return cb(new BlockedAddressError(`${hostname} resolves to a non-public address`));
    }
    if (opts.all) return cb(null, addresses);
    const first = addresses[0]!;
    cb(null, first.address, first.family);
  });
}
