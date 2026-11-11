// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { resolveTxt as nodeResolveTxt } from 'node:dns/promises';
import { domainInfo, issueProof, type OwnershipProof } from './proof';
import { tokensEqual } from './token';

/** Method C — a DNS TXT record, for people comfortable with DNS. */

export const DNS_RECORD_LABEL = '_qa-jp-ai';

export type TxtResolver = (name: string) => Promise<string[][]>;

export function dnsRecordName(targetHost: string): string | undefined {
  const info = domainInfo(targetHost);
  if (info.isIp || !info.registrable) return undefined;
  return `${DNS_RECORD_LABEL}.${info.registrable}`;
}

export async function verifyByDns(
  targetHost: string,
  expectedToken: string,
  resolveTxt: TxtResolver = nodeResolveTxt,
  now: number = Date.now(),
): Promise<OwnershipProof | undefined> {
  const name = dnsRecordName(targetHost);
  const registrable = domainInfo(targetHost).registrable;
  if (!name || !registrable) return undefined;

  let records: string[][];
  try {
    records = await resolveTxt(name);
  } catch {
    return undefined;
  }
  const found = records.some((chunks) => tokensEqual(chunks.join('').trim(), expectedToken));
  return found ? issueProof('dns', 'domain', registrable, now) : undefined;
}
