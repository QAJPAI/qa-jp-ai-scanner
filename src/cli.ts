#!/usr/bin/env node
// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { parseArgs } from 'node:util';
import { closeAgents } from './net/fetcher';
import { ownership as ownershipText } from './i18n/ja';
import { dnsRecordName, verifyByDns } from './ownership/dns';
import { verifyByFile } from './ownership/file';
import { ownershipSubject, type OwnershipProof } from './ownership/proof';
import { mintVerificationToken } from './ownership/token';
import { renderOwnerReport, renderPublicSummary, toPublicSummary } from './report';
import { normalizeTarget, scan } from './scanner';

const USAGE = `Usage:
  qa-scan <url>                                  Public summary (passive checks only)
  qa-scan token <url> --account <id>             Show the ownership token and how to place it
  qa-scan <url> --account <id> --verify file|dns Verify ownership, then show the detailed report

Environment:
  QA_JP_AI_SECRET   Secret used to derive ownership tokens (required for token / --verify)`;

function tokenFor(account: string, host: string): string {
  const secret = process.env.QA_JP_AI_SECRET;
  if (!secret) throw new Error('QA_JP_AI_SECRET is not set');
  return mintVerificationToken(secret, account, ownershipSubject(host));
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      account: { type: 'string' },
      verify: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  if (values.help || positionals.length === 0) {
    console.log(USAGE);
    return values.help ? 0 : 2;
  }

  if (positionals[0] === 'token') {
    const input = positionals[1];
    if (!input || !values.account) {
      console.error(USAGE);
      return 2;
    }
    const target = normalizeTarget(input);
    const token = tokenFor(values.account, target.hostname);
    console.log(ownershipText.aiPrompt(token));
    const record = dnsRecordName(target.hostname);
    if (record) console.log(`\n---\n${ownershipText.dnsInstruction(record, token)}`);
    return 0;
  }

  const target = normalizeTarget(positionals[0]!);

  let proof: OwnershipProof | undefined;
  if (values.verify) {
    if (!values.account) {
      console.error('--verify requires --account');
      return 2;
    }
    const token = tokenFor(values.account, target.hostname);
    if (values.verify === 'file') proof = await verifyByFile(target.origin, token);
    else if (values.verify === 'dns') proof = await verifyByDns(target.hostname, token);
    else {
      console.error('--verify must be "file" or "dns"');
      return 2;
    }
    if (!proof) {
      console.error('所有者確認ができませんでした。確認ファイルまたは DNS レコードをご確認ください。');
      return 1;
    }
  }

  const result = await scan(target.href, { proof });
  console.log(proof ? renderOwnerReport(result) : renderPublicSummary(toPublicSummary(result)));
  return 0;
}

main()
  .then(async (code) => {
    await closeAgents();
    process.exitCode = code;
  })
  .catch(async (err: unknown) => {
    await closeAgents();
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
