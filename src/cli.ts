#!/usr/bin/env node
// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { validateAssessment } from './core/validate';
import { ownership as ownershipText } from './i18n/ja';
import { dnsRecordName, verifyByDns } from './ownership/dns';
import { verifyByFile } from './ownership/file';
import { ownershipSubject, type OwnershipProof } from './ownership/proof';
import { mintVerificationToken } from './ownership/token';
import { renderOwnerReport, renderPublicSummary, toPublicSummary } from './report';
import { closeAgents } from './url/net/fetcher';
import { normalizeTarget, scan } from './url/scan';

const USAGE = `Usage:
  qa-scan <url>                                  Public summary (passive checks only)
  qa-scan token <url> --account <id>             Show the ownership token and how to place it
  qa-scan <url> --account <id> --verify file|dns Verify ownership, then show the detailed report
  qa-scan validate <assessment.json>             Check that an assessment is well-formed and consistent

Options:
  --json   Print machine-readable output. Without verification this is the public
           summary only; the full assessment is printed only for a verified owner.

Environment:
  QA_JP_AI_SECRET   Secret used to derive ownership tokens (required for token / --verify)`;

const MAX_ASSESSMENT_BYTES = 5 * 1024 * 1024;

function tokenFor(account: string, host: string): string {
  const secret = process.env.QA_JP_AI_SECRET;
  if (!secret) throw new Error('QA_JP_AI_SECRET is not set');
  return mintVerificationToken(secret, account, ownershipSubject(host));
}

function validateFile(path: string): number {
  const raw = readFileSync(path);
  if (raw.length > MAX_ASSESSMENT_BYTES) {
    console.error(`File exceeds ${MAX_ASSESSMENT_BYTES} bytes`);
    return 1;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    console.error('Not valid JSON');
    return 1;
  }
  const errors = validateAssessment(parsed);
  if (errors.length === 0) {
    console.log('OK: well-formed and internally consistent. This does not prove its claims are true.');
    return 0;
  }
  for (const error of errors) console.error(`- ${error}`);
  return 1;
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      account: { type: 'string' },
      verify: { type: 'string' },
      json: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  if (values.help || positionals.length === 0) {
    console.log(USAGE);
    return values.help ? 0 : 2;
  }

  if (positionals[0] === 'validate') {
    if (!positionals[1]) {
      console.error(USAGE);
      return 2;
    }
    return validateFile(positionals[1]);
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

  const assessment = await scan(target.href, { proof });
  if (values.json) {
    console.log(JSON.stringify(proof ? assessment : toPublicSummary(assessment), null, 2));
  } else {
    console.log(proof ? renderOwnerReport(assessment) : renderPublicSummary(toPublicSummary(assessment)));
  }
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
