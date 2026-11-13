#!/usr/bin/env node
// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { BaselineError, loadBaseline, readAssessmentFile, saveBaseline } from './baseline';
import type { Assessment } from './core/assessment';
import { compareAssessments, ComparisonError, type Comparison } from './core/compare';
import { SEVERITIES, type Severity } from './core/types';
import { validateAssessment } from './core/validate';
import { renderFixRequest } from './fixrequest';
import { renderHandoff } from './handoff';
import { comparison as comparisonText, fixRequest as fixRequestText, ownership as ownershipText, scanErrorText } from './i18n/ja';
import { dnsRecordName, verifyByDns } from './ownership/dns';
import { verifyByFile } from './ownership/file';
import { ownershipSubject, type OwnershipProof } from './ownership/proof';
import { mintVerificationToken } from './ownership/token';
import { inspectRepo } from './repo/scan';
import { renderComparison } from './recheck';
import { renderLocalReport, renderOwnerReport, renderPublicSummary } from './report';
import { closeAgents } from './url/net/fetcher';
import { BlockedAddressError } from './url/net/guard';
import { normalizeTarget, ScanError, scanOwner, scanPublic } from './url/scan';

const USAGE = `Usage:
  qa-scan check [folder]                         Pre-deployment check of your own source code (default: current folder)
      --for-ai                                   Output a hand-off for an AI coding tool instead of the report
      --fix-request                              Output a fix request to paste into an AI coding tool (saves the result)
      --baseline                                 Save this result, to compare with after fixing
      --compare                                  Compare with the saved result: which problems are confirmed fixed
      --since <assessment.json>                  Compare with this earlier result instead of the saved one
      --fail-on P0|P1|P2                         Exit with code 3 if a confirmed problem of this level or worse is found
  qa-scan <url>                                  Public summary (passive checks only)
  qa-scan token <url> --account <id>             Show the ownership token and how to place it
  qa-scan <url> --account <id> --verify file|dns Verify ownership, then show the detailed report
  qa-scan validate <assessment.json>             Check that an assessment is well-formed and consistent

Exit codes: 0 done, 1 error, 2 usage, 3 problems found at the --fail-on level.

Saved results go to the user's cache folder (never into the project), one per project.

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

interface CheckFlags {
  json?: boolean;
  'for-ai'?: boolean;
  'fail-on'?: string;
  'fix-request'?: boolean;
  baseline?: boolean;
  compare?: boolean;
  since?: string;
}

/** The earlier result to compare with, or a message saying why there is none. */
function previousResult(folder: string, since: string | undefined): Assessment | string {
  try {
    return since ? readAssessmentFile(since) : loadBaseline(folder);
  } catch (err) {
    if (!(err instanceof BaselineError)) throw err;
    if (since) return err.code === 'not_found' ? comparisonText.sinceNotFound : comparisonText.invalidBaseline;
    return err.code === 'not_found' ? comparisonText.noBaseline : comparisonText.invalidBaseline;
  }
}

async function check(folder: string, values: CheckFlags): Promise<number> {
  const failOn = values['fail-on']?.toUpperCase();
  if (failOn !== undefined && !(SEVERITIES as readonly string[]).includes(failOn)) {
    console.error('--fail-on must be P0, P1 or P2');
    return 2;
  }
  const formats = [values.json, values['for-ai'], values['fix-request']].filter(Boolean).length;
  const comparing = Boolean(values.compare || values.since);
  if (formats > 1 || (values.compare && values.since) || (comparing && (values.baseline || values['fix-request']))) {
    console.error('Choose one of --json, --for-ai, --fix-request; --compare/--since cannot be combined with saving.');
    return 2;
  }

  // Reads files only: no code is run and nothing is sent anywhere.
  const { assessment, filesRead } = await inspectRepo(folder);

  let comparison: Comparison | undefined;
  if (comparing) {
    const previous = previousResult(folder, values.since);
    if (typeof previous === 'string') {
      console.error(previous);
      return 1;
    }
    try {
      comparison = compareAssessments(previous, assessment, { wasRead: (path) => filesRead.has(path) });
    } catch (err) {
      if (!(err instanceof ComparisonError)) throw err;
      console.error(comparisonText.differentTarget);
      return 1;
    }
  }

  const save = Boolean(values.baseline || values['fix-request']);
  if (save) {
    try {
      saveBaseline(folder, assessment);
    } catch (err) {
      console.error(err instanceof BaselineError ? comparisonText.unsafeLocation : String(err));
      return 1;
    }
    // On stderr, so the text meant for the AI stays clean on stdout.
    console.error(fixRequestText.savedNote);
  }

  if (values.json) console.log(JSON.stringify(comparison ? { comparison, assessment } : assessment, null, 2));
  else if (values['fix-request']) console.log(renderFixRequest(assessment));
  else if (values['for-ai']) console.log(renderHandoff(assessment, { comparison, baselineSaved: save }));
  else if (comparison) console.log(renderComparison(comparison, assessment));
  else console.log(renderLocalReport(assessment));

  if (failOn) {
    const threshold = SEVERITIES.indexOf(failOn as Severity);
    const hit = assessment.records.some((r) => r.verdict === 'confirmed' && SEVERITIES.indexOf(r.severity) <= threshold);
    if (hit) return 3;
  }
  return 0;
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      account: { type: 'string' },
      verify: { type: 'string' },
      json: { type: 'boolean' },
      'for-ai': { type: 'boolean' },
      'fail-on': { type: 'string' },
      'fix-request': { type: 'boolean' },
      baseline: { type: 'boolean' },
      compare: { type: 'boolean' },
      since: { type: 'string' },
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

  if (positionals[0] === 'check') return check(positionals[1] ?? '.', values);

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

  if (proof) {
    const assessment = await scanOwner(target.href, proof);
    console.log(values.json ? JSON.stringify(assessment, null, 2) : renderOwnerReport(assessment, proof));
  } else {
    const summary = await scanPublic(target.href);
    console.log(values.json ? JSON.stringify(summary, null, 2) : renderPublicSummary(summary));
  }
  return 0;
}

/** What the requester is told. Internal detail (resolved addresses, stack traces) stays out. */
function publicMessage(err: unknown): string {
  if (err instanceof ScanError) return scanErrorText[err.code] ?? scanErrorText.generic!;
  if (err instanceof BlockedAddressError) return scanErrorText.blocked!;
  if (err instanceof Error && (err as { cause?: unknown }).cause instanceof BlockedAddressError) {
    return scanErrorText.blocked!;
  }
  return err instanceof Error ? err.message : String(err);
}

main()
  .then(async (code) => {
    await closeAgents();
    process.exitCode = code;
  })
  .catch(async (err: unknown) => {
    await closeAgents();
    console.error(publicMessage(err));
    process.exitCode = 1;
  });
