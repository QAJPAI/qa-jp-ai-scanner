// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { AssessmentRecord } from '../../core/records';
import { findSecrets, isPlaceholder, newSecretScanState } from '../../detect/secrets';
import { evidence } from '../../i18n/ja';
import { baseName, everythingReadInRepo, isTestPath, lineAt, type RepoContext, type RepoFile } from '../context';
import { ignoreMatcher } from '../gitignore';

/**
 * R02 in source code, before deployment. Three ways a key ends up public:
 *
 * 1. secret.<kind>          a key written directly into a file that will be committed.
 * 2. secret.public_env_name a key given an environment-variable name that the
 *                           build tool copies into browser code (VITE_, NEXT_PUBLIC_ …).
 *                           Found from the .env definition or from a reference in code;
 *                           the value itself may live only in a hosting dashboard.
 * 3. secret.env_not_ignored an env file holding secrets that .gitignore does not exclude.
 *
 * Values are never recorded: evidence carries a variable name or a redacted prefix.
 *
 * Tests and fixtures are not shipped and are often full of deliberately fake
 * keys. A key-shaped value there is handed to the owner (needs_validation:
 * fake is fine, real must be revoked) instead of being reported as a leak,
 * and variable names referenced from tests are not app code.
 */

/** Prefixes whose variables are inlined into client bundles by common build tools. */
const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|VITE|PUBLIC|REACT_APP|GATSBY|VUE_APP)_/;
const PUBLIC_REFERENCE = /\b(?:NEXT_PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|VITE|PUBLIC|REACT_APP|GATSBY|VUE_APP)_[A-Z0-9_]{1,100}\b/g;

/** Names that denote a secret whatever their value. */
const SECRET_NAME = [
  /(?:^|_)(?:SERVICE_ROLE|SECRET|PRIVATE_KEY|PASSWORD|PASSWD|DATABASE_URL|DB_URL|ACCESS_TOKEN|AUTH_TOKEN|REFRESH_TOKEN)(?:$|_)/,
  /(?:^|_)(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|DEEPSEEK|COHERE|XAI|PERPLEXITY|REPLICATE|HUGGINGFACE|HF|ELEVENLABS|SENDGRID|RESEND|MAILGUN|TWILIO|SLACK|GITHUB)_(?:API_)?(?:KEY|TOKEN|SECRET)(?:$|_)/,
];
/** Names that are public by design even if they contain a word above. */
const PUBLIC_BY_DESIGN = /PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|CLIENT_ID|MEASUREMENT_ID|APP_ID/;

export function isSecretName(name: string): boolean {
  const rest = name.toUpperCase().replace(PUBLIC_PREFIX, '');
  if (PUBLIC_BY_DESIGN.test(rest)) return false;
  return SECRET_NAME.some((pattern) => pattern.test(rest));
}

const ENV_FILE = /^\.env(?:\..+)?$/;
/** Committed on purpose, as documentation: scan them like any other file. */
const ENV_TEMPLATE = /(?:example|sample|template|dist|defaults?)$/i;
const CODE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?)$/i;

const isEnvFile = (path: string) => ENV_FILE.test(baseName(path));
const isEnvTemplate = (path: string) => isEnvFile(path) && ENV_TEMPLATE.test(baseName(path));

interface EnvEntry {
  name: string;
  value: string;
  line: number;
}

const ENV_LINE = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]{0,127})[ \t]*=[ \t]*(.*)$/;
const MAX_ENV_LINES = 10_000;

export function parseEnv(text: string): EnvEntry[] {
  const entries: EnvEntry[] = [];
  const lines = text.split('\n', MAX_ENV_LINES);
  lines.forEach((raw, i) => {
    const m = ENV_LINE.exec(raw.replace(/\r$/, ''));
    if (!m) return;
    let value = m[2]!.trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.length >= 2 && value.endsWith(quote)) value = value.slice(1, -1);
    else value = value.replace(/[ \t]+#.*$/, '');
    entries.push({ name: m[1]!, value, line: i + 1 });
  });
  return entries;
}

/** A value worth protecting: not empty, not a placeholder, or shaped like a known key. */
function holdsSecret(entry: EnvEntry): boolean {
  if (findSecrets(entry.value).length > 0) return true;
  return isSecretName(entry.name) && entry.value.length >= 8 && !isPlaceholder(entry.value);
}

export const repoSecretsChecker: Checker<RepoContext> = {
  id: 'repo.secrets',
  layer: 'repo',
  mode: 'passive',
  rules: ['R02'],
  run(ctx, make) {
    const records: AssessmentRecord[] = [];
    const state = newSecretScanState();
    const ignore = ignoreMatcher(ctx);
    const at = (file: RepoFile, line: number) => `${file.path}:${line}`;

    // One record per variable name, at its first occurrence.
    const namesSeen = new Set<string>();
    const publicName = (name: string, file: RepoFile, index: number | { line: number }, valueIsKey: boolean) => {
      if (namesSeen.has(name)) return;
      namesSeen.add(name);
      const line = typeof index === 'number' ? lineAt(file.text, index) : index.line;
      records.push(
        make.confirmed({
          ruleId: 'R02',
          code: 'secret.public_env_name',
          severity: 'P0',
          key: `env:${name}`,
          location: at(file, line),
          evidence: valueIsKey ? evidence.publicEnvWithKey(name) : evidence.publicEnvName(name),
        }),
      );
    };

    for (const file of ctx.files) {
      if (state.limitHit) break;

      if (isEnvFile(file.path)) {
        const template = isEnvTemplate(file.path);
        let secrets = 0;
        for (const entry of parseEnv(file.text)) {
          // Template values are placeholders; a real key in a template is caught by the full-text scan below.
          const valueIsKey = !template && findSecrets(entry.value).length > 0;
          // A secret under a browser-exposed name is a design error, whatever the value is today.
          if (PUBLIC_PREFIX.test(entry.name) && (isSecretName(entry.name) || valueIsKey)) {
            publicName(entry.name, file, { line: entry.line }, valueIsKey);
          }
          if (!template && holdsSecret(entry)) secrets++;
        }
        if (!template) {
          // A real env file is the right place for secrets, as long as git ignores it.
          if (secrets > 0 && !ignore.isIgnored(file.path)) {
            records.push(
              make.confirmed({
                ruleId: 'R02',
                code: 'secret.env_not_ignored',
                severity: 'P0',
                key: `envfile:${file.path}`,
                location: file.path,
                evidence: evidence.envNotIgnored(secrets),
              }),
            );
          }
          continue;
        }
      }

      // Every other file is committed: a key written in it is leaked — unless it is a test's fake.
      const inTest = isTestPath(file.path);
      for (const match of findSecrets(file.text, state)) {
        const input = {
          ruleId: 'R02' as const,
          key: match.key,
          location: at(file, lineAt(file.text, match.index)),
          evidence: match.evidence,
        };
        records.push(
          inTest
            ? make.needsValidation({ ...input, code: 'secret.in_test_file', blocker: 'requires_owner_intent' })
            : make.confirmed({ ...input, code: match.code, severity: match.severity }),
        );
      }

      // Code that reads a secret through a browser-exposed variable name.
      if (CODE_FILE.test(file.path) && !inTest) {
        PUBLIC_REFERENCE.lastIndex = 0;
        for (const m of file.text.matchAll(PUBLIC_REFERENCE)) {
          if (isSecretName(m[0])) publicName(m[0], file, m.index, false);
        }
      }
    }

    const note = state.limitHit
      ? 'record_limit_reached'
      : everythingReadInRepo(ctx.load)
        ? undefined
        : 'some_files_not_read';
    return {
      records,
      coverage: [note ? { ruleId: 'R02', status: 'partial', note } : { ruleId: 'R02', status: 'checked' }],
    };
  },
};
