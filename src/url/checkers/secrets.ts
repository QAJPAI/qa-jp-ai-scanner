// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { ConfirmedRecord, RecordFactory } from '../../core/records';
import { findSecrets, newSecretScanState, type SecretScanState } from '../../detect/secrets';
import { everythingRead, type UrlContext } from '../context';

/**
 * R02 — privileged keys shipped to the browser.
 * Passive: only inspects text the site already serves to every visitor.
 * Detection itself lives in src/detect/secrets.ts and is shared with the repo layer.
 */

export { JWT_PATTERN, jwtRole, MAX_SECRET_RECORDS, newSecretScanState, type SecretScanState } from '../../detect/secrets';

/** Scan one served text (HTML or a script) for privileged keys. */
export function scanTextForSecrets(
  sourceUrl: string,
  text: string,
  make: RecordFactory,
  state: SecretScanState = newSecretScanState(),
): ConfirmedRecord[] {
  return findSecrets(text, state).map((m) =>
    make.confirmed({
      ruleId: 'R02',
      code: m.code,
      severity: m.severity,
      key: m.key,
      location: `${sourceUrl} (offset ${m.index})`,
      evidence: m.evidence,
    }),
  );
}

export const secretsChecker: Checker<UrlContext> = {
  id: 'url.secrets',
  layer: 'url',
  mode: 'passive',
  rules: ['R02'],
  run(ctx, make) {
    const state = newSecretScanState();
    const records: ConfirmedRecord[] = [];
    for (const text of ctx.texts) {
      for (const record of scanTextForSecrets(text.url, text.body, make, state)) records.push(record);
      if (state.limitHit) break;
    }
    // Never "checked": a script whose name is put together at runtime is not seen. Say which limit applied.
    const note = state.limitHit
      ? 'record_limit_reached'
      : !everythingRead(ctx.load)
        ? 'some_content_not_read'
        : ctx.load.importsFollowed
          ? 'scripts_and_their_imports'
          : 'html_referenced_scripts_only';
    return { records, coverage: [{ ruleId: 'R02', status: 'partial', note }] };
  },
};
