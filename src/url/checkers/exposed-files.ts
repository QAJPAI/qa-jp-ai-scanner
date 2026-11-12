// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { ConfirmedRecord } from '../../core/records';
import { evidence } from '../../i18n/ja';
import type { UrlContext } from '../context';
import { safeFetch, type FetchOptions } from '../net/fetcher';

/**
 * R11 — debug information and internal files reachable from outside.
 *
 * ACTIVE: requests specific paths a normal visitor would not load, so it runs
 * only for a verified owner.
 * Detect-only: reads a few KB to confirm the file format, then keeps a boolean
 * and a count. File contents are never stored or reported.
 */

const PROBE_BYTES = 4096;
const MAX_SOURCEMAPS = 5;

const SOURCEMAP_COMMENT = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/;
const ENV_LINE = /^[A-Za-z_][A-Za-z0-9_]*\s*=/gm;

interface Probe {
  status: number;
  contentType: string;
  body: string;
}

async function probe(url: string, options: FetchOptions): Promise<Probe | undefined> {
  try {
    const res = await safeFetch(url, { ...options, maxBytes: PROBE_BYTES, sameHostRedirectsOnly: true });
    return {
      status: res.status,
      contentType: (res.headers['content-type']?.[0] ?? '').toLowerCase(),
      body: res.body,
    };
  } catch {
    return undefined; // unreachable is not a finding
  }
}

/** Single-page apps answer every path with index.html; that is not exposure. */
function looksLikeHtml(p: Probe): boolean {
  return p.contentType.includes('text/html') || p.body.trimStart().startsWith('<');
}

export const exposedFilesChecker: Checker<UrlContext> = {
  id: 'url.exposed-files',
  layer: 'url',
  mode: 'active',
  rules: ['R11'],
  async run(ctx, make) {
    const origin = ctx.finalUrl.origin;
    const records: ConfirmedRecord[] = [];

    const envUrl = new URL('/.env', origin);
    const env = await probe(envUrl.href, ctx.fetch);
    if (env && env.status === 200 && !looksLikeHtml(env)) {
      const keyCount = env.body.match(ENV_LINE)?.length ?? 0;
      if (keyCount > 0) {
        records.push(
          make.confirmed({
            ruleId: 'R11',
            code: 'exposed.env',
            severity: 'P0', // keys in the file must be treated as leaked: same impact as R02
            key: envUrl.pathname,
            location: envUrl.href,
            evidence: evidence.envExposed(keyCount),
          }),
        );
      }
    }

    const gitUrl = new URL('/.git/HEAD', origin);
    const git = await probe(gitUrl.href, ctx.fetch);
    if (git && git.status === 200 && !looksLikeHtml(git)) {
      const head = git.body.trim();
      if (head.startsWith('ref: refs/') || /^[0-9a-f]{40}$/.test(head)) {
        records.push(
          make.confirmed({
            ruleId: 'R11',
            code: 'exposed.git',
            severity: 'P1',
            key: gitUrl.pathname,
            location: gitUrl.href,
            evidence: evidence.gitExposed(),
          }),
        );
      }
    }

    let checked = 0;
    for (const script of ctx.scripts) {
      if (checked >= MAX_SOURCEMAPS) break;
      const ref = SOURCEMAP_COMMENT.exec(script.body.slice(-512).trimEnd())?.[1];
      if (!ref || ref.startsWith('data:')) continue;

      let mapUrl: URL;
      try {
        mapUrl = new URL(ref, script.url);
      } catch {
        continue;
      }
      if (mapUrl.hostname !== ctx.finalUrl.hostname) continue;
      checked++;

      const map = await probe(mapUrl.href, ctx.fetch);
      if (map && map.status === 200 && map.body.trimStart().startsWith('{') && map.body.includes('"version"')) {
        records.push(
          make.confirmed({
            ruleId: 'R11',
            code: 'exposed.sourcemap',
            severity: 'P2',
            key: mapUrl.pathname,
            location: mapUrl.href,
            evidence: evidence.sourcemapExposed(),
          }),
        );
      }
    }

    return { records, coverage: [{ ruleId: 'R11', status: 'checked' }] };
  },
};
