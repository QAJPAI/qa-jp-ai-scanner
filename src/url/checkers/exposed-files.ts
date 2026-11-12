// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomBytes } from 'node:crypto';
import type { Checker } from '../../core/checker';
import type { CoverageReport } from '../../core/coverage';
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

const PROBE_BYTES = 8192;
const MAX_SOURCEMAPS = 5;

const ENV_PATHS = ['/.env', '/.env.local', '/.env.production'];
const SOURCEMAP_COMMENT = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/;
const ENV_LINE = /^(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=/gm;
/** Build tools put a content hash in asset names; it changes on every build. */
const ASSET_HASH = /[-.][A-Za-z0-9_]{6,}(?=\.(?:m?js|css)\.map$)/;

interface Probe {
  status: number;
  contentType: string;
  body: string;
}

/** undefined = the question could not be asked (network error, timeout). */
async function probe(url: string, options: FetchOptions): Promise<Probe | undefined> {
  try {
    const res = await safeFetch(url, { ...options, maxBytes: PROBE_BYTES, sameHostRedirectsOnly: true });
    return {
      status: res.status,
      contentType: (res.headers['content-type']?.[0] ?? '').toLowerCase(),
      body: res.body,
    };
  } catch {
    return undefined;
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
    let asked = 0;
    let unanswered = 0;

    const ask = async (url: string): Promise<Probe | undefined> => {
      asked++;
      const result = ctx.outOfTime() ? undefined : await probe(url, ctx.fetch);
      if (!result) unanswered++;
      return result;
    };

    // A server that answers every path the same way exposes nothing by doing so.
    // Ask for a path that cannot exist and discard any probe that gets the same answer.
    const control = await ask(new URL(`/.qa-jp-ai-control-${randomBytes(8).toString('hex')}`, origin).href);
    const real = (p: Probe | undefined): p is Probe =>
      p !== undefined && p.status === 200 && !looksLikeHtml(p) && !(control?.status === 200 && control.body === p.body);

    for (const path of ENV_PATHS) {
      const url = new URL(path, origin);
      const env = await ask(url.href);
      if (!real(env)) continue;
      const keyCount = env.body.match(ENV_LINE)?.length ?? 0;
      if (keyCount > 0) {
        records.push(
          make.confirmed({
            ruleId: 'R11',
            code: 'exposed.env',
            severity: 'P0', // keys in the file must be treated as leaked: same impact as R02
            key: url.pathname,
            location: url.href,
            evidence: evidence.envExposed(keyCount),
          }),
        );
      }
    }

    const gitUrl = new URL('/.git/HEAD', origin);
    const git = await ask(gitUrl.href);
    if (real(git)) {
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

      const map = await ask(mapUrl.href);
      // A real source map is a JSON object with a numeric version and a mappings field.
      if (real(map) && map.body.trimStart().startsWith('{') && /"version"\s*:\s*\d/.test(map.body) && map.body.includes('"mappings"')) {
        records.push(
          make.confirmed({
            ruleId: 'R11',
            code: 'exposed.sourcemap',
            severity: 'P2',
            key: mapUrl.pathname.replace(ASSET_HASH, ''),
            location: mapUrl.href,
            evidence: evidence.sourcemapExposed(),
          }),
        );
      }
    }

    // "Could not ask" is not "not there".
    const coverage: CoverageReport =
      unanswered === 0
        ? { ruleId: 'R11', status: 'checked' }
        : unanswered === asked
          ? { ruleId: 'R11', status: 'error' }
          : { ruleId: 'R11', status: 'partial', note: 'some_probes_failed' };
    return { records, coverage: [coverage] };
  },
};
