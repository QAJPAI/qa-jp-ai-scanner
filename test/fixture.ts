// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Route {
  status?: number;
  headers?: Record<string, string | string[]>;
  body?: string;
  /** Wait this long before answering. */
  delayMs?: number;
  /** Drop the connection without answering. */
  destroy?: boolean;
}

export interface Fixture {
  port: number;
  origin: string;
  /** Every path requested, in order — lets tests prove what was NOT probed. */
  requests: string[];
  close: () => Promise<void>;
}

/** Local site for tests. `fallback` emulates an SPA answering every path. */
export async function startFixture(routes: Record<string, Route>, fallback?: Route): Promise<Fixture> {
  const requests: string[] = [];
  const server: Server = createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0]!;
    requests.push(path);
    const route = routes[path] ?? fallback ?? { status: 404, body: 'not found' };
    if (route.destroy) {
      req.socket.destroy();
      return;
    }
    const answer = () => {
      res.writeHead(route.status ?? 200, { 'content-type': 'text/plain', ...route.headers });
      res.end(route.body ?? '');
    };
    if (route.delayMs) setTimeout(answer, route.delayMs);
    else answer();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    origin: `http://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

const VARIED = 'Ab3Cd5Ef7Gh9Jk2Mn4Pq6Rs8Tu1Vw0XyZ';

/**
 * A string with the character variety of a real random key, so it is not
 * mistaken for a documentation placeholder. `seed` gives distinct values.
 */
export function varied(length: number, seed = 0, alphabet = VARIED): string {
  // A small deterministic generator: the same seed always gives the same string.
  let x = (Math.imul(seed + 1, 2654435761) + 1013904223) >>> 0;
  let out = '';
  for (let i = 0; i < length; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out += alphabet[(x >>> 16) % alphabet.length];
  }
  return out;
}

/** A private-key header, assembled so the literal never sits in the repo. */
export const PEM_BEGIN = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ');

/** Fake keys are assembled at runtime so no secret-shaped literal sits in the repo. */
export const fake = {
  supabaseJwt: (role: string) =>
    [
      b64({ alg: 'HS256', typ: 'JWT' }),
      b64({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role, iat: 1, exp: 2 }),
      's'.repeat(43),
    ].join('.'),
  stripeLive: () => ['sk', 'live', 'A1b2C3d4E5f6G7h8I9j0K1l2'].join('_'),
  stripePublishable: () => ['pk', 'live', 'A1b2C3d4E5f6G7h8I9j0K1l2'].join('_'),
  openai: () => `sk-${'proj'}-${varied(40, 1)}`,
  anthropic: () => `sk-${'ant'}-${varied(40, 2)}`,
  supabaseSecret: () => `sb_${'secret'}_${varied(30, 3)}`,
  githubToken: () => `gh${'p'}_${varied(36, 4)}`,
  awsKeyId: (seed = 5) => `AK${'IA'}${varied(16, seed, 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789')}`,
};

export const html = (scripts: string[], inline = '') =>
  `<!doctype html><html><head>${scripts
    .map((s) => `<script type="module" src="${s}"></script>`)
    .join('')}</head><body><div id="root"></div><script>${inline}</script></body></html>`;
