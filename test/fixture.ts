// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Route {
  status?: number;
  headers?: Record<string, string | string[]>;
  body?: string;
}

export interface Fixture {
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
    res.writeHead(route.status ?? 200, { 'content-type': 'text/plain', ...route.headers });
    res.end(route.body ?? '');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

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
  openai: () => `sk-${'proj'}-${'x'.repeat(40)}`,
  anthropic: () => `sk-${'ant'}-${'y'.repeat(40)}`,
};

export const html = (scripts: string[], inline = '') =>
  `<!doctype html><html><head>${scripts
    .map((s) => `<script type="module" src="${s}"></script>`)
    .join('')}</head><body><div id="root"></div><script>${inline}</script></body></html>`;
