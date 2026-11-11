// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { closeAgents, safeFetch } from '../src/net/fetcher';
import { isBlockedAddress } from '../src/net/guard';
import { startFixture } from './fixture';

after(closeAgents);

test('non-public addresses are blocked, public ones are not', () => {
  const blocked = [
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1',
    '::ffff:7f00:1', '64:ff9b::7f00:1', 'not-an-ip', '',
  ];
  for (const address of blocked) assert.equal(isBlockedAddress(address), true, address);

  const allowed = ['8.8.8.8', '1.1.1.1', '172.32.0.1', '203.0.114.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'];
  for (const address of allowed) assert.equal(isBlockedAddress(address), false, address);
});

test('safeFetch refuses loopback, metadata, odd ports, credentials and non-http schemes', async () => {
  const fixture = await startFixture({ '/': { body: 'ok' } });
  try {
    const refused = [
      fixture.origin + '/', // loopback on a non-standard port
      'http://127.0.0.1/',
      'http://[::1]/',
      'http://169.254.169.254/latest/meta-data/',
      'http://localhost/', // hostname that resolves to loopback: caught at connect time
      'http://user:pw@example.com/',
      'ftp://example.com/',
      'file:///etc/passwd',
    ];
    for (const url of refused) {
      // Must fail because the guard refused it, not because nothing was listening.
      await assert.rejects(safeFetch(url, { timeoutMs: 3000 }), { code: 'QA_BLOCKED_ADDRESS' }, url);
    }
    assert.deepEqual(fixture.requests, [], 'the guarded fetcher must never reach the local server');
  } finally {
    await fixture.close();
  }
});

test('safeFetch caps the response size', async () => {
  const fixture = await startFixture({ '/big': { body: 'a'.repeat(50_000) } });
  try {
    const res = await safeFetch(fixture.origin + '/big', { allowPrivate: true, maxBytes: 1000 });
    assert.equal(res.body.length, 1000);
    assert.equal(res.truncated, true);
  } finally {
    await fixture.close();
  }
});

test('safeFetch follows redirects but can be pinned to the original host', async () => {
  const fixture = await startFixture({
    '/a': { status: 302, headers: { location: '/b' } },
    '/b': { body: 'landed' },
    '/away': { status: 302, headers: { location: 'http://localhost:9/' } },
  });
  try {
    const res = await safeFetch(fixture.origin + '/a', { allowPrivate: true });
    assert.equal(res.body, 'landed');
    assert.equal(res.redirectChain.length, 1);

    await assert.rejects(
      safeFetch(fixture.origin + '/away', { allowPrivate: true, sameHostRedirectsOnly: true }),
      /Redirect left the original host/,
    );
  } finally {
    await fixture.close();
  }
});
