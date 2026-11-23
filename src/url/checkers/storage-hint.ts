// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Checker } from '../../core/checker';
import type { NeedsValidationRecord } from '../../core/records';
import { evidence } from '../../i18n/ja';
import type { UrlContext } from '../context';
import { supabaseNames } from '../supabase-names';

/**
 * R06 — files in public storage, as far as the site's own code tells.
 *
 * A site that shows files from a Supabase bucket through the public object
 * path, or through getPublicUrl(), uses that bucket as public: anyone with
 * the address of a file can open it. That is right for avatars and product
 * pictures and wrong for identity documents. What is in the bucket cannot be
 * seen from the code, and is not looked at: no request is made to the
 * storage.
 *
 * So this checker never confirms anything. It names each such bucket and
 * asks the owner what is in it: one needs_validation record per bucket.
 */

/** Buckets asked about in one result. More than this is noise, not help. */
const MAX_BUCKETS = 10;

export const storageHintChecker: Checker<UrlContext> = {
  id: 'url.storage-hint',
  layer: 'url',
  mode: 'passive',
  rules: ['R06'],
  run(ctx, make) {
    const records: NeedsValidationRecord[] = [];
    const seen = new Set<string>();
    for (const text of ctx.texts) {
      for (const bucket of supabaseNames([text]).publicBuckets) {
        if (seen.has(bucket) || seen.size >= MAX_BUCKETS) continue;
        seen.add(bucket);
        records.push(
          make.needsValidation({
            ruleId: 'R06',
            code: 'storage.supabase_public_bucket',
            blocker: 'requires_owner_intent',
            key: `supabase:${bucket}`,
            location: text.url,
            evidence: evidence.publicBucket(bucket),
          }),
        );
      }
    }
    // Names in the code only: what the bucket holds, and other kinds of storage, are not examined.
    return { records, coverage: [{ ruleId: 'R06', status: 'partial', note: 'names_in_code_only' }] };
  },
};
