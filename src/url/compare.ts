// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CompareOptions } from '../core/compare';

/**
 * Comparing two checks of the same site.
 *
 * In a project, "fixed" needs the file the problem was in to have been read
 * again. The same holds for a site: a key that was in a script counts as
 * removed only if this check can say where it would be now.
 *
 *  - If the page and every script it references were read in full, the key is
 *    in none of them, whatever the scripts are called now. Builds rename
 *    their output (`index-3fA9kQ2x.js`), so names are not compared here.
 *  - If something was left unread (a script failed, was cut off, or was over
 *    the cap), the key may simply sit in the unread part. Then only a text
 *    with the same address that was read in full again counts.
 *
 * Anything else is reported as "gone, but not confirmed as fixed". That errs
 * on the side of not claiming a fix.
 *
 * A script that another script loads is read too (see imports.ts), as long as
 * its name is written out in the code, and counts like any other: unread, it
 * keeps "everything was read" from being true.
 *
 * Known limit: a script whose name is put together at runtime is not read by
 * this layer, so a key moved into one is not seen. The R02 coverage note says
 * so on every result.
 */

/** Checkers whose records point into a served text: the page or one of its scripts. */
const SERVED_TEXT_CHECKERS: ReadonlySet<string> = new Set(['url.secrets', 'url.baas-hint']);

/** What a URL check read, as returned by inspectOwner(). */
export interface ServedTextsRead {
  /** The page, every script it references and every script those name were read in full. */
  everythingRead: boolean;
  /** Addresses of the texts that were read in full. */
  textsRead: ReadonlySet<string>;
}

/** Identity of a served text: host and path, without query or fragment. */
function textKey(address: string): string | undefined {
  try {
    const url = new URL(address);
    return `${url.host}${url.pathname}`;
  } catch {
    return undefined;
  }
}

/**
 * The `wasRead` for comparing two URL checks: true unless the record points
 * into a served text that the current check cannot vouch for.
 */
export function servedTextReader(current: ServedTextsRead): NonNullable<CompareOptions['wasRead']> {
  const read = new Set<string>();
  for (const address of current.textsRead) {
    const key = textKey(address);
    if (key) read.add(key);
  }
  return (place, record) => {
    if (!SERVED_TEXT_CHECKERS.has(record.checker)) return true;
    if (current.everythingRead) return true;
    const key = textKey(place);
    return key !== undefined && read.has(key);
  };
}
