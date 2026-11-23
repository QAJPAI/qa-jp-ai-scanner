// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Scripts that a script loads: the chunks a build splits an app into.
 *
 * A page names only its entry script. The rest arrives when the app runs: an
 * ES module imports others (`from"./vendor-x.js"`, `import("./Admin-y.js")`),
 * Vite lists what to preload (`["assets/Admin-y.js", …]`), Next.js lists the
 * chunks of every page in a build manifest (`"static/chunks/pages/admin-z.js"`).
 * A key in one of those is as public as a key in the entry script.
 *
 * All of these are path-shaped string literals that end in `.js` or `.mjs`,
 * so that is what is collected, without parsing JavaScript. Names that a
 * bundler computes at runtime (webpack's `"static/js/" + id + "." + hash`)
 * are not literals and are not found: the rule stays "partly examined".
 *
 * The script is text from the site being checked. The scan is linear: each
 * occurrence of the extension is looked at once, within a bounded window, and
 * the number of occurrences examined is capped.
 */

const MAX_PATH_LENGTH = 200;
/** Occurrences of the extension examined in one script. Beyond it the script counts as not fully followed. */
const MAX_OCCURRENCES = 5000;
const QUOTES = new Set(['"', "'", '`']);
const PATH_CHAR = /[A-Za-z0-9_@~.\/-]/;

export interface ReferencedScripts {
  /** Absolute URLs, in order of first appearance, without duplicates. */
  urls: string[];
  /** More occurrences than are examined: there may be references that were not collected. */
  limitHit: boolean;
}

/** The string literal that ends at `end` (exclusive), if it is a path in quotes of at most MAX_PATH_LENGTH characters. */
function pathEndingAt(text: string, end: number): string | undefined {
  const quote = text[end];
  if (quote === undefined || !QUOTES.has(quote)) return undefined;
  const floor = Math.max(0, end - MAX_PATH_LENGTH - 1);
  for (let i = end - 1; i >= floor; i--) {
    const c = text[i]!;
    if (c === quote) return text.slice(i + 1, end);
    if (!PATH_CHAR.test(c)) return undefined;
  }
  return undefined;
}

/**
 * Where a path written in a script points.
 *
 *  `./x.js`, `../x.js`   relative to the script, as the browser resolves an import
 *  `/assets/x.js`        from the site root
 *  `assets/x.js`         relative to the build's base. The base is not written
 *                        anywhere, but the script itself sits under it: for
 *                        `/app/assets/index.js` the base of `assets/…` is `/app/`,
 *                        for `/_next/static/chunks/main.js` the base of
 *                        `static/…` is `/_next/`. Otherwise the page's base.
 */
function resolve(path: string, script: URL, pageBase: URL): URL | undefined {
  try {
    if (path.startsWith('./') || path.startsWith('../') || path.startsWith('/')) return new URL(path, script);
    const slash = path.indexOf('/');
    // A bare file name ("index.js") is far more often a word in a message than a chunk.
    if (slash <= 0) return undefined;
    const firstSegment = `/${path.slice(0, slash + 1)}`;
    const at = script.pathname.indexOf(firstSegment);
    const base = at >= 0 ? new URL(script.pathname.slice(0, at + 1), script) : pageBase;
    return new URL(path, base);
  } catch {
    return undefined;
  }
}

export function referencedScripts(body: string, scriptUrl: URL, pageBase: URL): ReferencedScripts {
  const urls = new Set<string>();
  let examined = 0;
  for (let at = body.indexOf('.'); at >= 0; at = body.indexOf('.', at + 1)) {
    const end = body.startsWith('.js', at) ? at + 3 : body.startsWith('.mjs', at) ? at + 4 : -1;
    if (end < 0) continue;
    if (examined >= MAX_OCCURRENCES) return { urls: [...urls], limitHit: true };
    examined++;
    const path = pathEndingAt(body, end);
    if (!path) continue;
    const url = resolve(path, scriptUrl, pageBase);
    if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:')) continue;
    url.hash = '';
    if (url.href !== scriptUrl.href) urls.add(url.href);
  }
  return { urls: [...urls], limitHit: false };
}
