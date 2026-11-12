// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Text that came from the thing being checked — file paths, table and policy
 * names, variable names, host names — is data. Before it is shown to a person
 * or handed to an AI it is made inert:
 *
 * - control characters (including ESC, so no terminal escape sequences) and
 *   line breaks become spaces, so it cannot start a new line that looks like
 *   part of the report;
 * - bidirectional overrides and isolates are removed, so it cannot reorder
 *   how the surrounding text is displayed ("Trojan Source");
 * - it is cut to a bounded length.
 */

// C0 and C1 controls, DEL, line/paragraph separators. Written as escapes: the raw
// characters would end the regular expression literal.
const CONTROL = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]', 'g');
// Bidi embeddings, overrides, isolates and marks; zero-width characters and BOM.
const INVISIBLE = new RegExp('[\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]', 'g');

export function cleanText(value: string, max = 300): string {
  const cleaned = value.replace(CONTROL, ' ').replace(INVISIBLE, '').replace(/ {2,}/g, ' ').trim();
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}
