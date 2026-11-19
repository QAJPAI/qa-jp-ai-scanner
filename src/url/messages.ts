// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { scanErrorText } from '../i18n/ja';
import { BlockedAddressError } from './net/guard';
import { ScanError } from './scan';

/**
 * What a requester may be told when a URL check cannot produce a result.
 * One fixed message per kind: internal detail (resolved addresses, which guard
 * refused, stack traces) never reaches the requester, so the answer cannot be
 * used to map the scanning side's network.
 */
export type ScanErrorKind = 'page_unavailable' | 'redirected_elsewhere' | 'proof_mismatch' | 'blocked' | 'generic';

export function scanErrorKind(err: unknown): ScanErrorKind {
  if (err instanceof ScanError) return err.code;
  if (err instanceof BlockedAddressError) return 'blocked';
  if (err instanceof Error && (err as { cause?: unknown }).cause instanceof BlockedAddressError) return 'blocked';
  return 'generic';
}

export function scanErrorMessage(err: unknown): string {
  return scanErrorText[scanErrorKind(err)] ?? scanErrorText.generic!;
}
