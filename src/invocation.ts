// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import { ENGINE_VERSION } from './core/types';

/**
 * How text written by the tool tells someone to run the tool again. Pinned to
 * this exact version, so a re-check is always made by the same version as the
 * check it is compared with.
 */
export const PACKAGE_SPEC = `github:QAJPAI/qa-jp-ai-scanner#v${ENGINE_VERSION}`;

export const commandFor = (args: string): string => `npx --yes ${PACKAGE_SPEC} ${args}`;

export const RECHECK_COMMAND = commandFor('check . --compare --for-ai');
