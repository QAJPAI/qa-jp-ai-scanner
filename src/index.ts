// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
export { scan, normalizeTarget, type ScanOptions } from './scanner';
export { toPublicSummary, renderPublicSummary, renderOwnerReport } from './report';
export { evaluateEmailOwnership, confirmEmailOwnership, type EmailDecision } from './ownership/email';
export { verifyByFile, WELL_KNOWN_PATH } from './ownership/file';
export { verifyByDns, dnsRecordName } from './ownership/dns';
export { mintVerificationToken } from './ownership/token';
export { ownershipSubject, type OwnershipProof } from './ownership/proof';
export * from './types';
