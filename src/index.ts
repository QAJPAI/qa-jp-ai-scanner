// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later

// Core: the judging layer shared by every layer and every checker.
export * from './core/types';
export { RULES, type RuleDef } from './core/rules';
export { fingerprintOf, recordFactory, type AssessmentRecord, type Blocker } from './core/records';
export { buildLedger, countCoverage, type CoverageUnit } from './core/coverage';
export { summarize, gradeFor, type Assessment, type Summary } from './core/assessment';
export { validateAssessment } from './core/validate';
export type { Checker, CheckOutcome } from './core/checker';

// URL layer.
// scanPublic() returns the summary only; scanOwner() requires a proof.
// The lower-level scan() is not exported here: it returns every detail at either tier.
export { scanPublic, scanOwner, normalizeTarget, ScanError, URL_CHECKERS, type ScanOptions } from './url/scan';
export type { UrlContext } from './url/context';

// Ownership verification.
export { evaluateEmailOwnership, issueEmailProofAfterLinkClick, type EmailDecision } from './ownership/email';
export { verifyByFile, WELL_KNOWN_PATH } from './ownership/file';
export { verifyByDns, dnsRecordName } from './ownership/dns';
export { mintVerificationToken } from './ownership/token';
export { ownershipSubject, type OwnershipProof } from './ownership/proof';

// Reports (Japanese).
export { toPublicSummary, renderPublicSummary, renderOwnerReport, type PublicSummary } from './report';
