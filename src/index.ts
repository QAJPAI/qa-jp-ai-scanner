// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later

// Core: the judging layer shared by every layer and every checker.
export * from './core/types';
export { RULES, type Disclosure, type RuleDef } from './core/rules';
export { fingerprintOf, recordFactory, type AssessmentRecord, type Blocker } from './core/records';
export { buildLedger, countCoverage, type CoverageUnit } from './core/coverage';
export { summarize, gradeFor, type Assessment, type Summary } from './core/assessment';
export { validateAssessment } from './core/validate';
export type { Checker, CheckOutcome } from './core/checker';

// URL layer.
// scanPublic() returns the summary only; scanOwner() requires a proof.
// The lower-level scan() is not exported here: it returns every detail at either tier.
export {
  scanPublic,
  scanOwner,
  inspectOwner,
  normalizeTarget,
  ScanError,
  URL_CHECKERS,
  type ScanOptions,
  type UrlInspection,
} from './url/scan';
export { servedTextReader, type ServedTextsRead } from './url/compare';
export { scanErrorKind, scanErrorMessage, type ScanErrorKind } from './url/messages';
export { closeAgents } from './url/net/fetcher';
export type { UrlContext } from './url/context';

// Entrance B: source code, before deployment.
export { scanRepo, REPO_CHECKERS, type RepoScanOptions } from './repo/scan';
export type { RepoContext } from './repo/context';

// Ownership verification.
export { evaluateEmailOwnership, issueEmailProofAfterLinkClick, type EmailDecision } from './ownership/email';
export { verifyByFile, WELL_KNOWN_PATH } from './ownership/file';
export { verifyByDns, dnsRecordName } from './ownership/dns';
export { mintVerificationToken } from './ownership/token';
export { ownershipSubject, proofCovers, PROOF_TTL_MS, type OwnershipProof } from './ownership/proof';
export { sealProof, openProof } from './ownership/seal';

// Reports (Japanese).
export { toPublicSummary, renderPublicSummary, renderOwnerReport, renderLocalReport, type PublicSummary } from './report';
export { renderHandoff } from './handoff';

// Fixing and re-checking: the request an owner hands to an AI coding tool, and
// what changed since an earlier check. Both contain locations and evidence:
// for a site, show them only to a verified owner.
export { renderFixRequest } from './fixrequest';
export {
  compareAssessments,
  ComparisonError,
  type CompareOptions,
  type Comparison,
  type UnverifiedReason,
} from './core/compare';
export { renderComparison } from './recheck';
export { cleanText } from './text';
// All Japanese wording, so a web front end says exactly what the reports say.
export * as ja from './i18n/ja';
