// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Check the case site as its verified owner and print what the owner would
// see: the scoreboard of the six problems, the report, the fix request, the
// request for a review of the source code, and the re-check after a correct fix.
//
//   npx tsx evals/case-site/run.ts
import { compareAssessments } from '../../src/core/compare';
import { renderFixRequest } from '../../src/fixrequest';
import { notRunReasonLabel } from '../../src/i18n/ja';
import { verifyByFile } from '../../src/ownership/file';
import { renderComparison } from '../../src/recheck';
import { renderOwnerReport } from '../../src/report';
import { renderSourceReview } from '../../src/sourcereview';
import { servedTextReader } from '../../src/url/compare';
import { closeAgents } from '../../src/url/net/fetcher';
import { inspectOwner } from '../../src/url/scan';
import { caseSiteRoutes, CASE_TOKEN, scoreCaseSite, type CaseStatus } from '../../test/case-site';
import { startFixture } from '../../test/fixture';

const FETCH = { allowPrivate: true };
const LABEL: Record<CaseStatus, string> = {
  confirmed: '問題として確認',
  question: '確認のお願いとして表示',
  clear: '検査して、見つからず',
  not_examined: '未検査',
};
const PROBLEM: Record<number, string> = {
  1: 'ログインなしで、全利用者のプロフィールを返す API がある',
  2: '本人確認書類の画像が、公開ストレージに置かれている',
  3: '利用者が、自分の「本人確認済み」を自分で書き換えられる',
  4: 'データベースの管理者用キーが、フロントエンドに含まれている',
  5: '「学生のみ」の制限が、ブラウザー側でしか確認されていない',
  6: 'AI 機能に、回数制限・利用上限がない',
};
const heading = (text: string) => console.log(`\n==================== ${text} ====================\n`);

const routes = caseSiteRoutes('vulnerable');
const site = await startFixture(routes);
try {
  const proof = await verifyByFile(site.origin, CASE_TOKEN, FETCH);
  if (!proof) throw new Error('The case site did not verify as owned');

  const before = await inspectOwner(site.origin, proof, { fetch: FETCH });
  heading('見本サイトの 6 つの問題（修正前）');
  for (const s of scoreCaseSite(before.assessment)) {
    const why = s.reason ? `（${notRunReasonLabel[s.reason]}）` : '';
    console.log(`${s.problem.id}. ${PROBLEM[s.problem.id]}\n   → ${LABEL[s.status]}${why}`);
  }
  heading('所有者向けの結果');
  console.log(renderOwnerReport(before.assessment, proof));
  heading('AI に渡す修正依頼文');
  console.log(renderFixRequest(before.assessment));
  heading('URL から調べられない項目：AI に渡すソースコードの確認依頼文');
  console.log(renderSourceReview(before.assessment));

  // The owner publishes a correct fix, then checks the same site again.
  Object.assign(routes, caseSiteRoutes('fixed'));
  const now = await inspectOwner(site.origin, proof, { fetch: FETCH });
  heading('修正を公開したあとの再検査');
  console.log(renderComparison(compareAssessments(before.assessment, now.assessment, { wasRead: servedTextReader(now) }), now.assessment));
} finally {
  await site.close();
  await closeAgents();
}
