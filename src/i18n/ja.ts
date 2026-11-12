// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CoverageNote, CoverageStatus, NotRunReason } from '../core/coverage';
import type { Blocker } from '../core/records';
import type { Grade, RuleId, Severity } from '../core/types';

/** All user-facing text is Japanese. Code and identifiers stay English. */

export const severityLabel: Record<Severity, string> = {
  P0: '至急',
  P1: '重大',
  P2: '改善推奨',
};

export const gradeLabel: Record<Grade, string> = {
  A: '今回の検査範囲では問題は見つかりませんでした',
  B: '改善を推奨する項目があります',
  C: '改善を推奨する項目が複数あります',
  D: '重大な問題があります',
  E: '至急の対応が必要な問題があります',
};

/** The public view grades basic configuration only, and its wording must not suggest more. */
export const publicGradeLabel: Record<Grade, string> = {
  A: '基本設定に問題は見つかりませんでした',
  B: '基本設定に改善を推奨する項目があります',
  C: '基本設定に改善を推奨する項目が複数あります',
  D: '基本設定に重大な問題があります',
  E: '基本設定に至急の対応が必要な問題があります',
};

interface FindingText {
  title: string;
  fix: string;
}

const AI_KEY_FIX =
  '第三者に利用され、高額な請求につながるおそれがあります。このキーをただちに無効化して再発行し、AI の呼び出しはサーバー側を経由する形に変更してください。';

const TOKEN_FIX =
  'このキーをただちに無効化して再発行し、フロントエンドのコードから削除してください。秘密のキーはサーバー側（環境変数）でのみ使用します。';

export const findingText: Record<string, FindingText> = {
  'secret.supabase_service_role': {
    title: 'Supabase の service_role キーがフロントエンドに含まれています',
    fix: 'このキーはデータベースの全権限を持ち、行レベルセキュリティ（RLS）も無視します。Supabase の管理画面でただちにキーを再発行し、フロントエンドのコードから削除してください。service_role キーはサーバー側（環境変数）でのみ使用します。',
  },
  'secret.supabase_secret_key': {
    title: 'Supabase のシークレットキーがフロントエンドに含まれています',
    fix: 'このキーはデータベースの全権限を持ちます。Supabase の管理画面でただちにキーを再発行し、フロントエンドのコードから削除してください。フロントエンドで使用できるのは公開用（publishable / anon）キーのみです。',
  },
  'secret.openai': {
    title: 'OpenAI の API キーがフロントエンドに含まれています',
    fix: AI_KEY_FIX,
  },
  'secret.anthropic': {
    title: 'Anthropic の API キーがフロントエンドに含まれています',
    fix: AI_KEY_FIX,
  },
  'secret.stripe_live': {
    title: 'Stripe の本番用シークレットキーがフロントエンドに含まれています',
    fix: '決済の操作や顧客情報の取得に悪用されるおそれがあります。Stripe の管理画面でただちにキーを無効化して再発行し、決済処理はサーバー側で行ってください。',
  },
  'secret.stripe_test': {
    title: 'Stripe のテスト用シークレットキーがフロントエンドに含まれています',
    fix: 'テスト用であっても、シークレットキーをフロントエンドに置く構成のまま本番に移行すると重大な事故につながります。キーを再発行し、決済処理をサーバー側に移してください。',
  },
  'secret.aws_access_key': {
    title: 'AWS のアクセスキー ID がフロントエンドに含まれています',
    fix: '対になるシークレットキーも含まれていないか確認してください。該当するキーを AWS の管理画面で無効化し、AWS へのアクセスはサーバー側で行ってください。',
  },
  'secret.private_key': {
    title: '秘密鍵（PRIVATE KEY）がフロントエンドに含まれています',
    fix: 'この鍵は漏えいしたものとして扱ってください。鍵を発行元で失効させて再発行し、フロントエンドのコードから削除してください。',
  },
  'secret.github_token': {
    title: 'GitHub のアクセストークンがフロントエンドに含まれています',
    fix: TOKEN_FIX,
  },
  'secret.slack_token': {
    title: 'Slack のトークンがフロントエンドに含まれています',
    fix: TOKEN_FIX,
  },
  'secret.sendgrid': {
    title: 'SendGrid の API キーがフロントエンドに含まれています',
    fix: 'なりすましメールの送信に悪用されるおそれがあります。' + TOKEN_FIX,
  },
  'transport.no_https': {
    title: 'HTTPS（暗号化通信）が使用されていません',
    fix: '通信内容を第三者に読み取られるおそれがあります。ホスティングサービスの設定で HTTPS を有効にしてください。',
  },
  'transport.no_https_redirect': {
    title: 'HTTP でのアクセスが HTTPS に自動転送されていません',
    fix: 'http:// でアクセスした利用者が暗号化されないまま通信してしまいます。HTTP から HTTPS への自動転送を設定してください。',
  },
  'header.hsts_missing': {
    title: 'HSTS（Strict-Transport-Security）ヘッダーが設定されていません',
    fix: 'ブラウザーに常に HTTPS で接続させるための設定です。レスポンスヘッダーに Strict-Transport-Security を追加してください。',
  },
  'header.csp_missing': {
    title: 'CSP（Content-Security-Policy）ヘッダーが設定されていません',
    fix: '不正なスクリプトが埋め込まれた場合の被害を抑える設定です。レスポンスヘッダーに Content-Security-Policy を追加してください。',
  },
  'header.nosniff_missing': {
    title: 'X-Content-Type-Options ヘッダーが設定されていません',
    fix: 'レスポンスヘッダーに「X-Content-Type-Options: nosniff」を追加してください。',
  },
  'header.clickjacking': {
    title: '他サイトへの埋め込み（クリックジャッキング）対策が設定されていません',
    fix: 'レスポンスヘッダーに「X-Frame-Options: DENY」または CSP の frame-ancestors を追加してください。',
  },
  'cookie.insecure': {
    title: 'Cookie に安全のための属性が設定されていません',
    fix: 'ログイン状態を保持する Cookie には Secure・HttpOnly・SameSite の各属性を設定してください。',
  },
  'exposed.env': {
    title: '環境変数ファイル（.env）が外部から取得できる状態です',
    fix: 'ファイル内のキーやパスワードはすべて漏えいしたものとして再発行してください。そのうえで .env を公開ディレクトリから除外し、外部からアクセスできないことを確認してください。',
  },
  'exposed.git': {
    title: 'Git の管理ディレクトリ（.git）が外部から取得できる状態です',
    fix: 'ソースコードと変更履歴の全体を第三者が復元できるおそれがあります。.git ディレクトリを公開対象から除外してください。履歴にキーやパスワードが含まれていた場合は再発行が必要です。',
  },
  'exposed.sourcemap': {
    title: 'ソースマップ（.map）が公開されています',
    fix: '圧縮前のソースコードを第三者が読める状態です。本番用のビルド設定でソースマップの公開を無効にしてください。',
  },
};

/** Items the outside cannot decide: handed to the owner with one precise check. */
export const needsValidationText: Record<string, { title: string; plan: string }> = {
  'baas.supabase_rls_unverified': {
    title: 'Supabase の行レベルセキュリティ（RLS）が有効かどうか、外部からは確認できません',
    plan: 'このサイトはブラウザーから Supabase に直接接続しています。ページに含まれる公開用キーは誰でも取得できるため、データを守っているのは RLS の設定だけです。Supabase の管理画面で、すべてのテーブルの RLS が有効になっていること、各ポリシーが「本人のデータのみ」などに限定されていることを確認してください。',
  },
  'baas.firebase_rules_unverified': {
    title: 'Firebase のセキュリティルールが適切かどうか、外部からは確認できません',
    plan: 'このサイトはブラウザーから Firebase に直接接続しています。Firebase コンソールで Firestore・Realtime Database・Storage のセキュリティルールを開き、「allow read, write: if true」のような全開放の設定や、テストモードのままの設定が残っていないことを確認してください。',
  },
};

export const blockerLabel: Record<Blocker, string> = {
  not_observable_from_outside: '外部からの検査では確認できません',
  requires_source: 'ソースコードの検査が必要です',
  requires_deployment_fact: '運用環境の設定を確認する必要があります',
};

export const ruleTitle: Record<RuleId, string> = {
  R01: 'データベースのアクセス制御が有効になっていない',
  R02: '管理者用のキーがフロントエンドに含まれている',
  R03: '認証チェックがフロントエンドだけで行われている',
  R04: 'ログインなしで利用者のデータを取得できる',
  R05: '利用者が自分の権限や認証状態を書き換えられる',
  R06: '機密ファイルが公開ストレージに置かれている',
  R07: '回数制限・利用上限が設定されていない',
  R08: 'インジェクション（SQL・XSS）',
  R09: '画面上の制限がサーバー側で実施されていない',
  R10: '依存ライブラリのリスク',
  R11: '内部ファイル・デバッグ情報の露出',
  R12: 'LLM が入力によって権限外の操作をさせられる',
  R13: 'AI エージェントの権限が広すぎる・停止手段がない',
  R14: '通信の暗号化とレスポンスヘッダー',
  R15: 'ログの取り扱い',
};

export const coverageStatusLabel: Record<CoverageStatus, string> = {
  checked: '検査済み',
  partial: '一部のみ検査',
  not_run: '未検査',
  error: '検査できませんでした',
};

export const notRunReasonLabel: Record<NotRunReason, string> = {
  requires_owner_verification: '所有者確認後に検査します',
  requires_source: 'ソースコードの検査が必要なため、今後対応予定です',
  not_implemented: '今後対応予定です',
};

export const coverageNoteLabel: Record<CoverageNote, string> = {
  html_referenced_scripts_only: 'HTML から参照されているスクリプトのみが対象です',
  presence_hint_only: '利用しているサービスの検出のみで、設定内容は確認していません',
  some_content_not_read: '一部のスクリプトを読み込めなかったため、その部分は検査していません',
  record_limit_reached: '該当箇所が多すぎるため、途中で検査を打ち切りました',
  some_probes_failed: '一部の確認に応答がなかったため、その部分は判定していません',
};

/** Shown to the requester when a scan cannot honestly produce a result. */
export const scanErrorText: Record<string, string> = {
  page_unavailable: 'ページを正常に取得できなかったため、検査を行いませんでした。URL をご確認ください。',
  redirected_elsewhere:
    'この URL は別のサイトへ転送されます。検査したいサイトの URL を直接入力してください。',
  proof_mismatch: '所有者確認の対象と、検査するサイトが一致しません。',
  blocked: 'この URL は検査できません。',
  generic: '検査中に問題が発生しました。時間をおいて再度お試しください。',
};

export const evidence = {
  directConnection: (service: string) =>
    `ブラウザーから ${service} へ直接接続する設定を検出（設定内容は確認していません）`,
  redactedSecret: (prefix: string, length: number) =>
    `先頭「${prefix}」で始まる ${length} 文字の文字列（全体は記録していません）`,
  privateKeyHeader: () => 'PRIVATE KEY のヘッダー行を検出（鍵の本体は記録していません）',
  missingHeader: (name: string) => `レスポンスヘッダー ${name} がありません`,
  finalUrlNotHttps: () => '最終的に表示された URL が http:// です',
  httpNotRedirected: () => 'http:// でのアクセスが https:// に転送されませんでした',
  cookieMissingAttrs: (attrs: string[]) => `不足している属性: ${attrs.join('、')}`,
  envExposed: (keyCount: number) =>
    `HTTP 200 で応答し、${keyCount} 件の変数名を確認（値は記録していません）`,
  gitExposed: () => 'HTTP 200 で応答し、Git の管理ファイルの形式と一致（内容は記録していません）',
  sourcemapExposed: () => 'HTTP 200 で応答し、ソースマップの形式と一致（内容は記録していません）',
};

export const report = {
  publicTitle: 'QA.JP.AI 簡易チェック結果（公開表示）',
  ownerTitle: 'QA.JP.AI チェック結果（所有者向け詳細）',
  target: '対象',
  scannedAt: '検査日時',
  grade: '総合評価',
  counts: '優先度別の件数',
  countUnit: '件',
  checksPublic: '実施した検査: 通常のページ表示と同等のアクセスのみ',
  checksOwner: '実施した検査: 通常のページ表示と同等のアクセス、および所有者確認後にのみ行う検査',
  basicGrade: '基本設定の評価',
  basicCounts: '基本設定の件数',
  seriousGated:
    'キーの露出など重大な問題の有無と、問題の場所・修正方法は、サイトの所有者であることを確認できた方にのみ表示します。',
  sameForEverySite: 'この案内は、問題の有無にかかわらず、すべてのサイトで同じ内容です。',
  noFindings: '今回の検査範囲では問題は見つかりませんでした。',
  needsValidationCount: '確認をお願いしたい項目',
  incomplete: (count: number) =>
    `※ ${count} 項目の検査が完了しなかったため、この評価は不完全です。`,
  needsValidationHeading: '■ 確認をお願いしたい項目（外部からは判定できないため、所有者の方による確認が必要です）',
  findingsHeading: '■ 見つかった問題',
  coverageHeading: '■ 検査範囲（全項目の一覧）',
  coverageLine: (total: number, checked: number, partial: number) =>
    `検査範囲: 全 ${total} 項目のうち ${checked} 項目を検査、${partial} 項目を一部検査`,
  reason: '理由',
  whatToCheck: '確認していただきたいこと',
  location: '場所',
  evidence: '根拠',
  fix: '修正方法',
  disclaimer:
    '※ この結果は安全性を保証するものではありません。検査していない項目があります。',
  rulesVersion: '検査ルール',
};

export const ownership = {
  aiPrompt: (token: string) =>
    [
      '次の作業をお願いします。',
      '',
      'このウェブサイトの公開ディレクトリに、次のファイルを追加してください。',
      '',
      '  パス: /.well-known/qa-jp-ai.txt',
      `  内容（この 1 行のみ）: ${token}`,
      '',
      '追加後、https://（このサイトのドメイン）/.well-known/qa-jp-ai.txt をブラウザーで開いたときに、',
      '上記の 1 行だけがテキストとして表示されることを確認し、本番環境に反映してください。',
    ].join('\n'),
  dnsInstruction: (recordName: string, value: string) =>
    `DNS に次の TXT レコードを追加してください。\n  名前: ${recordName}\n  値: ${value}`,
  email: {
    eligible: 'このメールアドレスで所有者確認ができます。',
    invalid: 'メールアドレスの形式が正しくありません。',
    domain_mismatch:
      'メールアドレスのドメインが、検査対象のサイトのドメインと一致しません。',
    mailbox_not_on_main_domain:
      'サイトのドメインそのもののメールアドレス（例：info@example.jp）が必要です。サブドメインのメールアドレスでは確認できません。「確認ファイルを置く方法」もご利用いただけます。',
    free_mail:
      'フリーメールや携帯キャリアのメールアドレスでは所有者確認ができません。「確認ファイルを置く方法」をご利用ください。',
    platform_subdomain:
      'このサイトはホスティングサービスの共用ドメイン上にあるため、メールアドレスでは所有者確認ができません。「確認ファイルを置く方法」をご利用ください。',
    ip_address: 'IP アドレスで指定されたサイトは、メールアドレスでは所有者確認ができません。',
    admin_only:
      'このドメインは多数の方が同じドメインのメールアドレスを持つため、管理用アドレス（admin@、administrator@、webmaster@、hostmaster@、postmaster@）でのみ確認できます。または「確認ファイルを置く方法」をご利用ください。',
  },
};
