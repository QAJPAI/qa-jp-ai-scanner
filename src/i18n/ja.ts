// Copyright (C) 2026 iQi
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Grade, Severity } from '../types';

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

export const evidence = {
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
  detailsGated:
    '問題の種類・場所・修正方法は、サイトの所有者であることを確認できた方にのみ表示します。',
  noFindings: '今回の検査範囲では問題は見つかりませんでした。',
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
    free_mail:
      'フリーメールや携帯キャリアのメールアドレスでは所有者確認ができません。「確認ファイルを置く方法」をご利用ください。',
    platform_subdomain:
      'このサイトはホスティングサービスの共用ドメイン上にあるため、メールアドレスでは所有者確認ができません。「確認ファイルを置く方法」をご利用ください。',
    ip_address: 'IP アドレスで指定されたサイトは、メールアドレスでは所有者確認ができません。',
    admin_only:
      'このドメインは多数の方が同じドメインのメールアドレスを持つため、管理用アドレス（admin@、administrator@、webmaster@、hostmaster@、postmaster@）でのみ確認できます。または「確認ファイルを置く方法」をご利用ください。',
  },
};
