# CIBA 承認連携と監査失敗の IdM 事例

2026-09-28 に公式公開資料を確認。製品を動かした検証ではない。以下の事実と設計案は、gem の採用決定ではない。

## Authlete

標準 CIBA endpoint を提供する OP 実装と、Authlete のバックエンド API を分離する。`/backchannel/authentication` が検証と ticket 発行、`/issue` が auth_req_id と受付応答の作成、`/complete` が認証・承認結果の受け渡しを担当する。`/fail` は受付成功前の失敗処理であり、受付後の顧客拒否とは区別する。

`/complete` は AUTHORIZED / ACCESS_DENIED / TRANSACTION_FAILED を受け、成功時には subject を指定する。poll では状態を更新し、後続の token endpoint 呼び出しでトークンを発行する。これらは Authlete 独自 API であり、標準 Discovery の承認 API ではない。

出典: [実装ガイド](https://developers.authlete.com/guides/flows-and-protocols/grant-types-and-token-flows/how-to-implement-ciba-with-authlete)、[CompleteRequest](https://authlete.github.io/authlete-java-common/com/authlete/common/dto/BackchannelAuthenticationCompleteRequest.html)。

[Audit Logs](https://developers.authlete.com/configuration-reference/security/audit-logs) は操作記録を説明するが、監査保存失敗と CIBA トランザクションの成否の関係は確認できなかった。管理操作ログをそのまま CIBA の承認証跡と同一視しない。

## Auth0

Guardian アプリまたは Guardian SDK を組み込んだアプリによる承認と、メールのリンクからブラウザで認証・承認するフローを提供する。確認した資料では任意の承認サービスが呼べる標準の承認完了 API は示されていない。未公開の内部 API の有無は判断していない。

出典: [CIBA 設定](https://auth0.com/docs/get-started/applications/configure-client-initiated-backchannel-authentication)、[メールによる CIBA](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow/email-notifications-with-ciba)。

[Log Streams](https://auth0.com/docs/customize/log-streams) は監視・分析向けであり、アプリのクリティカルパスやリアルタイムの判断に使わないよう明記している。配送失敗は再試行し、7 日間連続して宛先に到達できない場合はストリームを停止する。これは外部ログ配送の仕様であり、内部ログ保存失敗時の挙動を証明するものではない。

## gem への示唆（提案、未採用）

- 標準 Discovery の公開 API と、アプリから認証・承認結果を受け取る拡張 API を分ける。Authlete の責任分界は参考になるが、Ruby gem に HTTP API が必要という結論にはならない。
- 観測用イベントの出力失敗で認証を一律中断する案は見直す。既定では監査基盤を要求せず、観測と必須の保存処理を別の契約にする案を検討する。
- 厳密な証跡保存を必要とするアプリには、同じ DB トランザクション内で記録する拡張点を検討する。外部への配送保証は別問題であり、上記製品が同一の仕組みを提供していると主張しない。

## 追加調査: トランザクション内の拡張点

### Keycloak

[EventListenerProvider の公式契約](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/events/EventListenerProvider.html) は、リスナーが実行中のトランザクションに参加し、JPA でイベントを保存すれば元の変更と一緒に commit / rollback できると説明する。ファイル出力など取り消せない処理には after-completion を使い、成功確定後に出力することを推奨している。

ただし、トランザクション内で動くことと例外伝播は別の契約である。[EventBuilder の実装](https://github.com/keycloak/keycloak/blob/4cf1ba6396919b754806ec00afe105a56e0f0265/server-spi-private/src/main/java/org/keycloak/events/EventBuilder.java) では通常のイベントリスナーの Throwable を捕捉してログに記録する。任意のリスナーが例外を投げるだけで必ず認証を中断できる、とは解釈しない。

### Auth0

[Post Login Actions](https://auth0.com/docs/customize/actions/explore-triggers/post-login) は同期的に認証フローへ参加する。一方、[api.access.deny](https://auth0.com/docs/actions/reference/post-login/post-login-api-object) はログインを拒否しても、Action が要求したユーザーメタデータ変更などの副作用を取り消さないと明記する。認証フローの中断は、アプリの DB も含めたトランザクションの rollback と同義ではない。

### Rodauth

この gem の基盤である Rodauth 自身が最も直接的な参考になる。[create_account の実装](https://github.com/jeremyevans/rodauth/blob/master/lib/rodauth/features/create_account.rb) は transaction ブロック内で before_create_account、保存、after_create_account を呼ぶ。after は commit 後を意味しない。

[audit_logging](https://rodauth.jeremyevans.net/rdoc/files/doc/audit_logging_rdoc.html) は任意の feature として after フックに接続し、DB テーブルに記録する。[実装](https://github.com/jeremyevans/rodauth/blob/master/lib/rodauth/features/audit_logging.rb) の INSERT には局所的な例外の握り潰しはない。これは通常設定・同じ DB で状態変更と監査保存を同一トランザクションに参加させる具体例である。CIBA の匿名クライアント要求やアカウントの結び付けにそのまま適用できるかは別途確認が必要。

### 推奨の修正（未採用）

「専用フックを初版から外す」と決める前に、Rodauth の通常の before / after フックを CIBA の主要な状態変更にも適用する案を優先して検討する。根拠は新たに確認した基盤側の拡張慣例と既存 audit_logging の利用例である。独自のフック基盤や必須の監査保存機能を追加する理由にはならない。成否を変えない観測イベントは別の契約として維持する。
