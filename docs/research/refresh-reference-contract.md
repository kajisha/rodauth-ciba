# CIBA refresh token: reference contract

2026-09-30。参照はインストール済み `oidc-provider 9.12.2`。これは仕様全体の適合試験ではなく、既定設定の実測と上流コードの比較である。gem の [refresh 基本実装](../refresh-tokens.md)は開発途中で、公開可能な対応完了ではない。

## HTTP で確認したこと

`test/reference/full-op/lifecycle.mjs` を Node 24.21.0、固定 Docker image、network none で実行した。[実行ログ](../validation/node-refresh-reference.txt)。既存 lifecycle ケースも成功。今回 ping.mjs は再実行していない。

- client が `refresh_token` grant を登録し、CIBA 要求が `offline_access` を含む場合のみ、既定 policy は refresh token を発行する。片方だけの場合は発行しない。
- 更新で元の scope にない `read` を要求すると `invalid_scope`。
- `scope=openid` に縮小した更新の次に scope を省略すると、元の `openid offline_access` に戻る。更新時の縮小はそのアクセストークンだけに適用される。
- 発行直後の confidential client の refresh token は、既定 rotation policy では同じ値で再利用できる。
- refresh token の保存モデルには元の authTime/acr/amr が残り、更新後 ID Token は元の nonce を持つ。この試験の claim 設定では auth_time/acr/amr は出力されない。保存と claim 出力の条件を混同しない。
- 保存 Grant を削除すると更新は `invalid_grant` になる。
- 保存モデルの iat/exp を変更し TTL の80%が経過した fixture では、既定 policy が rotation し、旧 token に consumed、後続 token に同じ grantId と rotations=1 を保存する。実時間で寿命の80%を待った試験ではない。
- 別の refresh 対応 client が旧 token を使用しても `invalid_grant` で拒否するだけで Grant は残る。正当な client が使用済み token を再利用すると Grant が消え、後続 refresh token は使用不能、後続 access token の introspection は active=false になる。
- exp を過去にした保存 fixture は `invalid_grant`。その Grant は保持される。memory adapter の期限管理も含むため、expired token が必ず handler の期限分岐まで到達した証拠ではない。
- resource A/B を要求して A の read token を最初に発行しても、refresh は B の write token を取得できる。resource 省略では OIDC scope に戻り、未要求の宛先は `invalid_target`。
- 保存 Grant の B/write を後から拒否すると B の refresh は成功するが scope は空になる。初回 token の scope を refresh の元許可として使ってはいけない。
- revocation の既定 policy は別 confidential client の live token 取消しを400 `invalid_request` で拒否する。正当な client の取消しは空bodyの200で、保存 Grant ごと無効化する。hint の省略・`refresh_token`・`access_token`・未知値で同じ結果。取消し後は別 client の再送も200になる。
- claims/RAR を伴う rotation は source の claims/rar/authTime を後続に保持する。保存 Grant で後から拒否した email は次の ID Token に含まれない。参照アプリの RAR policy は完了時に明示した source.rar を返し、更新パラメータで read/delete を再要求しても read のまま。RAR policy は固定したテストアプリのものであり、一般的な権限縮小アルゴリズムではない。

## コードから確認した境界

参照側 `lib/helpers/defaults.js` の issueRefreshToken/rotateRefreshToken、`lib/helpers/grant_common.js`、`lib/actions/grants/refresh_token.js` を確認した。

参照側は RefreshToken を AccessToken とは別のモデルとして保存し、元の scope、resource、claims、rar、nonce、認証情報、grantId を保持する。更新では保存 Grant を検証し、resource/scope/承認から新しいアクセストークンを構成する。rotation 後の使用済み token の再利用は関連 Grant の取消しへ進む。上記 HTTP ケースで rotation/replay/resource を確認したが、claims/RAR の refresh 併用は未検証。

rodauth-oauth 1.7.0 の `oauth_base.rb#create_token` は既定で毎回 rotation し、`create_token_from_token` は既存 oauth_grants 行の token と期限を更新する。元の許可を保持する独立した RefreshToken モデルではない。比較開始時の gem は refresh grant を super に渡していた。現在の開発実装は CIBA 専用 namespace の token を別処理し、それ以外を super に渡す。

したがって `generate_token(..., true)` への変更だけでは整合しない。CIBA 元要求の許可と、今回の access token に限定された scope/resource/claims/RAR を分け、保存承認の期限・取消し・account/client を更新でも検証する必要がある。通常の OAuth refresh の既定設定を OP 全体で変更しない。

## 次の実装前に残る検証

- refresh での claims/RAR、rotation 後の認証情報・元許可の保持。
- gem の更新処理、同時更新・取消し、発行失敗 rollback、機能無効化。保存 migration のみ下記の段階まで実装。

上記のうち更新・rotation/replay・署名失敗 rollback・無効化・同時 rotation は基本実装へ接続した。refresh token を提示する取消し endpoint、期限切れ cleanup、更新 hooks/events も接続した。claims/RAR の opaque/JWT 更新は元の要求・現在の承認・アプリ policy の分離を試験した。access token を提示する grant-wide 取消し、Ruby matrix・配布 gem での検証は残る。

## 保存基盤の実装段階

`Schema.create_refresh_tokens(db, ...)` を追加した。明示的な追加 migration であり、呼び出しても refresh の受付・発行は有効にならない。まだ導入用の機能として公開する段階ではない。

- `token_digest` の一意制約と `consumed_at` によって、rotation 後も旧 token の使用済み記録を保持できる。生の refresh token 用の列は持たない。
- 元の account/client、保存承認への外部キー、scope、要求した claims/resources/RAR、認証時刻・acr/amr・nonce を、access token の絞り込まれた属性と別に保存する。
- 初回作成時刻・今回発行時刻・期限・rotation 回数を持ち、node の経過時間による rotation を実装するための情報を保持する。lock_version は既存の CIBA と同様に DB の競合制御に使用する予定。
- 要求テーブルへの外部キーを持たず、短寿命の要求を cleanup しても refresh source は残る。保存承認・account/client の削除時は cascade する。承認の論理取消しは更新処理で検証する必要があり、この migration だけでは強制されない。

保存テストは既存要求・発行 token・承認の保持、digest 重複拒否、使用済みと後続 token の共存、要求削除後の保持、承認削除時の cascade、transaction rollback、テーブル名変更を対象とする。この段階の後、基本プロトコル処理と replay 取消しを実装した。

Ruby 4.0.6 の SQLite/PostgreSQL/MySQL で各 **2 tests / 17 assertions** 成功。[限定 matrix のログ](../validation/refresh-storage-matrix.txt)。これは追加 storage テストのみの実行であり、既存全 suite の再実行や Ruby 3.3/3.4 の確認ではない。

基本 runtime 接続後、同じ3 DBで全 suite 各 **190 tests** 成功（SQLite 1709 assertions、PostgreSQL/MySQL 1706）。[runtime matrix](../validation/refresh-runtime-matrix.txt)。同時 rotation、通常 OAuth refresh の維持、client 登録削除、認証情報・scope 保持、resource の宛先変更を含む。auth_time は既存 completion API と同じく省略可能なので nullable に修正した。Ruby 3.3/3.4・配布成果物での refresh 検証はまだ行っていない。

refresh の revocation 接続後は3 DBで各192 tests成功（1756〜1759 assertions）。その後の取消し済み token の扱いの調整は、3 DB各2 tests/54 assertionsで確認した。[全体](../validation/refresh-revocation-matrix.txt)、[最終差分](../validation/refresh-revocation-final.txt)。上流の browser session 分岐をこの名前空間の取消しだけで使わず、client 認証に固定した。通常 OAuth token の取消し経路は変更していない。

claims/RAR の opaque/JWT rotation と cleanup 追加後は3 DB各 **195 tests** 成功（1831〜1834 assertions）。[ログ](../validation/refresh-permissions-matrix.txt)。未承認操作の追加拒否、rotation rollback、現在の claim 拒否、後続 source の保持、RAR 無効化、許可縮小、期限境界・外側 rollback を含む。汎用 RAR 意味論や全 callback の組合せを網羅するものではない。

更新フック追加後は3 DBと Ruby3.3/3.4 SQLite の5環境で各 **200 tests** 成功（1894〜1897 assertions）。[DB](../validation/refresh-hooks-matrix.txt)、[Ruby](../validation/refresh-ruby-matrix.txt)。フック後の再検証、rollback、同一 source の再入拒否、outer commit 後の観測と失敗の分離を確認。残件のうち Ruby matrix は解消したが、配布 gem での refresh と access-token 取消しの整合化は未完了。

その後、配布 gem の opaque/JWT refresh smoke を追加して成功した。[ログ](../validation/refresh-package.txt)。CIBA の signed request・claims/resource/RAR と組み合わせ、rotation・認証情報保持・取消し・cleanup を検証した。Discovery の revocation URL 欠落も修正した。配布検証の残件は解消したが、access-token を提示した grant-wide 取消しの整合化は残る。

## JWT client assertion audience

A separate complete-OP fixture now exercises both `private_key_jwt` (RS256) and
`client_secret_jwt` (HS256), with a fresh signed client assertion at each CIBA
initiation, token collection and refresh. Node 9.12.2 accepts the issuer as aud
at all three stages. Wrong audiences and reuse of the same assertion fail client
authentication. [Reference run](../validation/node-assertion-refresh.txt),
[harness](../../test/reference/full-op/assertion-refresh.mjs).

The gem originally accepted issuer aud for initiation/collection but rejected
it for CIBA refresh with HTTP401. Both authentication methods reproduced the
failure. The corrected audience rule includes the issuer for CIBA refresh only,
selected by the existing reserved `ciba_rt_` namespace; it does not grant access
without client signature/secret, replay checks and refresh ownership/consent
validation. Unrelated authorization-code requests retain the previous audience
rule. Wrong-audience attempts preserve refresh rows, and assertion replay after
one successful refresh cannot issue another token.
[Before correction](../validation/assertion-refresh-red.txt),
[local regressions](../validation/assertion-refresh-current.txt).

This proves these two authentication methods with issuer aud and the fixture's
algorithms. It is not mTLS support or coverage of every authentication method,
JWT algorithm, key rotation or remote-key refresh failure.
