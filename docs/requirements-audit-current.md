# 現行構成の要件再監査

2026-09-30。初期の159項目カタログを保持し、現在の任意機能に対する再監査を追記する。**159項目を再分類、未分類は0項目**。この分割は最終目標や監査範囲を縮小しない。CIBA以外のRFCやnode固有の挙動は[整合化計画](alignment-roadmap.md)で別途追跡する。

初期監査の verified / optional_excluded は自動で引き継がない。以下の protocol_boundary_verified は記載したgem側の境界のみで、導入アプリ・Clientの正しさや認定を意味しない。partial は未解消の条件・差が残る。

各節は再監査時点の記録であり、後の実装変更で置き換えられた判定も含む。
最新の項目別判定は [JSON overlay](requirements-audit-current.json) を参照する。
特に NumericDate、空の jti、クライアント識別情報欠落時のエラーは、後続の整合化で変更済み。

追加確認：署名付き要求・ping・user_code の組み合わせでは、署名内の scope、hint、通知トークン、必須 user_code の欠落・空値を、署名外の正常値で補うことはできない。要求保存・通知開始前の拒否と正常要求の受理を確認した（[2 tests / 44 assertions](validation/signed-ping-required-fields.txt)）。CIBA-067/072 はこの限定的な証拠だけで全面合格には変更しない。

| ID | 対象 | 現判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-005](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | user_codeの対応表明 | protocol_boundary_verified | Discovery follows the feature flag; enabled metadata is asserted directly. |
| [CIBA-013](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | user_codeクライアント設定 | partial | Enabled clients accept explicit false and omitted metadata under the application policy. Disabled-feature clients declaring true are rejected, a stricter eligibility policy; this is not proof of identical handling in all deployments. |
| [CIBA-045](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | user_code | protocol_boundary_verified | Mandatory application verifier receives resolved account/client/code before insertion or dispatch; rejection has no pending request. Production verifier correctness remains application-owned. |
| [CIBA-060](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_codeはOPパスワードと別 | app_contract | Documentation now explicitly requires a separate code from the OP login password. No application password/code policy is implemented or audited. |
| [CIBA-061](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_codeの例外ポリシー | protocol_boundary_verified | Callback can explicitly allow omission for a client/user. Tests cover false/omitted client metadata; arbitrary per-user policy correctness is not established. |
| [CIBA-062](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_codeの都度入力 | client_only | Client-side collection/non-storage is outside this OP gem. Gem-side removal from snapshots is separately tested and does not prove this client requirement. |
| [CIBA-063](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_code変更手段 | app_contract | Application-owned code enrollment/change lifecycle is documented. No production change UI is supplied or tested. |
| [CIBA-144](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 missing_user_code | protocol_boundary_verified | Application-declared missing code yields the protocol error before dispatch. |
| [CIBA-145](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_user_code | protocol_boundary_verified | False/nil validation yields invalid_user_code; malformed input instead fails request validation. |

[対象テスト](../test/ciba_user_code_test.rb)は4ケースを実行。省略されたclient metadataと明示falseの両方を確認するテストを追加した。[実行ログ](validation/user-code-audit-current.txt)。node9.12.2も account 解決後にアプリの verifyUserCode を呼ぶ構造で、既存比較の責務分界を維持する。[比較](user-code.md#reference-comparison-and-evidence)。

パスワードとの分離・コード変更手段は[導入契約](user-code.md)に明記した。実際のアプリのコード管理を実装していないため、その要件をgemのテスト成功扱いにはしない。

[機械可読差分](requirements-audit-current.json)には元の159 IDのうち未分類IDの空リストも明示する。[歴史的カタログ](requirements-audit.json)の規範文と出典を保持する。次の対象は署名付き要求・hint・ping・pairwiseであり、未確認項目の適用条件を実装の有無だけで判定しない。


## 署名付き要求の再確認

設定可能な9種類のRS/PS/ESで、登録鍵の受理と誤署名の拒否を実行した。
[gem](validation/signed-request-audit-current.txt)、[参照OP](validation/node-signed-algorithms.txt)。
参照版のEd25519/EdDSAは未対応であり、全アルゴリズムの一致とはしない。
以下は追加14項目。時刻claimの文字列・小数拒否を追加し、合計6 tests /128 assertionsが成功した。aud配列など未試験の枝はコード確認と区別する。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-004](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 署名要求の対応表明 | protocol_boundary_verified | Configured signing algorithms appear in Discovery; disabled feature omission has baseline coverage. |
| [CIBA-012](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 署名要求アルゴリズム登録 | protocol_boundary_verified | Registered algorithm gates signed input; independent client authentication remains required. DCR composition is separately covered. |
| [CIBA-049](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のJWT形式 | protocol_boundary_verified | Signed inner parameters determine new pending work; normal request validation still applies. |
| [CIBA-050](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求の非対称署名 | partial | All nine configured RS/PS/ES algorithms accept the registered key and reject a different key in gem and reference. Ed25519/EdDSA now have Node/jose fixed-vector, three-DB HTTP remote-key and installed-artifact evidence; see the current Edwards update below. |
| [CIBA-051](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のaud | protocol_boundary_verified | OP issuer audience membership is checked; incorrect/missing audience rejected. Array audience path is code-reviewed but not directly covered by this test. |
| [CIBA-052](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のiss | protocol_boundary_verified | Request issuer must match the independently authenticated client. |
| [CIBA-053](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のexp | protocol_boundary_verified | Missing/noninteger/expired exp rejected under configured time tolerance; numeric-date restriction is documented. |
| [CIBA-054](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のiat | partial | Required integer iat and future-time rejection are stricter than measured node defaults; no claim of exact acceptance parity. |
| [CIBA-055](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のnbf | protocol_boundary_verified | Required integer nbf and not-before check enforced under configured time tolerance. |
| [CIBA-056](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のjti | partial | Nonempty jti is required; uniqueness remains a client obligation. Reusing a valid signed JWT creates distinct pending requests in both implementations, without reusing approval. This is not a one-use request ledger. |
| [CIBA-057](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のrequested_expiry型 | protocol_boundary_verified | Integer and numeric-string requested_expiry are accepted through the ordinary expiry validator. |
| [CIBA-058](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求の内外混在禁止 | client_only | Client must place authentication request parameters inside the JWT. OP ignores nonconforming outer protocol values rather than merging them; separate client authentication remains outside. Do not classify tolerated client input as evidence of client compliance. |
| [CIBA-059](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 暗号化要求非対応 | protocol_boundary_verified | Five-part encrypted request shape is rejected; only three-part signed JWT requests enter verification. |
| [CIBA-066](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 署名要求検証 | partial | Signature, required claims, key selection and bounded parsing are tested. These cases do not exhaust every JWT/profile requirement, all key types or deployment key-management behavior. |


## Hintの再確認

追加11項目。login_hint_tokenはアプリの形式・検証方針に委ね、ID Token hintは
署名等を検証する独立した経路として確認した。期限切れcallbackと予期しない
障害を区別する回帰を追加。公開文書に残っていた「id_token_hint未対応」の
記述も現在のopt-in構成に訂正した。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-038](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | login_hint_token | protocol_boundary_verified | Authenticated client is passed to the required application resolver; identity eligibility and raw-value exclusion are checked. Token-format validation belongs to the application. |
| [CIBA-039](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | id_token_hint | protocol_boundary_verified | Verified ID Token identity creates a new pending request; approval is not inherited. |
| [CIBA-040](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 暗号化id_token_hintの復号 | client_only | Decrypting an encrypted ID Token before submitting its signed inner token is a Client duty. A real nested JWE is rejected by the gem; the decrypted signed hint is accepted. This matches measured node behavior, not missing OP decryption support. |
| [CIBA-141](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 expired_login_hint_token | protocol_boundary_verified | Application expiry errors become HTTP400 expired_login_hint_token; unexpected resolver errors become HTTP500 without pending records or dispatch. The gem does not infer arbitrary token expiry. |
| [CIBA-149](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | login_hint_token署名 | app_contract | Issuer-signature policy is delegated to the token-format resolver. Existing fixtures use opaque references and do not prove signature validation for a production login_hint_token format. |
| [CIBA-151](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | 期限切れid_token_hint許容 | partial | Expired ID hints are accepted, with optional maximum age from iat. Default unlimited age while keys remain trusted matches the measured reference; deployment-specific reasonable retention has not been established. |
| [CIBA-152](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | id_token_hintのissuerとaudience | protocol_boundary_verified | Trusted OP issuer and authenticated-client audience membership are verified before subject resolution; wrong issuer/audience are rejected. |
| [CIBA-153](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | id_token_hint署名 | protocol_boundary_verified | Configured asymmetric/Edwards signatures use trusted current or retained OP keys; HMAC issuance and hint verification use the client secret, with no OP-key fallback. Actual issuance/reuse and wrong-key rejection have direct tests. HMAC Basic/POST and hashed/plaintext storage pass three-DB and independent jose checks; installed-gem issuance/refresh/hints and backend secret replacement pass, as do Ruby 3.3/3.4 full suites. DCR generates sufficiently long HS256/384/512 secrets. This verifies the signature boundary, not all deployment rotation policies. Encrypted hints are rejected by both implementations; optional signature-free pairwise acceptance is not required by this catalog guidance. |
| [CIBA-157](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | pairwise ID Token hint | protocol_boundary_verified | Actual signed pairwise ID Token maps through an application resolver to a canonical account and creates a request without saved consent. Arbitrary resolver correctness is not proven. |
| [CIBA-158](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | 一回限り識別子hint token | app_contract | The optional AD-to-CD one-use reference protocol is not implemented. A resolver hook can integrate it; its existence does not prove atomic single-use handling or privacy properties. |
| [CIBA-159](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | Discovery Service hint token | app_contract | The optional discovery-service encrypted login_hint_token format is not implemented. Decryption and issuer/audience policy belong to an application resolver; no complete deployment has been tested. |

[hint試験](validation/hint-audit-current.txt)と[pairwise hint試験](validation/pairwise-hint-audit.txt)は成功。アプリが実装していないtoken形式やClientの義務を、gemの合格項目には数えない。


## Pingの再確認

追加16項目。通知データと再試行の境界、Client側のentropy／受信検証、
アプリ側の通知URL管理権限確認を分けた。1024文字の許容とBearer構文、
CRLF等の拒否の回帰を追加した。[今回の試験](validation/ping-audit-current.txt)。
実TLS・redirect拒否は既存の[配布ログ](validation/mtls-remote-installed-final.txt)
と対応するfixtureを確認した。response bodyの上限は意図的な制約として残る。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-011](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 通知URL登録 | protocol_boundary_verified | Ping client eligibility requires an HTTPS registered endpoint; changed destinations cannot receive saved credentials. Push is not implemented. |
| [CIBA-020](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | ping配送 | protocol_boundary_verified | Approval/denial persists before notification; authenticated retrieval remains possible despite send failure. This matches the measured reference save-before-send boundary. |
| [CIBA-033](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 通知トークン必須条件 | protocol_boundary_verified | Ping requires a nonempty notification token before persistence. Push remains outside the implementation. |
| [CIBA-034](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 通知トークンの長さと構文 | protocol_boundary_verified | Bearer syntax and1024-character ASCII boundary checked; CRLF, misplaced padding and non-ASCII rejected without pending records. |
| [CIBA-035](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 通知トークンentropy | client_only | Required entropy is a client generation obligation. No syntax or length check can prove randomness. Minimum128/recommended160 bits are documented. |
| [CIBA-097](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | pingクライアントのpoll許容 | protocol_boundary_verified | Ping requests can be polled while pending and after approval; no successful notification receipt is needed to collect a saved result. |
| [CIBA-105](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping HTTP POST | protocol_boundary_verified | Application completion sends POST for approval and denial after commit. Expiry does not require a callback. Transaction rollback sends none. |
| [CIBA-106](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping bearer認証 | protocol_boundary_verified | Outgoing Authorization Bearer contains the request notification token; signed requests cannot be overridden by an outer value. |
| [CIBA-107](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping payload | protocol_boundary_verified | Only auth_req_id is sent as JSON; no tokens or consent payload accompany a ping. |
| [CIBA-108](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | pingクライアント検証 | client_only | Receiver validation of bearer/auth_req_id association and invalid-bearer401 is outside this OP. Existing sender tests do not establish a production receiver implementation. |
| [CIBA-109](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping応答処理 | partial | 200 and204 are accepted without interpreting response content. Shared transport still reads a bounded response and may reject oversized bodies; arbitrary-body equivalence is not claimed. |
| [CIBA-110](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | pingリダイレクト禁止 | protocol_boundary_verified | Shared HTTP transport issues one request with no redirect handling. Installed TLS smoke rejects302 and sends only on explicit retry; this is not merely a mock assertion. |
| [CIBA-111](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping後の取得 | client_only | The client retrieves tokens after validating a notification. OP tests demonstrate retrieval works, not that every client performs the required validation. |
| [CIBA-112](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.9) | 通知Endpoint TLS | protocol_boundary_verified | Ping endpoints require HTTPS; installed smoke uses verified TLS and rejects an untrusted receiver before credentials arrive. Arbitrary deployments remain application-owned. |
| [CIBA-113](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.9) | 通知Endpoint bearer認証 | protocol_boundary_verified | Ping sends the saved client_notification_token as Bearer; receiver verification remains a separate client duty. |
| [CIBA-150](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | 通知URLの管理権限 | app_contract | Application should establish notification endpoint administrative ownership. HTTPS/IP filtering and immutable destination snapshots are not proof of client ownership; no universal ownership protocol is supplied. |


## Pairwiseの再確認

3項目を追加。自己署名mTLSの組合せ拒否を再現・修正したが、署名要求だけで別の認証方式を許可する経路は参照版も拒否する。[登録比較](research/pairwise-reference-contract.md#signed-requests-do-not-replace-pairwise-client-authentication)で共通の制限と確認したため、未解消の参照差分とは扱わない。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-015](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | pairwise sector算出 | protocol_boundary_verified | CIBA sector derives from registered remote JWKS or explicit sector URI, rather than redirect URI; nondefault port matches measured node URL.host behavior. Application owns identifier mapping. |
| [CIBA-016](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | pairwise DCR検証 | protocol_boundary_verified | Pairwise registration requires remote JWKS and validates explicit sector-document membership; hybrid browser clients include their redirect URIs. Verified TLS, redirect limits and rejection cases have installed-artifact evidence. |
| [CIBA-017](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | pairwise鍵所有証明 | partial | private_key_jwt and self-signed TLS authenticate with registered remote key material. Self-signed TLS has actual reference and installed DCR/HTTPS tests. Signed-request-only proof using another authentication method remains unsupported. |

[実装・失敗からの修正・検証範囲](research/mtls-reference-contract.md#pairwise-self-signed-tls-client-authentication)。

## Token交換の再確認

CIBA Core §10.1–10.1.1の7項目を、現在の実装と直接テストで再確認。
成功応答のtoken_type／expires_in／cache headersと、未承認応答にtokenが
含まれないことを明示的なアサーションに追加した。
SQLite・PostgreSQL・MySQLの各DBで8 tests / 129 assertions、失敗なし。
[実行ログ](validation/token-exchange-audit-current.txt)。
参照OPの非トランザクションadapterとの障害時差分や任意機能の組合せは、
既存の整合化計画で引き続き扱う。今回の結果はそれらの解消を意味しない。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-098](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token POST form | protocol_boundary_verified | A form-encoded POST with non-rewindable Rack input successfully redeems an approved request. This is positive transport evidence, not an exhaustive charset or malformed-media matrix. |
| [CIBA-099](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token grant_type必須 | protocol_boundary_verified | Missing grant_type fails with invalid_request; successful requests use the exact CIBA grant value. Other OAuth grants retain their upstream dispatch. |
| [CIBA-100](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token auth_req_id必須 | protocol_boundary_verified | Missing and empty auth_req_id fail with invalid_request; an unissued identifier fails with invalid_grant without token persistence. |
| [CIBA-101](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | auth_req_idのクライアント束縛 | protocol_boundary_verified | The request lookup binds its digest to the authenticated client. A different authenticated client cannot redeem it or alter the request; wrong account completion and exact expiry also reject issuance. |
| [CIBA-102](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1) | 成功Token応答 | protocol_boundary_verified | Approved baseline issuance returns access_token, signed issuer/audience-verified ID Token, bearer token type, positive integer lifetime and no-store/no-cache headers. This does not certify every optional claims/resource/sender-binding combination. |
| [CIBA-103](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1) | 成功後の一回限り消費 | protocol_boundary_verified | Sequential redemption is rejected after success. Ten two-connection races per DB each yield exactly one successful signed response and one invalid_grant, with one grant per request. Arbitrary hooks and distributed adapters are outside this test. |
| [CIBA-104](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1) | 認証承認前のToken禁止 | protocol_boundary_verified | Pending, throttled-pending and denied requests return errors without access_token, id_token or refresh_token and create no OAuth grant. Customer authentication itself is supplied through the application completion boundary. |

## 受付応答の再確認

10項目を再分類。整数値の上限・型の回帰を追加し、5 tests / 74 assertionsが成功。
[実行ログ](validation/acknowledgement-audit-current.txt)。entropyは乱数生成コードと
プラットフォームCSPRNGへの依存に基づく判断であり、少数サンプルの統計的証明ではない。
期限の起点は検証後に記録されるため、要求受信からの時間を厳密に検証済みとはしない。
参照9.12.2もrequest保存後、device callback前にexpires_inを構築し、intervalは省略する
（lib/actions/authorization/ciba.js）。[時刻起点の実測比較](research/acknowledgement-time-contract.md)で一致を確認。通知処理が寿命を超えると、両者とも受付応答後のpollが期限切れになる共通制約がある。CIBA-080の規範上のpartial判定は維持する。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-075](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | 受付成功HTTP 200 | protocol_boundary_verified | Validated baseline requests return HTTP 200; invalid hints, scopes and unsupported parameters do not receive successful acknowledgement. |
| [CIBA-076](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_id必須と一意性 | protocol_boundary_verified | Each accepted request receives a fresh base64url identifier. Its SHA256 digest has a database unique constraint; two observed identifiers differ. Forced RNG collision recovery is not tested. |
| [CIBA-077](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_id entropy | protocol_boundary_verified | Source review confirms SecureRandom.urlsafe_base64(32), supplying 256 random input bits. Tests check encoding and distinct samples, not statistical entropy or the platform RNG implementation. |
| [CIBA-078](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_id文字集合 | protocol_boundary_verified | The 43-character unpadded base64url output uses only the permitted character set; direct response assertions cover the encoding. |
| [CIBA-079](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_idのopaque扱い | client_only | Opaque handling is a Client obligation. The OP generation test cannot prove how external clients interpret or store identifiers. |
| [CIBA-080](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | expires_in | partial | Positive integer lifetime, configured maximum and exact expiry are tested. The gem records its timestamp after client/hint validation; elapsed time before that timestamp is not accounted for as request-receipt time. Therefore the catalog requirement is only partially established. |
| [CIBA-081](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | interval | protocol_boundary_verified | Returned interval is an integer: 1, 5 and the configured 32-bit maximum are accepted. Zero, negative, fractional, string and overflow configuration values are rejected. The reference OP omits this optional field; the gem explicitly advertises its polling policy. |
| [CIBA-082](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | interval既定値 | client_only | The five-second fallback when interval is omitted is a Client obligation; the gem normally returns an explicit interval. |
| [CIBA-083](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | 未知応答パラメータ | client_only | Ignoring unknown acknowledgement fields is a Client obligation, not evidence about OP request-parameter parsing. |
| [CIBA-084](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.4) | 受付応答の必須項目確認 | client_only | Client validation of required HTTP200 acknowledgement fields is outside this OP gem; valid gem responses do not prove client validation. |

## Discoveryと登録の再確認

9項目を追加。独自routeを両Discoveryから取得して実際に利用する回帰と、
static clientの未設定／複数配送モード拒否を追加した。
[実行ログ](validation/discovery-registration-audit-current.txt)：9 tests / 93 assertions成功。
全認証方式・全アルゴリズムの組合せを網羅したとは扱わない。
初期カタログの「CIBA DCR拒否」を、現行のopt-in DCR成功と無効metadata拒否の証拠に更新した。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-001](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | CIBA grant識別子 | protocol_boundary_verified | The standard CIBA grant identifier appears in both metadata documents and drives successful authenticated token dispatch alongside the existing authorization-code flow. |
| [CIBA-002](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | Discoveryの対応モード | protocol_boundary_verified | Default discovery advertises poll only; enabling ping advertises poll and ping. Push is not advertised. Both metadata documents agree in the custom-route test. |
| [CIBA-003](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | Discoveryの開始URL | protocol_boundary_verified | A configured custom Backchannel route is advertised in OAuth and OIDC discovery, and an actual request to that discovered URL creates the pending record. Deployment proxy/alias rewriting is audited separately. |
| [CIBA-006](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | Discoveryのgrant_types | protocol_boundary_verified | Both discovery documents include the CIBA grant identifier while preserving upstream grants. |
| [CIBA-007](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 認証方式メタデータの共有 | partial | OIDC and OAuth discovery preserve the same upstream token-endpoint authentication method metadata. Basic, post and private_key_jwt routes have direct evidence, with separate mTLS evidence; no exhaustive enabled-method combination matrix is established. Confidential-client eligibility remains CIBA-scoped. |
| [CIBA-008](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 認証署名アルゴリズムの共有 | partial | The upstream authentication signing-algorithm metadata is preserved in both documents and advertised RS256 private_key_jwt authenticates on both endpoints. Exhaustive algorithm-by-authentication-method coverage is not established. |
| [CIBA-009](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 登録済み配送モード | protocol_boundary_verified | Static clients with missing, multiple or push delivery-mode values fail eligibility before persistence. DCR also rejects missing or unavailable modes without inserting a client; enabled ping has separate acceptance evidence. |
| [CIBA-010](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | CIBA grantのクライアント登録 | protocol_boundary_verified | A static client lacking the CIBA grant is rejected. Opt-in DCR with the CIBA grant creates a client that successfully starts, approves and redeems a request. This supersedes the initial audit evidence that DCR CIBA was wholly unavailable. |
| [CIBA-014](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 登録された認証方式 | partial | Registered Basic, client_secret_post and private_key_jwt authenticate at both endpoints in the executed tests. Self-signed/PKI TLS have separate existing evidence. Arbitrary method and extension combinations remain outside this subset. |

## Push条件付き要件の分類

18項目を再分類。参照9.12.2はpush設定を拒否し、gemも広告・登録・利用を拒否する。
reference_unsupportedは参照版との共通の非対応範囲を表し、合格件数ではない。
元の要件IDは保持し、対応モードや比較対象を変える場合は再検討する。
[比較と試験](research/push-reference-boundary.md)。

| ID | 対象 | 判定 |
|---|---|---|
| [CIBA-018](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | push pairwise sector | reference_unsupported |
| [CIBA-021](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | push配送 | reference_unsupported |
| [CIBA-022](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | push sender-constrained token | reference_unsupported |
| [CIBA-114](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push成功payload | reference_unsupported |
| [CIBA-115](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push at_hash | reference_unsupported |
| [CIBA-116](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push auth_req_id claim | reference_unsupported |
| [CIBA-117](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push rt_hash | reference_unsupported |
| [CIBA-118](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push受信検証 | client_only |
| [CIBA-119](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push応答処理 | reference_unsupported |
| [CIBA-120](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | pushリダイレクト禁止 | reference_unsupported |
| [CIBA-121](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push未知パラメータ | client_only |
| [CIBA-130](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | pushクライアントのToken拒否 | protocol_boundary_verified |
| [CIBA-131](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | pushエラーJSON | reference_unsupported |
| [CIBA-132](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push error_description文字集合 | reference_unsupported |
| [CIBA-133](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push access_denied | reference_unsupported |
| [CIBA-134](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push expired_token | reference_unsupported |
| [CIBA-135](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push transaction_failed | reference_unsupported |
| [CIBA-154](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | push Endpoint保護 | reference_unsupported |

## エラー応答の再確認

15項目を追加。早期認証エラーのCache-Control欠落を修正し、3 DB各30 tests /
590 assertions成功。[実装差分と限界](research/error-response-reference-contract.md)。
参照版のPragma省略と、client identity未指定時のHTTPステータス差は別途明記した。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-122](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | Tokenエラー形式 | protocol_boundary_verified | Required-parameter and unknown-request errors are JSON with cache suppression and no error_uri. Early authentication halts now receive no-store/no-cache from the CIBA HTTP boundary. |
| [CIBA-123](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | authorization_pending | protocol_boundary_verified | Pending requests return authorization_pending and persist polling timestamps without issuing tokens. |
| [CIBA-124](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | slow_down | partial | Repeated early pending polls return slow_down and add five seconds to the saved interval, including concurrent calls. The reference delegates polling control to application policy; identical default throttling behavior is not claimed. |
| [CIBA-125](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | expired_token | protocol_boundary_verified | An approved request at its exact expiry returns expired_token without issuing a grant. |
| [CIBA-126](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | access_denied | protocol_boundary_verified | Application denial returns access_denied on poll. This is token retrieval after denial, distinct from pre-interaction HTTP403 policy rejection. |
| [CIBA-127](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | invalid_grant | protocol_boundary_verified | Unknown request identifiers and identifiers owned by another authenticated client return invalid_grant without issuing tokens or mutating the foreign request. |
| [CIBA-136](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 開始エラーJSON | protocol_boundary_verified | Six rejection/failure paths return JSON with ASCII error codes, no tokens or request identifiers, and cache suppression. Unexpected exceptions do not expose their messages. |
| [CIBA-137](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | error_description文字集合 | protocol_boundary_verified | Allowed ASCII error descriptions survive; quotes, backslashes, newlines and non-ASCII custom descriptions are omitted. |
| [CIBA-138](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | error_uri文字集合 | partial | The tested upstream responses do not emit error_uri. No custom URI injection mechanism or URI-syntax sanitizer is established; the conditional field is absent rather than positively validated. |
| [CIBA-139](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_request | protocol_boundary_verified | Missing or malformed parameters, duplicate form fields and conflicting hints return HTTP400 invalid_request. Specific optional hint combinations have separate evidence. |
| [CIBA-140](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_scope | protocol_boundary_verified | Missing scope returns invalid_request; present malformed or disallowed scopes return HTTP400 invalid_scope. |
| [CIBA-142](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 unknown_user_id | protocol_boundary_verified | A validly shaped but unresolved login_hint returns HTTP400 unknown_user_id before request persistence. |
| [CIBA-143](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 unauthorized_client | protocol_boundary_verified | Clients lacking CIBA eligibility return HTTP400 unauthorized_client without creating requests; registered mode and grant changes are checked. |
| [CIBA-146](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_binding_message | protocol_boundary_verified | An oversized binding message returns HTTP400 invalid_binding_message before request persistence. Application-specific acceptable message content is separately configurable. |
| [CIBA-147](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 401 invalid_client | partial | Absent and incorrect Basic credentials return HTTP401 invalid_client; challenge headers have direct assertions. The reference returns HTTP400 when no client identity is supplied but HTTP401 for wrong Basic credentials, so not every unauthenticated wire response is identical. |

## 開始要求パラメーターの再確認

20項目を再分類。非email hint、内部列名に似た未知入力の無視、ACR順序と
達成ACRの区別を追加確認。[試験](validation/request-parameters-audit-current.txt)：
13 tests / 240 assertions成功。AD/CD表示とhint利用契約はアプリ／Clientの責務として保持。
広範な「全パラメーター検証」の要求は任意機能の未解消条件まで合格扱いにしない。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-030](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | scope必須 | protocol_boundary_verified | Missing scope fails before acceptance; malformed scope has a distinct invalid_scope response. |
| [CIBA-031](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | openid scope | protocol_boundary_verified | A scope set without openid is rejected for CIBA. |
| [CIBA-032](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 追加scope | protocol_boundary_verified | An additional read scope allowed by both server and client survives acceptance and issuance. |
| [CIBA-036](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | acr_values受理 | protocol_boundary_verified | Requested ACR preference order is retained in the frozen application dispatch snapshot; the gem does not choose an authentication method. |
| [CIBA-037](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 達成したacrの返却 | protocol_boundary_verified | ID Token carries the achieved ACR supplied at completion, even when different from requested preferences. Truthfulness and adequacy of the application authentication are not proven. |
| [CIBA-041](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | login_hint | protocol_boundary_verified | A non-email customer reference resolves through an application callback in authenticated-client context. No built-in email interpretation is required. |
| [CIBA-042](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | binding_messageの受理と引継ぎ | app_contract | Binding message is preserved for the application dispatch snapshot. Display on AD/CD, safe rendering and end-user confirmation remain application/client duties, not proven by the Ruby snapshot test. |
| [CIBA-043](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | binding_messageの関連付け | client_only | The client must choose a meaningful correlation message. OP storage and dispatch cannot prove the correlation seen by the end-user. |
| [CIBA-044](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | binding_messageの表示適性 | protocol_boundary_verified | The default node-aligned policy accepts 1–20 characters from its limited ASCII set and rejects whitespace, control and other characters. Applications may replace this display policy and own the resulting UI safety. |
| [CIBA-046](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | requested_expiry構文 | protocol_boundary_verified | Unsigned requested_expiry accepts positive decimal syntax and rejects zero, negatives, fractions and nonnumeric strings. Signed JSON-number handling is audited separately. |
| [CIBA-047](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | requested_expiryの採用 | protocol_boundary_verified | Requested lifetime is used up to the configured maximum; the default and cap are directly asserted. Callback elapsed-time limits remain in CIBA-080. |
| [CIBA-048](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | hintはちょうど一つ | protocol_boundary_verified | Exactly one recognized hint name is required; absent, empty and mixed hint inputs fail before resolver dispatch. The opt-in token resolver tests validate this with optional hints enabled. |
| [CIBA-067](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 認証要求パラメータ検証 | partial | Baseline scope, hint, binding and lifetime validation and unknown-field handling are directly checked. This broad requirement also covers optional extensions whose unresolved limits remain in their individual audit rows. |
| [CIBA-068](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 複数hintのエラー | protocol_boundary_verified | Multiple hint names return invalid_request before resolving or saving the request, including opt-in login_hint_token combinations. |
| [CIBA-069](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | hintとユーザーの検証 | protocol_boundary_verified | Resolved accounts must remain eligible; a disabled account is rejected and a different completion account cannot approve the request. Arbitrary resolver correctness is application-owned. |
| [CIBA-070](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | hintポリシーの伝達 | app_contract | Accepted hint formats, issuer trust and age policy must be communicated by each deployment. Documentation describes the integration responsibility; no production client agreement is tested. |
| [CIBA-071](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 不正または不明hintのエラー | protocol_boundary_verified | Malformed hints return invalid_request; well-shaped unresolved hints return unknown_user_id before persistence. |
| [CIBA-072](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 必須パラメータ検証 | partial | Missing/empty scope and hint requirements are exercised; optional feature-specific required parameters are covered in their own rows rather than inferred from this baseline subset. |
| [CIBA-073](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 未知パラメータの無視 | protocol_boundary_verified | Unknown parameters are ignored, including names resembling internal account, status and expiry fields. They neither override persisted state nor appear in the application snapshot. |
| [CIBA-074](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 開始エラーの形式 | protocol_boundary_verified | Validation failures produce JSON protocol errors with the expected HTTP status and no token/request identifiers. Internal exceptions return server_error without private text. |

## 通信と認証の再確認

11項目を追加。両endpointの非TLS／JSON／GET拒否と無変更を追加確認。
[実行ログ](validation/auth-transport-audit-current.txt)：15 tests / 123 assertions成功。
JWT audienceの3種類の受理は実行したfixtureの方式に限定し、全アルゴリズム
組合せの証明にはしない。実TLSとproxyの導入境界は既存契約で別途追跡する。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-019](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | poll配送 | protocol_boundary_verified | Approved poll requests obtain a signed ID Token and access token through the token endpoint, followed by single-use rejection. |
| [CIBA-023](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7) | 開始APIのTLS | protocol_boundary_verified | Authenticated HTTP requests are rejected before state changes; HTTPS Rack requests are accepted. Actual TLS termination and trusted proxy configuration remain deployment responsibilities with separate TLS fixtures. |
| [CIBA-024](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 開始APIのPOSTとform | protocol_boundary_verified | HTTPS POST form input is accepted, including non-rewindable request bodies. JSON and GET do not issue requests or tokens; malformed UTF8/form input is rejected. Backchannel GET is 404, token GET with CIBA grant is invalid_request. |
| [CIBA-025](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 開始APIのクライアント認証 | partial | JWT assertion required claims, signature handling, replay and explicit-client binding have direct negative tests. Basic/post and TLS have separate flow evidence; this does not exhaust every enabled upstream method or algorithm. |
| [CIBA-026](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのissuer受理 | protocol_boundary_verified | Issuer audience is accepted for private_key_jwt at Backchannel and for private_key_jwt/client_secret_jwt CIBA issuance and refresh; unrelated token flows retain their prior audience rules. |
| [CIBA-027](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのToken URL受理 | protocol_boundary_verified | Token endpoint URL is accepted as private_key_jwt audience at Backchannel, then the same client can complete and collect tokens. |
| [CIBA-028](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのBackchannel URL受理 | protocol_boundary_verified | Backchannel endpoint URL is accepted as private_key_jwt audience at Backchannel; resulting approved issuance succeeds. |
| [CIBA-029](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのissuer推奨 | client_only | The recommendation to choose issuer audience is a client responsibility. OP acceptance tests establish support but do not prove external clients follow the recommendation. |
| [CIBA-064](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 登録方式による認証検証 | partial | Registered client_secret_post and private_key_jwt are exercised at both endpoints with failed-assertion cases. All-method/algorithm combinations remain unproven rather than inferred from shared metadata. |
| [CIBA-065](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 公開鍵認証の推奨 | app_contract | Prefer public-key client authentication when provisioning clients. The gem supports asymmetric methods but intentionally does not prohibit shared-secret authentication across the OP; deployment selection is not proven by feature support. |
| [CIBA-090](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token Endpoint認証 | protocol_boundary_verified | Token collection without client authentication is rejected without issuing a grant; registered assertion and post authentication succeed. CIBA authentication rejects replayed assertions and inappropriate explicit client identity. |

## アプリ・Client責務と任意poll機能の分類

最後の16項目を分類。これでカタログ全159 IDに現時点の判定があるが、partial／
app_contract／client_only／reference_unsupportedを合格に数えてはいけない。
[試験](validation/application-boundaries-audit-current.txt)：13 tests / 116 assertions成功。
[参照版の明示403と既定400](validation/node-application-boundaries.txt)を区別し、
アプリのエラー選択が必要なことをAPI文書へ記載した。

| ID | 対象 | 判定 | 根拠・限界 |
|---|---|---|---|
| [CIBA-085](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.4) | auth_req_id保持 | client_only | External clients must retain auth_req_id. OP storage is not evidence of client persistence. |
| [CIBA-086](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.4) | クライアント期限管理 | client_only | Callback cleanup and expiry tracking belong to the client; no production client cleanup is tested. |
| [CIBA-087](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8) | 認証チャネルとacrの選択 | app_contract | The dispatch snapshot exposes requested ACR preferences and the resolved account. Channel selection and actual authentication assurance remain application-owned. |
| [CIBA-088](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8) | 認証後の承認取得 | app_contract | The gem prevents issuance before explicit approval and checks the completion account. Authenticating the human and obtaining informed consent are application responsibilities, not established by an internal API call. |
| [CIBA-089](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10) | 登録モード以外へ配送しない | partial | Static poll/ping eligibility and saved ping destination checks prevent unsupported delivery. Full mode/endpoint management changes overlapping completion and callback retries are not exhaustively tested. |
| [CIBA-091](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | クライアントpoll間隔 | client_only | The client must obey the minimum polling interval. Server slow_down enforcement does not prove client compliance. |
| [CIBA-092](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | long polling | reference_unsupported | Neither the selected node grant handler nor the gem implements a wait-for-result long-poll loop; pending requests return an error. The optional long-poll capability is not claimed. |
| [CIBA-093](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | OP応答時間 | partial | No hard 30-second request deadline is provided for arbitrary application hooks, DB waits or deployments. Prompt pending replies in tests do not prove the operational response-time recommendation. |
| [CIBA-094](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | 重複poll禁止 | client_only | Clients must not overlap requests for one auth_req_id. Defensive concurrent redemption tests do not prove external client behavior. |
| [CIBA-095](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | 503とRetry-After | protocol_boundary_verified | Injected DB lock timeout at acceptance and issuance yields 503 temporarily_unavailable with Retry-After and rolls back pending/grant mutation. This does not establish all production overload behavior. |
| [CIBA-096](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Retry-After遵守 | client_only | Respecting Retry-After is a client duty. Emitting the header does not establish client retries. |
| [CIBA-128](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | 繰返し過剰pollの拒否 | reference_unsupported | Optional terminal invalid_request after repeated fast polling is not implemented by either baseline. Gem continues slow_down with interval increases; node pending handler has no equivalent built-in throttling. |
| [CIBA-129](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | invalid_request後の停止 | client_only | Stopping polls after invalid_request is an external client duty, not an OP feature. |
| [CIBA-148](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 403 access_denied | app_contract | An explicit application rejection can send HTTP403 access_denied before persistence or device dispatch. The reference supports explicit OIDCProviderError(403), while its default AccessDenied is 400; gem ProtocolError also defaults to 400. Application policy must choose the appropriate status. |
| [CIBA-155](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | 業務コンテキストの追加 | protocol_boundary_verified | Opt-in request_context is validated in authenticated client context, stored and dispatched; signed input controls it, poll cannot replace it, and it is excluded from identity claims and observation events. Business meaning remains application-specific. |
| [CIBA-156](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | プライバシー配慮識別子 | app_contract | App-defined opaque login_hint references and token resolvers support alternatives to global identifiers. Actual unlinkability, identifier lifetime and privacy policy are not guaranteed by accepting an arbitrary string. |

## Edwards署名の追加証拠

CIBA-050をconfiguredアルゴリズムのprotocol_boundary_verifiedへ更新。
Node/joseの固定署名をinline／実HTTP remote鍵で受理し、payload改ざんを拒否。
3 DB各4 tests / 108 assertions成功。配布gemでも両alg × opaque/JWT構成で
開始・承認・署名検証済みID Token発行まで成功した。
[DB](validation/edwards-vectors-matrix.txt)、[配布](validation/edwards-installed.txt)。
現在の分類は検証した境界88、partial21、アプリ責務13、Client責務20、参照非対応17。
Ed448・汎用JWT署名・Edwards client authenticationを対応済みとはしない。

## Ping応答bodyの差分解消

CIBA-109をprotocol_boundary_verifiedへ更新。通知時だけbodyを読み取らず
接続を閉じることで、参照版同様に200/204をbodyに依存せず判定する。
実TCPの未送信body、配布gemと参照OPの140,000-byte bodyを検証。
[比較契約](research/ping-reference-contract.md#ignored-response-body-parity)。
現在は検証した境界89、partial20、アプリ責務13、Client責務20、参照非対応17。

## Client assertionの有限アルゴリズム行列

CIBA-008をconfigured12アルゴリズムのprotocol_boundary_verifiedへ更新。
RS/PS/ES各3種とHS3種を明示設定し、Discovery一致・両endpointの別鍵拒否・
gemでの発行まで確認した。方式全体のpartial判定はlegacy URN等を残して維持。
[比較契約](research/client-assertion-algorithm-contract.md)。
現在は検証した境界101、partial7、アプリ責務14、Client責務20、参照非対応17。

## ping 管理更新の整合化（CIBA-089）

参照実 OP の管理 PUT と実 TLS 通知を重ねた試験から、通知先変更後の
再送は現在登録されている endpoint を使うと確認した。gem の要求受付時
endpoint 固定を外して整合化。poll 変更後の再送拒否、進行中送信の選択済み
endpoint 保持、token の一度だけの取得を確認したため CIBA-089 を
protocol_boundary_verified に更新する。分散 cache の整合性や network
送信の取り消しを保証する判定ではない。

[参照](validation/node-ping-management.txt)、
[変更前の失敗](validation/ping-current-endpoint-red.txt)、
[3 DB 各9 tests /124 assertions](validation/ping-current-endpoint-matrix.txt)、
[配布 gem の既存 TLS 検証](validation/ping-current-endpoint-installed.txt)。
配布検証は runtime 変更後の成果物を対象とし、その後の説明文更新は含まない。

## 署名要求の NumericDate 整合化（CIBA-053〜055）

integer-only と未来 iat 拒否を外し、有限の numeric exp/iat/nbf を受理する。
未来 nbf と期限切れ exp は拒否し、要求受理から承認を経ずに token を取得
できないことも検証した。CIBA-054 を protocol_boundary_verified に更新。
[参照 HTTP](validation/node-signed-numericdate.txt)、
[変更前の失敗](validation/signed-numericdate-red.txt)、
[3 DB 各12 tests /251 assertions](validation/signed-numericdate-matrix.txt)。
時刻検証の共通部分を変更し、ID hint・client assertion には変更していない。

## 認証失敗と識別情報欠落の分離（CIBA-147）

CIBA の両 endpoint で識別情報がない場合を400 invalid_requestへ整合化。
誤った Basic 資格情報は401 invalid_clientとchallengeを維持する。
[参照 HTTP](validation/node-missing-client.txt)、
[変更前の失敗](validation/missing-client-red.txt)、
[3 DB 各24 tests /535 assertions](validation/missing-client-matrix.txt)。
JWT assertionからの識別、mTLS、通常OAuthの回帰試験を含む。CIBA-147は
protocol_boundary_verifiedへ更新し、複数の不正入力が同時にある場合の
すべてのエラー優先順位まで一致すると主張しない。

## Edwards HTTPS と認証設定の適用範囲

CIBA-014/025/064を、実行した認証方式・14署名アルゴリズムの範囲で
protocol_boundary_verifiedへ更新。配布gemの実HTTPS鍵取得・非信頼TLS拒否・
両endpoint認証と、CIBA設定が無関係なRSAクライアントに制限を適用しない
ことを確認した。CIBA-007は上流の旧assertion-type URN広告が残るためpartial。
[配布HTTPS](validation/client-auth-edwards-https-installed.txt)、
[3 DB 各5 tests /114 assertions](validation/client-auth-edwards-scope-matrix.txt)。
CIBA-011/033の改名前pingテスト参照も現行名へ修正した。

## 認証方式メタデータの最終整合化（CIBA-007）

OAuth/OIDC両Discoveryから、認証方式ではないassertion-type URNを除外。
実際のupstream認証処理は変更せず、残りの方式リストが一致することを
検証した。CIBA-007をprotocol_boundary_verifiedへ更新。
[red](validation/client-auth-metadata-urn-red.txt)、
[参照](validation/node-client-auth-metadata-urn.txt)、
[3 DB 各4 tests /162 assertions](validation/client-auth-metadata-urn-matrix.txt)。

## 署名要求のjti（CIBA-056）

参照実装と同じく文字列jtiを要求し、空文字を受理、null/非文字列を拒否。
同一署名要求の再送では新しいauth_req_idと承認待ち状態になり、以前の
承認・発行を引き継がないことを検証した。client assertionの非空jti・
replay防止は別経路として維持。CIBA-056を検証したOP境界として更新し、
クライアントの一意な識別子生成まで保証したとは扱わない。
[参照](validation/node-signed-jti.txt)、[red](validation/signed-jti-red.txt)、
[3 DB 各15 tests /290 assertions](validation/signed-jti-matrix.txt)。

## pairwise／署名検証の証拠再確認と応答時間責務

CIBA-017/066をprotocol_boundary_verifiedへ更新。pairwiseの2方式と署名要求の
11アルゴリズムについて、現行実装・既存の負例・独立署名ベクトル・参照実装
の証拠を確認し、3 DBで関連31テストを再実行した。SQLite639 assertions、
PostgreSQL/MySQL637 assertions、失敗・error・skipなし。
[実行ログ](validation/pairwise-signature-audit-current.txt)。
任意のJOSE profileや本番の鍵管理まで保証する判定ではない。

CIBA-093は元のカタログのgem+deployment責務を再確認し、app_contractへ分類。
30秒以内の本番応答を実証した意味ではない。[導入責務](operations.md#poll-response-time-deployment-contract)
にserver/DB/hookの合計待ち時間、測定、commit後timeoutの扱いを明記した。

### HMAC signature integration evidence

CIBA-153 is verified for the configured signature boundary. The [three-DB subset](validation/hmac-registration-secret-matrix.txt) passes10 tests/439 assertions per DB. [Ruby3.3/3.4](validation/hmac-id-token-rubies.txt) each pass354 tests/5,847 assertions with two SQLite row-lock skips. The [installed artifact](validation/hmac-id-token-installed.txt) covers12 HMAC configurations and backend secret replacement; this is not a standard rotation endpoint or remote-cache parity claim.

## 必須パラメーターの棚卸し

[CIBA-072 の一覧](research/required-parameter-inventory.md)を対応する実装・試験と照合し、必須入力と hint の排他選択を検証済みに更新した。CIBA-067 も[対応パラメーター一覧](research/request-parameter-inventory.md)と実装・試験を照合した。現在は103項目検証済み、5項目部分確認。方針上の差は別途残り、過去の件数・判定は履歴である。

