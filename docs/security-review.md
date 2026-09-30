# CIBA初版：要件・コード・セキュリティレビュー

## JWT mTLS introspection and installed rotation (2026-09-30)

The installed HTTPS rotation fixture exposed missing certificate cnf in JWT
introspection. The correction resolves the signed CIBA issuance marker to an
unrevoked, unexpired row and matches client, subject and certificate digest
before reporting binding. Opaque/JWT expiry/revocation and cnf regression cases
pass on all three DBs. The isolated fixture CA enables actual verified HTTPS
JWKS reads; different certificates with the same key cannot substitute for old
or new token bindings. Failed retrieval creates no pending request; restoration
recovers authentication. [Evidence and limits](research/mtls-reference-contract.md#installed-https-certificate-rotation-and-jwt-introspection).
This remains implementer review, without a multi-process or production proxy audit.

## Remote mTLS certificate lookup (2026-09-30)

TLS client authentication now uses a distinct lookup flag, ensuring remote
status/JSON failure reports invalid_client_metadata rather than the
post-authentication signed-request error. The same guarded HTTP destination,
size and timeout controls remain active; ensure restores lookup state.
Certificate mismatch cannot trigger an unbounded refetch. Tests cover exact
certificate replacement (including a different certificate with the same key),
repeated retrieval failure without persistence, configured transport-boundary
refusal and recovery. Node's failed refresh can keep previously cached keys
fresh; the gem deliberately keeps its rejection until successful retrieval.
[Measured contract](research/mtls-reference-contract.md#remote-x5c-rotation-and-retrieval-failures).
This is implementer review, not an independent audit or multi-process proof.

## mTLS installed-artifact TLS verification (2026-09-30)

The installed gem now passes real WEBrick/Net::HTTP TLS checks for PKI and
self-signed authentication with opaque and JWT access tokens. Certificate input
comes from the TLS peer, overriding no client-provided server variables; PKI
chain verification uses the application trust store and DN policy. Header-only
and absent certificates fail, a foreign same-DN certificate fails authentication,
and a same-key/different certificate fails bound UserInfo. The HTTPS client
verifies the server and hostname. The fixture explicitly permits self-signed
peers at the listener so the application can validate the selected method.
This does not verify arbitrary reverse-proxy or trust-store integration.
[Full scope and evidence](research/mtls-reference-contract.md#installed-gem-with-a-ruby-tls-server).

## Initial CIBA mTLS correction, deployment checks open (2026-09-30)

CIBA now requires an explicit trusted peer-certificate callback and storage at
startup. PKI chain/subject callbacks default to deny; self-signed auth compares
registered certificate DER digests. The grant stores the actual certificate
digest, and UserInfo requires it after normal live-token verification. Missing
required certificate and dual DPoP binding are rejected before nested persistence
so approval/proof/token state rolls back. Local opaque/JWT regression tests
cover these boundaries. Real Ruby TLS transport, DCR and other integration
combinations remain open. The following describes the reproduced baseline.

The actual gem Rack probe issues a PKI-authenticated certificate-bound token,
but UserInfo accepts it without a certificate. The stored binding hashes the
public JWK rather than the certificate DER; registered self-signed x5c auth
returns500. Forwarded certificate headers are accepted without an explicit
trusted-proxy policy in the fixture. These are measured gaps, not a complete
assessment of all deployments. The reference OP's real TLS test rejects absent,
header-only and same-key/different-certificate presentations. mTLS remains
disabled by default and must not be claimed as implemented through upstream
feature activation. [Evidence and required work](research/mtls-reference-contract.md).

## DPoP introspection boundary (2026-09-30)

Authenticated introspection now retrieves opaque CIBA DPoP tokens without
requiring possession of the token's key, matching the reference OP. Exact token
hash, CIBA type, expiry and revocation remain conjunctive predicates. Responses
report the stored `cnf.jkt` and DPoP type; inactive tokens reveal no binding.
Wrong client credentials still fail. Tests preserve unrelated OAuth lookup and
verify no introspection proof is claimed. This is OP metadata for an authorized
caller, not resource authorization; caller disclosure policy and external proof
enforcement remain application responsibilities.
[Evidence and scope](research/dpop-reference-contract.md#opaque-token-introspection-binding).

## Partial correction: upstream DPoP integration (2026-09-30)

The baseline upstream-only integration rejected random proof identifiers while
accepting hour-old proofs with a custom identifier and reusing them for another
approved CIBA issuance. The new CIBA token-endpoint boundary fixes those paths:
signature/key/claim validation precedes issuance, and a client-scoped,
domain-separated digest is claimed in the same transaction as token insertion.
Unique-key conflicts raise through the outer transaction, preserving approval;
signing failures also roll back the claim. Invalid private/malformed keys,
alg/typ/crit headers and tampered signatures are rejected before persistence.
Other OAuth grant validation is delegated unchanged.

UserInfo now validates CIBA proofs at `authorization_token`, because the upstream
OIDC route bypasses the general resource authorization method. It verifies ath,
the proof key, signed-token provenance and the saved issuance key before claiming
replay. CIBA-only dataset predicates also repair upstream's broad OR condition,
which otherwise lets a matching key bypass revocation, expiry or token lookup.
Opaque/JWT negative cases and concurrent UserInfo replay are tested. Unrelated
OAuth flows retain upstream behavior; this is not a global fix of that feature.

Nonce validation now permits old proof iat only with a valid server challenge.
Those replay records expire relative to validation time, so cleanup cannot
immediately reopen replay. The explicit 32-byte issuer secret and required-nonce
configuration are validated at startup; opaque/JWT tests cover expiry, rotation
and cleanup followed by replay. Cluster clock/secret management remains an
application deployment responsibility.

External resource integration and broader combinations remain
open, so this is not complete DPoP support. The default configuration does not
enable DPoP. Client authentication and customer approval are still required.
[Reference and implementation boundary](research/dpop-reference-contract.md).

## Revocation provenance and legacy formats (2026-09-30)

New opaque CIBA ATs reserve `ciba_at_`; this selects client authentication and unknown-token success, never ownership or a DB mutation target. New JWTs always carry the signed issuance ID; UserInfo now requires that exact row even without optional explicit claims. The legacy test reconstructs the historical unmarked JWT, rather than treating current issuance as a legacy fixture.

At revocation, unverified JWT markers select only a rejecting validation path. OP signature/issuer/at+jwt type are checked using configured keys before returning unsupported_token_type. Expiration is irrelevant to this rejection-only provenance check and remains enforced by normal consumption. Forged signature, wrong issuer/type and alg=none produce invalid_request without state changes. This intentionally has a narrower scope than node's header-only rejection of all structured JWTs, preserving other OAuth flows. Row-cleaned legacy unprefixed opaque tokens and unmarked old JWTs remain upstream cases.

## Opaque access-token revocation (2026-09-30)

Saved opaque CIBA tokens select the new path by their stored digest/type, not the untrusted hint. Client authentication remains mandatory even with a browser session. Authorization and validity are rechecked under Grant→token locks. Revocation preserves consent but invalidates related access tokens and deletes old request/refresh sources; otherwise refresh could recreate access or old-request replay could revoke the retained consent. Hook failure restores all these changes. Tests cover cross-client isolation, hints, explicit consent reuse for a new request, concurrent refresh and ordinary OAuth route preservation. JWT rejection and unknown tokens after row cleanup remain separate gaps; this is not full revocation parity.

## Refresh lifecycle and hook boundary (2026-09-30)

Refresh sources store digests and original permission context separately from access-token rows. Current consent/client/account/capabilities are checked at each update and again after the transactional before hook. Same-source reentrant calls are rejected. Hook/signing failures roll back rotation and issuance; observations wait for outer commit and contain no token or digest. Review moved basic scope parameter validation ahead of the hook to avoid committing hook effects on an immediate parameter error.

Tests cover cross-client isolation, age-based rotation, concurrent replay revocation, grant-wide refresh-token revocation, expiry cleanup retaining unexpired consumed records, and opaque/JWT claims/RAR updates under fixed test policies. Ordinary OAuth refresh still follows upstream. Access-token-initiated grant-wide revocation and installed-package refresh smoke remain outstanding. This is implementer review, not an independent security audit or a claim of complete reference parity.

## Ping in-flight behavior and adverse transport (2026-09-30)

Barrier-based tests show automatic completion can wait for a receiver while another connection retrieves the saved result; no DB transaction is active in the send callback. Two explicit retries can send the same identifier concurrently while collection succeeds once. Both sends may finish after consumption, later retries stop, and duplicate collection still triggers replay revocation. Receivers therefore need identifier deduplication before token collection, not only idempotent HTTP acknowledgement.

Installed-gem smoke now tests actual TLS rejection without the temporary CA trusted; no credentials reach the receiver and approval remains saved. A deliberately stalled receiver triggers a transport timeout, after which explicit retry and collection work. This can duplicate a notification already received before timeout. Signed-request/user-code/ping composition rejects outer credential replacement. No production code changes were needed for these cases. Process crashes, multi-process delivery and other TLS failure variants remain unverified; this is not independent audit.

## Ping completion and private delivery data (2026-09-30)

The original auth_req_id and client notification credential are stored only in a separate delivery table, inserted with the pending request and deleted by request cleanup cascade. Public APIs, hook/device snapshots and events do not contain those fields. This is separation from application-facing snapshots, not at-rest encryption; database privileges/backups remain deployment responsibilities.

Delivery runs only after the outermost commit. Rollback sends nothing; failed delivery raises after saved approval/denial, with a separate retry method. Endpoint snapshots prevent sending the credential to a newly registered destination. The current client must still be eligible. Sends use the bounded destination-checked HTTP transport and accept only 200/204. The installed artifact was exercised with real TLS, 503/302 and explicit retry. Dedicated concurrent lifecycle/delivery tests and adverse TLS/timeout cases remain unverified. Primary-implementer review, not independent audit.

## Outbound destination checks (2026-09-30)

The node comparison exposed special-use-IP protection absent from the gem's signed-request key fetching. A dedicated CIBA transport now rejects private/loopback/link-local, multicast, mapped IPv4 and reference special-use ranges. All resolved addresses must pass policy; Net::HTTP connects to the selected numeric IP while keeping the hostname for TLS/Host. Ambient proxies are disabled, redirects are not followed, and response bytes/total duration are bounded. Static registered JWKS is unaffected; unrelated OAuth HTTP paths remain upstream-owned.

Tests prove default refusal before a loopback receiver sees a request, bounded response reading, mapped-address cases, mixed DNS rejection and the pinned-IP/retained-hostname client configuration. Existing remote-key tests explicitly allow their single loopback address. Production TLS errors, live DNS rebinding and multi-address fallback remain limitations; see [transport contract](outbound-http.md). This is primary-implementer review, not independent audit.

## User-code application policy (2026-09-30)

Opt-in requires an explicit verifier. The application receives the resolved eligible account and authenticated client, before transaction hooks, request storage and device dispatch. Only true accepts; nil/false fails closed. Missing-code policy remains application-owned, as in node. Invalid shapes/oversized codes are rejected before the callback, and unknown/closed accounts do not invoke it. Unexpected callback failures create no pending work.

Tests verify raw code exclusion from request rows/device snapshots/events, signed-inner versus outer-code isolation, new approval and metadata. The reference OP independently tests missing/wrong code before dispatch and issuance after separate approval. Demo policies are fixtures only; production code provisioning, storage and brute-force controls are not implemented by the gem. Primary-implementer review, not independent audit.

## Remote request-signing keys (2026-09-30)

Actual loopback HTTP tests reproduce upstream's registered JWKS cache behavior: max-age prevents a new-kid refresh, no-cache refetches, and explicit cache invalidation permits the new key while rejecting a removed key. An attacker-controlled jku/embedded jwk does not replace registered keys. Malformed/empty JSON, HTTP 503 and connection refusal create no pending requests.

The tests exposed upstream's HTTP failure path returning 401 after client authentication had already succeeded. A scoped, ensure-cleared lookup flag now maps that path to invalid_request; common network exceptions are mapped at the same boundary. Wrong client credentials still return 401 and no other request paths enable the flag. This is an explicit error-policy adaptation, not exact node error-code parity. Production TLS/DNS/redirect behavior and distributed cache invalidation remain untested. This is primary-implementer review, not independent audit.

## Signed request boundary (2026-09-30)

Client authentication completes before request verification. The signing algorithm is pinned to client registration and the enabled asymmetric list. Only registered client JWKS is consulted; kid/alg/use/key_ops constrain candidate keys. An OP signing key does not validate a client request. Duplicate JSON keys and invalid UTF-8 are rejected before normalization, and standard claim types are checked explicitly after signature verification.

The original form body is not merged into verified protocol inputs. Tests prove outer scope/hint/resource cannot replace or fill inner values, and requested claims/resources/RAR reach existing validators. A resource-array integration test exposed the existing parser's scalar Rack parameter expectation; normalization now preserves the complete verified resource list while providing its scalar representation to that parser. No raw request JWT is persisted into the device snapshot. A repeated signed request deliberately creates new pending work, matching node; it is not a one-use client assertion. New approval remains mandatory.

Five environments pass 160 tests; installed-gem opaque/JWT examples use independently signed requests. Real remote JWKS failures/rotation, all configuration orders and algorithm variants remain unverified. This is the primary implementer's review, not an independent audit.

## ID Token hint validation (2026-09-30)

Dedicated verification ignores expiration only for hints; the ordinary JWT decoder remains unchanged. Algorithm comes from the authenticated client's configuration and keys from the OP. Signature/issuer/audience precede subject resolution. Unknown keys, wrong algorithm/client/issuer never reach the resolver. Raw hints are removed before storage and snapshots. Retained keys and kid selection are tested.

An adversarial test found ruby-jwt accepted a string nbf through numeric coercion. The dedicated verifier now explicitly checks iat/exp/nbf types. A different azp, at+jwt type and critical JOSE extensions are rejected; these stricter differences from the reference are documented. HMAC follows the actual upstream issuer's OP key source, with a client-secret forgery rejection test. Age defaults to unrestricted as in node, with an optional maximum. Encrypted/pairwise hints remain incomplete. This is the primary implementer's review, not an independent audit.

## login_hint_tokenの境界（2026-09-30）

無効を既定とし、有効化には専用resolverを必須にした。認証済みclientをcallbackへ渡し、入力hintの排他・長さ・型を検証する。アプリが返したaccountは既存の有効性と承認account/client一致チェックを通る。token endpointへ別hintを送っても保存済みユーザーは変わらない。

raw hint tokenはresolver後に要求の保存対象から除き、DB・AD snapshot・観測eventに含まれないことを検証した。元のHTTPリクエストやアプリ独自ログまで消去する保証はない。トークン形式はアプリ所有で、fixtureは固定参照値だけを解決するため、本番JWT等の検証器を検証したものではない。nodeは元のparamsを保存するため、raw tokenを残さない点は明示した保存方式の差である。

## 新形式の承認を結び付けた旧要求の無効化境界（2026-09-30）

RAR導入前の要求に、導入後に作ったRAR承認を結び付け、RARを無効化すると、要求側の新列がnullのため発行前チェックを通り、承認のRARを無視した基本tokenが発行されることを再現した。保存済み承認の機能列も検証対象に追加し、claims/resourceにも同じ境界を適用した。機能列が要求または承認のどちらかに記録されている限り、対応機能の無効化後はinvalid_grantとなり、消費と発行をrollbackする。

RARの同時pollでは異なるnarrowingを別DB接続から競合させ、勝者一件の内容だけが保存されること、再引換え検知後は失効することを検証。発行と取消しの競合でも、完了後に有効tokenやintrospectionのauthorization_detailsが残らないことを確認した。参照OPでもopaque RAR tokenの再引換え後にactive=falseとなる。全てのスケジューリングを証明するものではなく、RARのcompletion競合は別途残る。

## RARの受付・発行境界（2026-09-30）

登録型・クライアント許可型・JSON形状・型固有validatorを入力と保存済み承認とpolicy出力に適用する。発行policyには凍結済みの要求/承認/取得時要求と検証済みresourceを渡す。保存GrantをIDで再取得するため、呼出し側snapshotを書き換えても承認は増えない。発行直前hookでclientの許可型が変われば拒否し、要求消費とtoken作成をrollbackする。

RARはtoken response・resource JWT・opaque introspectionだけに出力し、ID Tokenから除く。無効化後のRAR要求はinvalid_grant、policy未設定は構成エラー。5環境で141テスト成功し、配布gemの複合フローも検証した。

型固有の包含関係やresourceへの割当は必須アプリpolicyの責務で、gemの形状検証だけでは保証しない。RAR専用の同時実行、introspectionでの追加秘匿policy、全feature有効化順の検証は残る。このレビューは主担当によるもので、独立監査ではない。

## resource JWT introspectionの参照比較による修正（2026-09-30）

前段階ではresource JWTを署名検証後にactiveとして返したが、再引換えで保存Grantが失効してもactive=trueが続くことを再現した。nodeの実OPとの比較では、active/inactiveを返すという仮説が誤りで、構造化JWTは最初からHTTP400 unsupported_token_typeだった。

gemも検証済みCIBA resource JWTについて同エラーを返すように修正した。発行直後、再引換え後、明示取消し後、発行行削除後をテストした。署名・issuerの検証は維持し、opaqueの失効結果と既存OAuthフローの扱いは保持する。nodeはJWT構造だけで全JWTを拒否するため、対象の限定はgem側の意図的な接続差である。以下の「JWTをintrospectionで説明する」記述は修正前の履歴。

## resource併用時のaudience修正（2026-09-30）

上流 `oauth_resource_indicators` を後から有効にすると、CIBAで保存したmapped audience `service-b` が、要求のresource URI配列に置き換わることを実際の署名済みJWTで再現した。CIBAの保存済みaudienceを最後に適用するwrapperへ移し、ID Tokenのclient audience、resource tokenのintrospection、UserInfo拒否をHTTP経由で検証した。OPのintrospectionはAPIの宛先ではないため、このCIBA tokenではaudienceの一致を要求せず、署名・issuer等の検証を維持する。改ざん署名・別issuerの拒否をテストした。JWTの即時失効保証を追加したものではない。

同時に異なるresourceを選択したpollは、一件だけ発行し、後続の再引換え検知でそのGrant/tokenを失効する。claims併用では明示許可されたemailだけがID Tokenへ入り、API tokenのscope/audienceは別に維持され、at_hashが実際のAPI tokenに一致する。

## optional resource対応のレビュー（2026-09-30）

主担当が、要求先を承認と誤認しないこと、保存済みGrantを再読込すること、発行hook後にresource policyを再取得すること、API scopeとID TokenのOIDC contextを分離することを確認した。JWT署名付きのresource識別子とopaque token行の識別子を使い、openid scopeを含むAPI tokenもUserInfoで拒否する。機能フラグを後から無効化してもこの拒否は維持する。

実装途中のHTTP試験で、introspection機能を後から有効化するとaudience追加メソッドが上書きされることを確認した。prependによる専用wrapperへ移し、opaqueのaudienceと取消しを実際のintrospection応答で検証した。未知・未要求resourceと署名失敗は要求消費/token保存をrollbackする。

5環境で各125テスト成功。これは独立した第三者監査ではない。resource専用の同時実行試験、claims併用、upstream resource featureとの組合せは未検証で、完全なresource対応とはしない。[対応範囲](resources.md)。

## optional claims追加後のレビュー（2026-09-30）

主担当が追加したclaims/UserInfoの接続を再レビューし、旧JWTへの許可の混入を再現・修正した。旧JWTの発行行が削除され、同じaccount/clientの別発行行にemail許可が残っていると、UserInfoの検索結果から旧JWTへその許可が使われていた。JWTの署名を改ざんせず、実際に機能追加前に発行したトークンで再現した。

修正後は、CIBAの明示claim projectionを読み込む前に、提示トークンとの厳密な発行ID結び付けを必須にした。結び付けのない旧JWTは既存のscopeベース経路を使用し、新機能の明示許可を引き継がない。`test_legacy_jwt_never_borrows_claim_consent_from_another_issuance`で修正前のemail漏出を確認後、修正後のemail非出力・属性getter非実行を検証した。旧JWTのDB行単位の取消し保証を追加したわけではない。

ローカル全体は117 tests / 896 assertions成功。以下はそれ以前の初版レビュー記録であり、今回の追加機能すべての独立監査を意味しない。

2026-09-29。軽量サブエージェント2体が要件整理と不足テストを担当し、主担当がコード・セキュリティレビュー、修正、再レビューを行った。対象はpoll/login_hintの初版と、実際に有効化して試験した上流クライアント認証の接続部分。Jevの点数は合否基準に使っていない。

## 再現して修正した問題

| 問題 | 修正と証拠 |
|---|---|
| private_key_jwtでiss不一致、exp/jti欠落、同じassertion再利用が受理される | OIDC Core §9の必須claim・iss/sub/client_idの一致を検証し、DBのunique digestで一回限りにする。`test_jwt_client_assertion_requires_issuer_expiry_and_jti`, `test_jwt_client_assertion_is_single_use` |
| Backchannelに別grant用grant_type/assertionを渡すと、登録済みのclient authenticationではなくJWT authorization grantの経路へ入る | Backchannelではそのgrant分岐を使わず、通常のclient authenticationを必須にする。余分なパラメータがあっても正しく認証した要求は通る。`test_backchannel_ignores_other_grant_parameters_without_bypassing_client_authentication` |
| 壊れたJWTが認証失敗ではなく500になる | CIBAの認証境界で形式を検証し401 invalid_clientへ。開始・Token両Endpointの負例を検証。`test_malformed_assertions_are_authentication_errors_at_both_ciba_endpoints` |
| カスタムerror_descriptionに非ASCII等がそのまま出る | 許可文字外の任意説明は省略し、status/errorは保持する。許可ASCIIは保持。`test_authentication_error_description_keeps_allowed_ascii_and_omits_unsafe_text` |
| scope欠落がinvalid_scopeになる | 欠落はinvalid_request、存在する不正scopeはinvalid_scopeへ区別。`test_scope_syntax_errors_are_invalid_scope` |
| slow_downのintervalが32bit上限で飽和し、5秒以上増加しない | 保存列をBignumにし、要求時の上限と実行中の増分を分離。`test_slow_down_does_not_saturate_at_the_initial_interval_limit` |
| 矛盾するform構造によるRack解析例外が500になる | 解析例外をinvalid_requestへ変換。`test_conflicting_form_parameter_shapes_return_invalid_request` |

| offline_accessを除外したのに実効scopeを応答に返さない | CIBA token responseに許可済みscopeを含める。RFC6749 §5.1の、要求と許可scopeが異なる場合の返却条件を確認。`test_reduced_scope_is_reported_when_offline_access_is_not_granted` |

## 追加の防御と再レビュー

- CIBA clientのJWTは、BackchannelとToken、および同じクライアントの非CIBA grant間でreplay ledgerを共有する。別クライアントの通常フローにこの制約を一律適用しない。
- ledgerのunique insertはsavepoint内。別接続からの同時再利用で1件のみ成功し、拒否を外側transactionで処理しても他のDB操作が続行できることを検証した。新しいテーブルには生のJWT・jti・secretを保存しない。
- client JWKS未設定時にOPの署名鍵へフォールバックしない。HS256/384/512の共有鍵長を検証。これらはソースレビューで認証の境界を確認し、負例テストを追加した。
- JWTのaudは文字列・文字列配列を受理する。CIBA開始時はissuer/Token URL/Backchannel URLの3種類を受理し、CIBA grant の Token 時は issuer または Token request URL を検証する。
- identity mismatch、認証前・拒否後・期限切れの発行禁止、署名失敗・hook失敗のrollback、二重poll、approve/deny競合、outer rollback後の観測抑止は既存テストを含め再実行した。
- 要件表の架空のテストクラス名、章単位の広すぎる根拠、任意と必須の混同を主担当レビューで差し戻し、原仕様と実在メソッドへ対応付け直した。

仕様根拠: [CIBA Core §7.1/§7.2/§11/§13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)、[OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)。[OAuth 2.0 §5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)。RFC7523単体のreplay対策は任意だが、今回のOIDCクライアント認証にはOIDC §9のjti/single-use条件が適用される。

## 検証結果と残る限界

`mise exec ruby -- ruby test/run.rb --seed 41025`：**76 tests / 563 assertions、failure/error/skipなし**。macOS arm64 / Ruby4.0.6 / SQLite。ログはリポジトリの `docs/validation/requirements-review-tests.txt`。

今回再現した不具合は修正後の回帰テストを通過し、上記の範囲で追加の既知の未修正不具合は残していない。これは安全性や全仕様適合を保証する意味ではない。

- Docker socketは現在の実行権限でpermission denied。新しいreplay tableとinterval列を含む現行コードのPostgreSQL/MySQL検証は未実施。以前の46テスト版のmatrix成功を、この変更の証拠として流用しない。
- 159は人手で整理した評価単位であり、参照先OIDC/RFCまで含めた全規範文の網羅性証明ではない。要件表は設定・モード・責務の条件と一緒に読む。
- mTLS、追加の上流拡張や署名algorithm全組合せ、別middleware構成、複数プロセスの実環境、長時間負荷、failoverは未検証。署名検証は上流/JWTライブラリに依存する。
- 本人確認、承認権限、CSRFを伴う本番UI、逆proxyの信頼設定、通知・監査の耐久配送は導入アプリの契約として残る。hookからのRack halt/throwは禁止し、失敗は例外で通知する。
- 認証成功応答を外側transactionのcommit前に返さない。JWTは業務要求が失敗しても消費される場合があるため、retryには新しいassertionを使う。live ledger行の早期削除はしない。

今回の依頼は要件整理・不足テスト・修正まで。`pkg/`の配布gemは今回の修正前の成果物であり、再公開候補としては使わない。公開前のDB matrix、配布物の再ビルドとclean install確認は次の工程として残す。


## 登録した client assertion アルゴリズムの制限

動的登録で `token_endpoint_auth_signing_alg=none` が201となることと、
RS512指定のclientがRS256 assertionで認証されることを別々に再現した。
登録時は方式・型・広告済みアルゴリズムを検証し、認証時は保存値とheaderを
比較したうえで、private_key_jwtのdecoderにも選択したアルゴリズムを渡す。
署名の正しさだけで登録制約を満たしたと判断しない。
[登録の再現](validation/registration-algorithm-red.txt)、
[認証時の再現](validation/registration-algorithm-runtime-red.txt)。
node比較はRS512を明示的に有効化したfixtureである。HMAC等の全組合せ、
JWK構造そのものの登録時検証は、この修正の検証範囲には含まれない。


## CIBA client assertion のリモート鍵取得

動的登録した private_key_jwt の JWKS 取得が、署名付き要求で使用している
送信先アドレス制限を迂回する経路を再現した。試験では登録URLポリシーだけを
対象のlocalhost fixtureに緩め、取得時の既定アドレス拒否が効くかを独立に確認。
修正後は既存のIP固定・proxy無効・deadline・応答上限を持つtransportを使い、
取得/JSON解析失敗は認証拒否とする。管理更新で別URLに切り替えた際の旧鍵拒否と
新鍵受理も実HTTPで検証する。同じURLの分散cache invalidationは未証明。
[再現](validation/registration-remote-red.txt)、
[DB検証](validation/registration-remote-matrix.txt)。


## DCR default_max_age の検証と保存

負値が201で受理され、有効値も応答には含まれるが保存されない経路を確認した。CIBA関連の登録／管理更新でのみ、非負の安全な整数であることを検証し、明示した列へ保存する。保存列がなければ拒否する。POSTの不正入力で追加行がなく、PUT失敗で設定と管理用credentialが変わらず、GETでゼロを含む保存値を取得できることを試験した。これはmetadataの整合性修正であり、認証freshness enforcementの実装や、その不備による攻撃成立を主張するものではない。[比較契約](research/registration-reference-contract.md#default_max_age-validation-and-persistence)。

## Pairwise sector変更後のJWTの本人対応付け

管理更新後の現在のsectorからsubを再計算すると、旧JWTのUserInfoが拒否される。
nodeでは既存opaque tokenのUserInfoとrefreshが新sectorのsubを返すことを実測した。
gemは明示migrationで発行時subをtoken行に保持し、署名済みsubとの一致を確認した後、
保存された内部accountで属性を取得する。UserInfoの公開subだけは現行client設定を使う。
旧JWTのsubを現行subに差し替えて再署名したfixtureも、保存済み発行subjectとの不一致で拒否する。
この変更でclient/内部accountのbindingを省略していない。NULLの旧行は従来の検証を維持する。
[再現](validation/pairwise-sector-update-red.txt)、[回帰](validation/pairwise-sector-update-matrix.txt)。
