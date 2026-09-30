# node-oidc-provider と rodauth-ciba の比較

後続調査で専用ソースをGitHub connectorから取得できた。最新の処理順序・差分は[ライフサイクル比較](node-ciba-lifecycle.md)を参照。以下は取得前の比較記録。

調査日: 2026-09-30。この比較は整合化作業前のスナップショット。以後の変更は[整合化作業](../node-alignment.md)を参照。結論: アプリが本人確認と承認UIを担当し、内部APIでOPへ結果を渡す分担は共通。node側は既存OIDCの認可モデル・拡張機能を広く利用し、gem側はpoll/login_hintと同一DB内の状態遷移に範囲を絞っている。機能数だけでは適合性・安全性を比較できない。

比較対象は公開時点でlatestと表示された [node-oidc-provider v9.12.2](https://github.com/panva/node-oidc-provider/releases/tag/v9.12.2) と、この作業ツリーのrodauth-ciba 0.1.0。`lib/rodauth/features/ciba.rb` のSHA-256は `f4336c948a135f3682d08eb292408eaaa168edfff13f8702a21c7af46e3d2121`。

これはソース・設定・APIの比較であり、相互接続試験ではない。shellからGitHubをcloneできず、Web経由で取得できたタグ固定の一次資料を読んだ。v9.12.2の `actions/authorization/ciba.js` と `actions/grants/ciba.js` は取得できていない。mainのgrantファイルも参照したが、タグとの差を保証できないため、そこだけからv9.12.2の挙動を断定しない。特にhint全種の検証詳細、slow_down、発行失敗後の再試行、JWT認証の全負例は今回の比較では未確定。

| 観点 | node-oidc-provider | このgem | 判断 |
|---|---|---|---|
| 配送 | poll / ping。既定poll、pushは設定検証で拒否 | pollのみ | poll初版を維持してよい。[設定検証](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/configuration.js#L607) |
| アプリとの境界 | `triggerAuthenticationDevice` と `backchannelResult` | `ciba_request_accepted` と `approve_ciba_request` / `deny_ciba_request` | 内部APIという方向は共通。どちらも業務用の承認HTTP APIをこの境界で標準化するものではない。[node設定](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/defaults.js#L1116) |
| 承認結果 | 保存済みGrantまたはエラー。account/client一致を確認 | account一致を確認し、要求を承認/拒否 | nodeのGrantはscope・claim・resourceごとの許可/拒否を表現できる。gemの承認APIにはscopeを減らす引数がない。[結果API](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/provider.js#L239)、[Grant](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/models/grant.js) |
| hint / user_code | login_hintとlogin_hint_tokenの解決、user_code検証をアプリ用callbackとして提供 | login_hintのみ解決を差替え可能。他は入口で拒否 | 対応範囲の差。nodeのcallbackもアプリ実装が必要で、任意のトークン形式を自動で検証するわけではない。[callback定義](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/defaults.js#L527) |
| 署名付き要求 | request-object処理をCIBAにも接続 | 明示的に未対応 | JWTクライアント認証とは別機能。初版へ自動追加しない。[処理スタック](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/actions/authorization/index.js#L90) |
| クライアント登録 / subject | 共通schemaにCIBA metadata・pairwise向け認証条件がある | 静的登録・public subjectのみ。CIBA DCR拒否 | 公開OSSとしての拡張余地だが初期用途の必須条件ではない。[client schema](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/client_schema.js#L133) |
| Refresh Token | 共通発行処理にRefresh Token生成とpolicy判断がある | offline_accessを除外し、CIBA refreshを発行しない | 長期アクセスが必要になった時点で再検討。nodeの全CIBA設定で必ず発行されるとは言わない。[共通発行処理](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/grant_common.js#L95) |
| 詳細な認可要求 | CIBA開始スタックにclaims / resource / RARの処理を接続 | CIBA専用処理ではscope等の固定項目を保存 | 業務操作の詳細は現在アプリが保持する必要がある。[処理スタック](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/actions/authorization/index.js#L114) |
| binding_message | 既定は限定文字集合・1〜20文字。検証callbackあり | 制御文字を除くUTF-8、最大128bytes | ライブラリの方針差。nodeの文字数をCoreの必須条件として移植しない。[検証既定値](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/defaults.js#L546) |
| 永続化 | モデル単位のadapter。既定in-memory、本番用adapterは導入側 | Sequel、既存OAuthと同じDB | gem側のDB選択は単純で妥当。汎用adapterを追加する理由にはならない。[adapter契約](https://github.com/panva/node-oidc-provider/blob/v9.12.2/example/my_adapter.js) |
| イベント | Provider event emitter。モデル保存後にsaved等をemit | transaction内のbefore/afterと、outer commit後の例外隔離した観測を分離 | nodeのイベントを「DB commit後・失敗しても認証へ無影響」と同一視しない。[保存・emit](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/models/base_model.js#L71)、[イベント一覧](https://github.com/panva/node-oidc-provider/blob/v9.12.2/docs/events.md) |
| 適合性の証拠 | READMEにFAPI CIBA認定を記載 | 宣言した範囲のローカルテスト、認定なし | 実績には差がある。ただしnodeの任意設定が認定済みになるわけではない。[README](https://github.com/panva/node-oidc-provider/blob/v9.12.2/README.md#certification) |

gem側の根拠は [実装](../../lib/rodauth/features/ciba.rb)、[API契約](../api.md)、[テスト対応表](../protocol-coverage.md)、[直近のレビュー結果](../security-review.md)。最後の実行記録はRuby 4.0.6 / SQLiteで76 tests / 563 assertions。今回はコード変更・テスト再実行をしていない。

特に参考になるのは、nodeが「認証要求」と「許可した内容」を別のモデルで扱う点。gemは受付時に許可候補scopeを保存し、承認時には全体を承認する。これは初版の単純な承認には合う。一部承認が必要なら、まず `approved_scopes` 相当の小さなAPIを検討できるが、その際は受付scopeの部分集合・openid維持・保存後の変更禁止・再試行一致・Token応答のscopeを一緒に検証する必要がある。nodeのGrant体系全体の移植は不要。

今回の「誰が、どの顧客の、何の操作を承認したか」には、scopeだけでは足りない。これは両実装の機能数とは別のアプリ設計問題。現行gemの `after_ciba_request` で、内部request IDに紐付く操作対象・実行者・範囲・期限のスナップショットを同じDBへ保存する案が使える。承認画面と実行側が同じ内容を参照し、後から内容を差し替えられないことを確認する。RARを初版へ追加する前に、この既存フックで足りるかを試すのが妥当。

状態遷移は、単にnodeへ揃えるべきではない。nodeの `backchannelResult` はGrantとのclient/account一致を確認して要求を保存するが、読んだメソッド内にはgemと同じ「同一結果なら冪等、異なる結果ならConflict」という分岐はない。一方gemは期限・完了済み状態・認証contextを確認し、行ロックと状態versionで変更を直列化する。node側の全呼出経路・adapterを含めた競合試験はしておらず、これを脆弱性の認定には使わない。[node結果API](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/provider.js#L239)

また、nodeの共通消費処理は消費済みsourceを拒否し、関連Grantのrevokeを呼ぶ。adapterにはfind/upsert/consume等の契約があるが、要求消費と複数トークン保存を一つのDB transactionで確定する保証は、この契約だけからは読み取れない。gemはそれを自前でまとめ、署名失敗時のrollbackと再試行をテストしている。nodeより安全という結論ではなく、保証を置く場所が異なるという比較である。[消費処理](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/grant_source.js#L21)、[adapter契約](https://github.com/panva/node-oidc-provider/blob/v9.12.2/example/my_adapter.js#L194)

再利用防止でも、nodeの `ReplayDetection.unique` はfindしてからsaveするモデル。gemはclient IDとjtiの組をhash化してunique insertする。nodeのモデルをそのままコピーして、gemのDB unique制約を弱める理由はない。ただしnodeでの同時リクエストの可否はadapter・呼出経路を含めて未検証。[ReplayDetection](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/models/replay_detection.js)

通知失敗の扱いにも注意する。nodeの設定ではAD起動helperを要求受付後・応答前に呼ぶ。gemの受付callbackはcommit後で、例外でも成立済みの受付を変えない。gemでは通知漏れが起きてもpending要求の走査で回復できるが、本番では同一DBへのoutbox保存と配送workerをアプリ側で用意するのが候補になる。観測イベント自体を配送保証とみなさない。pingについてnodeは結果保存後にHTTP通知し、200/204を受理する実装であり、読んだメソッドには永続的な再送queueはない。[ping処理](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/models/client.js#L379)

次に行うなら、機能の横並び化より、次の順序を推奨する。

1. 初期アプリで「承認内容の固定」と「通知失敗からの復旧」を既存のtransactional hook・内部IDで確認する。
2. gemは現行のpoll/login_hint範囲を維持し、未実施のPostgreSQL/MySQL検証を完了する。
3. nodeを動かせる環境で、同じクライアント要求を両OPに送り、開始・拒否・期限・二重引換え・再送を比較する。返却文言の完全一致ではなく、仕様と各実装の宣言した方針に沿って判定する。
4. 一部scope承認や別hintの具体的な利用者が現れた場合に、その機能だけを追加検討する。
