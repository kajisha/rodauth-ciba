# CIBA 初版の実装契約案

状態: 実装前の設計履歴。現在の0.1.0契約は [API](api.md) / [運用](operations.md) / [公開検証](release-validation.md) を参照。以下は当時の Codex の提案。既存の合意を前提とするが、新しい選択はユーザーの合意として記録しない。Jev との反復評価で改善する。GO は実装着手の判断であり、公開・本番適合の判定ではない。

## 対応範囲

合意済み: poll、login_hint、refresh token 発行なし、署名付き認証要求・user_code は対象外。Ruby >= 3.3、DB は rodauth-oauth に従う。UI・通知トランスポート・上流 IdP の検証・業務上の承認権限・委譲はアプリが担当する。

追加提案: CIBA クライアントは初版 public subject・事前登録のみ。既存の別フローの pairwise や DCR を変更しない。CIBA に不適合な登録内容は実行時にも検証する。public から pairwise への将来の移行は既存ユーザーの対応付けに影響するため、自動変更しない。

## 本人の解決と Ruby API

以下の名前は公開契約の候補で、Rodauth の実装慣例との整合を実装時に確認する。

```ruby
resolve_ciba_login_hint(login_hint, oauth_application:) # => local account_id
ciba_request(request_id) # => read-only snapshot or not-found
approve_ciba_request(request_id, account_id:, auth_time: nil, acr: nil, amr: nil)
deny_ciba_request(request_id, account_id:)
pending_ciba_requests(after_id: nil, limit: 100) # bounded recovery lookup
cleanup_ciba_requests(before:) # caller explicitly chooses retention cutoff
```

resolver の設定を必須にし、メールアドレスや既存 login 列への暗黙のマッピングは行わない。要求受付時に対象をローカル account_id に解決・固定する。後から同じ login_hint を再解決して別人に承認を付け替えない。

Ruby API は信頼するアプリコードからの呼び出し専用。request_id の所持だけでは認証・認可の証明にならない。HTTP に公開する場合の呼び出し元認証、CSRF 対策、権限確認はアプリが実施する。gem は明示された account_id が受付時の対象と一致すること、期限と状態を検証する。別の管理者による代理承認は初版の契約に含めない。

ID Token の sub は、CIBA OP がこのローカルアカウントに対して生成する値。上流 OP の sub やサポートアカウントの sub をそのまま代入しない。auth_time は分かる場合に実際の認証時刻を渡し、承認時刻を代用しない。acr/amr はアプリが確認した認証情報を渡す。未知の認証強度を gem が捏造しない。認証時刻等の必須要求を今後サポートする場合、必要な情報がない成功応答を許さない。

acr_values はアプリへ渡し、実際に達成した acr を結果として受け取る。初版 gem が独自の強度比較表を持つことはしない。アプリが実施すべき認証ポリシーとして定義する。

offline_access は初版の有効 scope から除き、応答は実際に付与した scope を反映する。これは refresh token を提供しない製品方針で、CIBA が特定のエラーを強制するという主張ではない。未知のパラメータは仕様通り無視する。既知の対象外機能 request/user_code の指定は invalid_request とし、無検証の署名要求を受理しない。このエラー選択は初版の明示方針である。

## 保存する情報

専用 CIBA 要求テーブルを同じ DB に作る。主な情報は内部 request_id、公開 auth_req_id の検索用ダイジェスト、client_id、account_id、scope、binding_message、要求された acr、期限、poll 間隔・直前 poll 時刻、状態、確定した認証コンテキスト、完了時刻・消費時刻・作成時刻。

auth_req_id は十分な乱数で生成し、クライアント向けの受付応答にだけ生値を返す。内部 API は別の内部 request_id を使う。いずれも単独で承認する権限を与えない。ログ相関には内部 request_id とイベント ID を使い、auth_req_id の生値やトークンは出さない。

login_hint の生値は既定では永続化しない。binding_message 等も利用者情報を含み得るため、サイズ制限と cleanup の対象とする。業務コンテキストはアプリが内部 request_id に関連付けて保存する。任意の HTTP パラメータを自動保存しない。

保存スキーマの最低制約:

- 内部 request_id は主キー、auth_req_id の SHA-256 ダイジェストは NOT NULL / UNIQUE。auth_req_id は32バイトの暗号学的乱数を padding なし base64url にする。
- client_id、account_id、scope、expires_at、created_at、status、interval、lock_version は NOT NULL。初期 status=pending、interval は正数、lock_version=0。
- last_polled_at は初回まで NULL。approved/consumed は不変の completion outcome/account/context を保持し、denied は拒否の本人と結果を保持する。auth_time/acr/amr 自体は任意。
- timestamps は UTC で比較、Ruby API の時刻表現は epoch 秒を正規化する。amr は文字列集合をソートして比較し、nil と未指定を同一視する。認証時刻の未来値等の不正な入力は変更前に拒否する。
- 索引は auth_req_id ダイジェスト、(status, request_id)、expires_at を起点にする。client/account の型・参照先は上流設定に合わせる。FK が有効な構成では削除に連動して要求も削除してよい。削除済み要求はトークンを発行できない。要求テーブルは監査台帳ではない。
- status と completion の整合は Ruby API で必ず検証し、利用可能な DB 制約でも補強する。唯一性は DB 制約に依存し、アプリの事前 SELECT だけで担保しない。

受付時の account_id・client_id・有効 scope は不変。承認時と発行時にも、対象アカウントが存在し通常の利用資格があること、クライアントが存在し CIBA と要求 scope を今も許可されていることを再確認する。無効化済みなら発行しない。ID の再割り当てによる別人への再関連付けは許さない。アプリの業務認可の再確認は transaction 内フックで行える。

これらの確認は操作 transaction 内の可視状態に基づく。別 transaction で同時に行う管理操作に対する絶対的な即時失効や発行済みトークンの失効を新たに保証するものではない。必要なロック・失効処理は上流と同じ整合性方針で検証する。

## 状態遷移と再送

```text
pending ── approve ──> approved ── token issuance ──> consumed
   └────── deny ─────> denied
pending / approved ── deadline ──> expired（時刻から判定可能）
```

期限の経過はアクセス時にも検証し、cleanup が実行されるまで有効になる設計にしない。denied、consumed を再び pending/approved にしない。

同じ account_id・同じ認証コンテキストによる approve の再送は、期限内で既に approved/consumed なら already_completed を返す。deny の同一再送も既存結果を返す。新たな状態変更、フック、成功イベントは発生させない。逆の決定や異なる本人・コンテキストは Conflict / IdentityMismatch とする。期限切れは Expired、削除済みは NotFound。消費済みへの再送でもトークンは返さない。

予期しない処理障害を顧客の拒否に変換しない。アプリ側の本人確認・通知に一時障害が起きた場合は再試行可能なまま要求を残し、期限までに完了しなければ expired とする。技術的な終端失敗専用 API は初版では設けない。

token endpoint の成功は一度だけ。commit 後に応答が失われても、再度同じ auth_req_id からトークンを発行・返却しない。クライアントは新規要求からやり直す。Ruby API の冪等性とは別の契約。

## トランザクションと競合

すべての状態変更は条件付き UPDATE と件数確認を基本にする。approve/deny は pending かつ期限内の行だけを対象とし、トークン発行は approved かつ期限内の行だけを消費する。トークン・grant の作成、消費への更新、before/after フックは同じ DB トランザクションに含める。

同時 poll の片方だけが消費権を獲得する。発行中の例外なら消費と grant 作成をともに rollback する。before/after フックの実行前に競合の勝者を確定し、敗者が同じ副作用を実行しない。これが実現できる SQL 順序と隔離動作は DB ごとの競合テストで確認する。

具体的には、読み込んだ lock_version・status・expires_at を条件に UPDATE し、更新件数1の操作だけが勝者になる。まず lock_version のみを更新して同一 transaction 内の変更権を確保し、状態は元のまま before フックを呼ぶ。ロック待ちで期限を跨いでいないことを確保後に再確認する。本処理で承認なら approved、拒否なら denied、発行なら consumed への変更と grant 作成を行い、after フックの後に commit する。フックから同じ要求への再入は拒否する。例外で予約更新も戻る。before は業務状態変更前を意味し、内部のロック用 SQL より前までは保証しない。

pending に対する poll 時刻・interval 更新にも lock_version を使う。競合に負けた場合は最新状態を再読込し、有限回の再試行後は一時的なサーバー応答とする。早すぎる poll では interval を5秒増やして保存してから slow_down を返す。authorization_pending/slow_down の応答生成でその保存を rollback しない。別クライアントや不正IDからの要求では対象の poll 状態を更新しない。完了済み・拒否・期限切れを pending の制限エラーで覆い隠さない。

CIBA の発行処理と Ruby API の変更境界には savepoint を設ける。外側のアプリ transaction が例外を捕捉して commit しても、失敗した内側の変更を残さない。観測通知は `after_commit(savepoint: true)` を使い、中間 savepoint が rollback した場合も取り消す。これは [縦断 TDD 実験](research/tdd-vertical-slice.md) の失敗テストから得た修正である。

外側にアプリの transaction がある場合も、観測通知は最外 transaction の commit 後。外部 HTTP やファイル出力は rollback できないため transaction 内フックで成功保証を期待しない。

## アプリへの引き渡しと観測

before/after フックは受付・承認・拒否・トークン発行の主要な変更に設ける。未設定は no-op。例外は状態変更を rollback し、内部 API の呼び出し元へ伝播する。認証エラーではなく、機密情報を含まない適切なサーバーエラーへ HTTP 境界で変換する。

受付確定後にアプリ向け callback を呼べる。commit と callback の間のプロセス停止による通知欠落は起こり得るので、pending_ciba_requests で復旧可能にする。アプリは transaction 内フックで同じ DB に配送ジョブを保存する方法も選べる。スケジューラ、配送の重複排除、再送はアプリの責務。gem はジョブ実行基盤を持たない。

commit 後の通知 callback の例外は reporter へ渡し、既に確定した受付の成功をエラー応答に変更しない。ネットワーク自体の障害による受付応答喪失は回避できず、期限まで残る孤立要求を許容する。pending lookup は期限内 pending だけを request_id 順にページングし、配送済みか否かは保証しない。アプリが周期的に先頭から走査し、重複通知を管理する。永続的な単調カーソルだけで一度見た未配信要求を取りこぼさない運用をサンプルに示す。

観測用イベントは commit 後に配信する。失敗は設定可能な reporter、既定 logger へ報告し、observer/reporter の例外で既に確定した CIBA の結果を変えない。プロセス停止によるイベント欠落を許容する best-effort の契約。厳密な監査保存はアプリが transaction 内フックを利用する。

イベントは version、event_id、内部 request_id、発生時刻、適用可能な client/account 参照、変更前後の状態、公開可能な結果コードを基本にする。トークン、認証情報、raw login_hint は既定で含めない。HTTP 応答がクライアントへ到達したことまで表すイベントにはしない。

## 運用とテスト

通常 poll のみ。要求期限の default と maximum はアプリに明示設定を求め、設定例は300秒とする（SLA の推奨値ではない）。requested_expiry は仕様に従って設定範囲内に制限する。poll interval の既定は5秒。検証・制限の詳細は仕様テストに対応付ける。

cleanup は明示メソッド／タスクのみで、保存期間は before 引数でアプリが決める。未消費・期限内の要求を削除しない。要求テーブルを長期監査台帳として扱わない。バックグラウンドスレッドを起動せず、起動時の自動 migration もしない。

cleanup の before は未来を拒否する。denied/consumed は終端時刻が cutoff より古い行、pending/approved は期限が cutoff より古い行だけをバッチ削除する。要求が消費されずとも有効期限後には削除可能。有効なトークン・grant 自体の寿命は要求テーブルの cleanup と連動させない。

Sequel migration の実行可能な例と設定可能なテーブル／カラム名を提供する。依存 gem は検証した下限・上限を指定する。正確なバージョン範囲はコードと CI の検証結果で決める。

Ruby 3.3/3.4/4.0 と SQLite、代表 MRI で PostgreSQL/MySQL の実 DB 競合テストを最初の CI 案とする。ほかの上流対応 DB を禁止する API は作らず、未検証環境を区別して示す。

必須シナリオ: 他クライアントの要求ID、本人不一致、期限境界、approve/deny 競合、二重 poll、フック例外時 rollback、外側 transaction rollback、完了結果の再送、commit 後の応答喪失、通知回復、ログへの秘密情報非混入。仕様上の要求と対応するテストを一覧化する。

ベンダーの認証情報不要の最小 RP/poll とブラウザ承認サンプルを提供する。デモ本人確認を本番向けと表現しない。ライセンスや最終 gem 名は公開前に確認し、実装の安全性と別の公開条件として扱う。

## 仕様確認の参照

- [CIBA §7.2–8](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request_validation): 有効ユーザーへの hint 解決は成功受付前。認証・承認はその後。
- [CIBA §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request): requested_expiry は正整数、採用は OP の裁量。acr_values と実際の認証コンテキストを区別。
- [CIBA §10.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#successful_token_response): 成功交換後に auth_req_id を再利用しない。
- [CIBA §11–12](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response): 顧客拒否と技術障害を混同しない。push の transaction_failed を poll の標準エラーだと扱わない。
- [OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)、[§11](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess): auth_time/amr は CIBA 全体の一律必須項目とはしない。offline_access の扱いを製品方針と区別。

## 上流への接続と最初の実装ゲート

コード読解対象: rodauth-oauth `cac77ec075b41672010126cd6961baf20afccdd7`、Rodauth 2.28.0。製品依存バージョンをこのまま固定する決定ではない。

- Rodauth は依存 feature を先に include するため、CIBA の create_token で return すると OIDC の ID Token wrapper を通らない可能性がある。[読込順](https://github.com/jeremyevans/rodauth/blob/2.28.0/lib/rodauth.rb#L334)、[OIDC wrapper](https://github.com/HoneyryderChuck/rodauth-oauth/blob/cac77ec075b41672010126cd6961baf20afccdd7/lib/rodauth/features/oidc.rb#L528)。
- 接続候補: 既存 token route の transaction 内で CIBA 要求を条件付きで消費し、保存済み属性から generate_token(attrs, false)、generate_id_token(grant) を一度ずつ実行して grant を返す。非 CIBA は super。authorization code を作る create_oauth_grant の流用は避ける。[token route](https://github.com/HoneyryderChuck/rodauth-oauth/blob/cac77ec075b41672010126cd6961baf20afccdd7/lib/rodauth/features/oauth_base.rb#L144)。
- 上流の auth_time は account の最終ログイン時刻を参照する経路がある。CIBA 完了時の snapshot を使い、別ログインで認証時刻が変わらないよう CIBA の claim 生成を接続する。[id_token_claims](https://github.com/HoneyryderChuck/rodauth-oauth/blob/cac77ec075b41672010126cd6961baf20afccdd7/lib/rodauth/features/oidc.rb#L583)。
- 最初の縦断実装で、実 Rack endpoint から署名検証可能な ID Token と access token、refresh 無しを確認する。署名失敗時の request/grant rollback、二度目の交換拒否、既存 grant 分岐を必須テストにする。
- pending/slow_down の poll 更新と JSON 応答の throw が transaction をどう終えるかをテストする。通常例外と throw を同一視しない。外側 transaction の commit/rollback と観測イベントも実 Sequel で検証する。
- これらを通すまで全機能実装・公開に進める判断はしない。GO の対象はこの検証を含む段階的な実装着手。

## 取得した実行証拠と限界

[SQLite の小規模実験](research/sqlite-transition-spike.py) では、version の条件付き更新による競合制御、二重 poll と approve/deny 競合（各20回）、発行相当の INSERT と消費の rollback、期限切れ・他クライアントの拒否を確認した。[実行結果](research/sqlite-transition-spike-result.json)。

Python sqlite3 / SQLite 3.54.0 に限定した SQL 仮説の検証であり、Sequel・Rodauth、PostgreSQL/MySQL、JWT、after-commit の検証ではない。この SQL 実験時点では標準 Ruby 2.6 しか調べていなかった。その後 mise の Ruby 4.0.6 を利用し、依存 gem を導入して下記の結合検証を行った。


## 縦断 TDD による設計更新（2026-09-29）

ユーザーの承認を受け、要求受付→Ruby承認→poll→実トークン発行を限定実装した。[実験記録](research/tdd-vertical-slice.md) の14テストが成功。savepointによる内側失敗の分離、savepointに連動したafter_commit、CIBA認証コンテキストによるID Token生成を確認した。

SQLiteのCIBA発行処理とRuby承認はIMMEDIATE transactionで検証した。既存の外側deferred transactionを内側から昇格できるわけではなく、DB固有の競合・再試行方針は引き続き検証が必要。PostgreSQL/MySQL対応、正式スキーマ、完全なプロトコル処理は未確認。この実験コードを契約案全体の実装済み状態と扱わない。


## DB 横断実験の追記（2026-09-29）

[Dockerでの検証](research/cross-database-experiment.md)により、PostgreSQL 17.11 / READ COMMITTED、MySQL 8.4.11 / InnoDB / REPEATABLE READでも同じ14テストが成功した。今回の範囲では発行・savepoint・条件付きUPDATEの実装変更は不要。上記の「PostgreSQL/MySQL未確認」は初回TDD時点の記録であり、この限定構成の実行証拠を追加した。DB全般の対応保証、正式スキーマ確定、競合再試行や全プロトコル対応の完了とは区別する。
