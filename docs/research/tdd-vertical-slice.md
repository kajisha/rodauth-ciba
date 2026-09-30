# CIBA 縦断 TDD 実験

2026-09-29。ユーザーの依頼により、最初の縦断部分を TDD で実装して設計を検証した。公開 gem の完成・CIBA 準拠の証明ではない。

## 実行環境と範囲

- Ruby 4.0.6、rodauth-oauth 1.7.0（RubyGems 配布版）、Rodauth 2.28.0。
- Sequel 5.108.0、sqlite3 gem 2.9.6、SQLite 3.53.2、WAL、最大4接続。
- JWT 3.3.0 / RS256。依存バージョンはルートの Gemfile.lock に保存。
- Rack::MockRequest から実際の Roda / Rodauth の HTTP 処理を実行。ネットワークサーバーは起動していない。
- DB、トークン保存、JWT 署名・検証は実物。アプリの本人解決はテスト専用メール検索。署名障害とフック障害は意図的に注入。
- 実験のクライアントは静的登録・public subject・client_secret_basic。scope=openid、期限300秒に限定。製品方針として確定したわけではない。

## Red → Green

1. [最初の Red](tdd-initial-red.txt): 3テストが CIBA 受付未実装の404で失敗。テスト基盤の依存不足を修正してから記録。
2. 受付・Ruby承認・token endpoint 接続を実装し、3テスト / 66 assertions が成功。
3. [境界テストの Red](tdd-boundaries-red.txt): poll 時刻未保存、未実装のフック・observer、外側で例外を捕捉した場合の残存更新を検出。テスト側の例外クラス参照誤りも1件含む（製品不具合とは区別）。
4. savepoint、poll 更新、発行フック、after_commit 通知を実装。追加の savepoint rollback / JWT access token テストも含め、[最終結果](tdd-green.txt) は **14 tests / 151 assertions / 0 failures / 0 errors**。

## 確認できた振る舞い

| テスト | 確認した結果 |
|---|---|
| 承認→発行 | RS256署名、iss/aud、顧客sub、exp/iat、at_hash、認証コンテキストのsnapshot、ID署名1回、refreshなし |
| 同じ要求を再交換 | invalid_grant、grantが増えない |
| 同時poll | 別DB接続を保持した2スレッドをbarrierで同時開始、10要求で各1成功・1 invalid_grant、grant計10件 |
| 署名例外 | 署名前にconsumedとgrant INSERTが実在することを確認し、例外後は両方rollback。再試行成功 |
| pending / slow_down | JSON応答のhalt後もpoll時刻とinterval更新が保存される。連続早期pollで5→10→15秒 |
| contextなし | auth_time/acr/amrを捏造しない |
| 本人・client・期限 | 別本人の承認、別clientのpoll、期限切れの発行を拒否 |
| client認証なし | 開始・tokenの両endpointで401、要求・grantを新規保存しない |
| 非CIBA | authorization_codeで署名付きID Tokenと元のnonce/auth_timeを返す |
| before/after | beforeはapproved、afterはconsumedを見る。after例外で両DB更新rollback |
| observer障害 | 最外commit後に実行。observerとreporterがともに例外でも結果を変更しない |
| 外側rollback | 要求消費・grant・観測イベントがすべて取り消される |
| 外側が例外捕捉 | 外側をcommitしても、失敗した発行の更新はsavepointで取り消される |
| 中間savepoint rollback | 最外transactionがcommitしても取り消した発行のイベントは配信されない |
| JWT access token設定 | JWT access token / ID Token双方を検証し、同じ顧客sub、refreshなし |

同時pollのテストは異なる接続の使用をassertするが、すべてのスケジュール・隔離レベルでの正しさを証明するものではない。

## 設計に反映する発見

### 1. transaction に入れるだけでは、外側が例外を捕捉した場合に不十分

Sequel の通常の入れ子transactionは既存transactionに参加する。内側の例外をアプリが捕捉して外側をcommitすると、消費済み要求とgrantが残る失敗を再現した。CIBAの処理境界を **savepoint: true** に変更した。これは実験から得た設計修正である。

### 2. 観測通知には savepoint も考慮した after_commit を使う

`db.after_commit(savepoint: true)` により、最外commitまで待ち、中間savepointのrollbackでも通知を取り消せた。observer例外と障害報告の例外は別々に捕捉する。

### 3. 既存token routeに接続できるが、OIDC wrapperの扱いを明示する

CIBA分岐は `generate_token(attrs, false)` と `generate_id_token(grant)` を呼ぶ。非CIBAはsuperへ渡す。CIBAのID Tokenには承認時に受け取った認証コンテキストを使う。上流の「アカウントの最終ログイン時刻」を誤って使わないことをテストした。

### 4. SQLite の書込み開始方法を明示する

今回のSQLite実験は、CIBA token transactionとRuby承認を `BEGIN IMMEDIATE` で開始する。読み取り後のwrite-lock昇格に依存しない構成である。この選択はDB固有であり、条件付きUPDATEだけで全DBの競合問題を解決したとは言えない。アプリがすでに外側でdeferred transactionを開始した場合、それを内側からIMMEDIATEに変更することはできない。

## 未実装・未検証

- PostgreSQL/MySQL、Ruby 3.3/3.4、他のRodauth/Sequelバージョン、並列プロセス・分散ノード、DB busy時の再試行。
- 全CIBA要求検証・Discovery・拒否API・冪等な承認再送・cleanup・通知復旧・正式migration。保存カラムも実験に必要なものだけ。
- 受付/承認/拒否の全フック、同一要求へのフック再入防止、観測イベントの正式なschema。
- client metadata変更と発行の競合、ロック待ち中の期限経過のプロトコルエラー変換。現在は安全側に例外rollbackする箇所があるが、正規のexpired_token応答まで保証しない。
- pending更新のCAS競合は仮のinvalid_grantで終了しており、契約案の再読込・有限再試行は未実装。SQLite IMMEDIATE以外の挙動を一般化しない。
- アプリはHTTP応答を外側transactionのcommitより先に送ってはならない。外側rollbackテストで組み立てた成功応答はクライアントに配送していない。
- テストは認証コードフロー1例の回帰確認であり、upstream全テスト実行ではない。OIDC Conformance Suiteは実行していない。

## 参照

- [CIBA Core §10.1–11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_request): token発行、再交換、pending/slow_down/client bindingの参照仕様。
- [Sequel transaction実装](https://github.com/jeremyevans/sequel/blob/5.108.0/lib/sequel/database/transactions.rb): transaction/savepoint/after_commit。実行対象のインストール済みソースも確認した。

Jevには実装・テスト・この結果と限界を渡して再評価を取得した。[再評価結果](jev-tdd-review.md)を参照。
