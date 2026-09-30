# Docker による DB 横断実験

2026-09-29。縦断TDD実験の次のステップとして、ユーザーの依頼によりPostgreSQL/MySQLで同じシナリオを検証した。

## 結果

| DB | DBの設定 | 結果 |
|---|---|---|
| SQLite 3.53.2 | WAL、CIBA書込みはIMMEDIATE | 14 tests / 151 assertions、失敗・エラーなし |
| PostgreSQL 17.11 | 既定のREAD COMMITTED | 14 tests / 151 assertions、失敗・エラーなし |
| MySQL 8.4.11 | InnoDB、既定のREPEATABLE READ | 14 tests / 151 assertions、失敗・エラーなし |

共通: Linux arm64、Ruby 4.0.6、rodauth-oauth 1.7.0、Rodauth 2.28.0、Sequel 5.108.0、JWT 3.3.0。DBドライバはsqlite3 2.9.6、pg 1.6.3、mysql2 0.5.7。

[再現スクリプトの実行結果](cross-database-results.txt)。各DBで2接続からの同時pollを10要求分検証し、それぞれ成功1件・invalid_grant 1件、grant計10件を確認した。実署名、発行失敗、フック例外、savepoint、外側transaction、観測イベント、既存authorization_codeの回帰確認も同じテストを通した。

今回のDB横断検証では **CIBA本体のコード変更は不要だった**。変更したのはDB接続・テスト用DBの作成削除と実行環境のみ。ローカルmacOS/Ruby 4.0.6のSQLiteテストも引き続き成功した。

## 再現方法と環境管理

ルートで `./bin/test-databases --seed 3363` を実行する。Ruby・PostgreSQL・MySQLのイメージはDockerfile.test / compose.yamlでdigestを固定した。Gemfile.lockでgem依存を固定している。OSパッケージ取得はaptリポジトリに依存するため、ビット単位の再現性までは保証しない。

- DBの起動完了はhealthcheckと `service_healthy` で待つ。[Compose公式資料](https://docs.docker.com/compose/how-tos/startup-order/)
- ホスト側のDBへは接続せず、Compose内部の固定ホストを使用。ホストへのポート公開なし。
- 各テストはプロセスID＋乱数の専用DBを作成し、自分が作成できたDBだけをteardownで削除する。
- DBデータはtmpfs。スクリプト終了時に当該Composeプロジェクトのコンテナ・ネットワークを削除する。イメージとビルドキャッシュは残る。
- PostgreSQL/MySQLのテスト用ユーザーにはDB作成削除権限がある。これらの固定認証情報は本番向けではない。

## 判断と限界

専用CIBA要求テーブルと既存grantの保存を同じtransaction/savepointで扱う設計は、今回の3DB構成で維持できる。SQLiteだけの結果から一般化していた段階より証拠が増えた。

ただしこれは、全てのSequelアダプタや隔離レベルでの保証ではない。以下は依然として未検証・未実装である。

- PostgreSQLのREPEATABLE READ / SERIALIZABLE、MySQLの他の隔離レベル、deadlock・serialization failure・DB busyの再試行。
- 複数プロセス／複数ホスト、長時間の負荷、DB切断、failover。現在の競合テストは2スレッド・別接続での10回の実験。
- ロック待ち中の期限経過、pending pollのCAS競合の再読込、同一要求へのフック再入防止など、前回記録の未実装部分。
- SQLiteでアプリが先に開始した外側deferred transactionのwrite-lock昇格。
- Ruby 3.3/3.4、他の依存バージョン、正式migration、Discoveryを含む完全なCIBA対応、Conformance Suite。

全体の未完了項目は [縦断TDD実験](tdd-vertical-slice.md) と [実装契約案](../implementation-contract.md) に引き続き従う。今回Jevへの追加問い合わせは行っていない。
