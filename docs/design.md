# CIBA OP 拡張の設計メモ

設計インタビューで確定した事項とその後の検証履歴を記録する。現在の公開候補の契約は [API](api.md)、[運用](operations.md)、[仕様テスト対応](protocol-coverage.md) を参照。限定的な設計検証用実装を開始しているが、未決定の項目を実装済み・合意済みと扱わない。

## 確定した範囲

- rodauth-oauth の CIBA OP 拡張を独立 gem として OSS 公開する。最初の利用先は自社サービス。
- 初版のトークン取得モードは poll のみ。
- 初版で受け付けるユーザー特定 hint は login_hint のみ。id_token_hint と login_hint_token は初版の対象外とし、対応範囲を文書化する。
- 署名付き認証要求と user_code は初版では未対応と明示する。クライアント認証は必須であり、要求全体への署名とは区別する。
- 初版の CIBA フローでは refresh token を発行しない。他の既存 grant の発行方針は変更しない。
- アプリとの責務分界は [ADR 0002](adr/0002-limit-gem-to-ciba-op-extension.md) に従う。
- 特定の CIBA クライアントへの対応を前提にしない。初期導入先のクライアントはアプリ側で実装する。
- CIBA 要求は rodauth-oauth と同じ DB に保存する。専用テーブルの形とトランザクションの詳細は未確定。
- 初版の監査連携は、イベントと共通項目を定義したフックを提供し、導入アプリがログを出力する方針とする。
- 認証・承認結果は Ruby API で受け取る。HTTP などのトランスポートは導入アプリが選択・実装する。
- 観測用イベントは任意とし、通知先の失敗で CIBA の成否を変えず、障害を報告する。
- 主要な状態変更には Rodauth の慣例に沿う before / after フックを設ける。トランザクション内の拡張処理と観測用イベントの契約は [ADR 0003](adr/0003-follow-rodauth-hook-conventions.md) に従って区別する。
- Ruby の下限は 3.3 とする。2026-09-28 時点で 3.3 はセキュリティ保守、3.4 と 4.0 は通常保守中（[公式保守一覧](https://www.ruby-lang.org/en/downloads/branches/)）。将来の下限変更を自動化する方針までは決めていない。
- DB 対応は rodauth-oauth に従い、Sequel を通じて実装する。特定 DB 専用の拡張には限定しない。Sequel にアダプタがあることだけで上流や本 gem の動作検証済みとは扱わず、CI で検証した組み合わせを明記する。

## 検証方針

CIBA Core、関連する OIDC/OAuth 仕様および RFC の適用可能な要求を、要求と対応付けた単体テストで検証する。OIDC Conformance Suite の該当ケースをテスト設計の参照にする。

OIDC Certified の取得、Conformance Suite 自体の実行・通過、独立クライアントによる接続試験は初版の公開条件としない。単体テストの成功を、認定取得や未検証の相互運用性の証明として扱わない。

## 未決定

未決定論点について [Jev による24論点の評価](research/jev-design-round.md) を取得した。これは議論用の参考であり、以下の項目の合意や実装承認には代えない。

その後、[実装契約案](implementation-contract.md) を作成し、追加5回の Jev 評価と限定的な SQL 実験を実施した。[反復結果](research/jev-iteration-review.md) では Codex は検証を含む最初の縦断実装に GO と判断した。保存設計は採用保留であり、ユーザーとの合意・全体設計確定・公開の GO とは区別する。

- 要求の保存スキーマ、依存 gem のバージョン範囲、Ruby 実装と DB の具体的な CI 構成。
- 本人特定、認証・承認結果の受け渡し、業務コンテキストとの関連付けの契約。
- subject identifier とクライアント登録は仕様を説明したうえで判断する。public のみ・事前登録のみという案はまだ未採用。offline_access 要求時の扱いなど、既存 feature との詳細な接続も未決定。
- before / after フックの対象となる状態変更、具体的なメソッド契約。観測イベントの実行時点・項目・障害報告方法。

## Discovery と承認結果の受け渡し

CIBA Core §4 は `backchannel_authentication_endpoint` と対応モードなどの OP metadata を定義する。poll の結果取得には既存の `token_endpoint` を使用する。これらはクライアントが要求を開始して結果を取得するための標準インターフェースである。

顧客を認証し承認を得る過程は CIBA Core §8 で実装に委ねられており、アプリから OP に承認・拒否を伝える標準エンドポイントやその Discovery 項目は定義されていない。gem は結果を受け取る Ruby API を提供し、導入アプリとのトランスポートを固定しない。標準 CIBA API は Discovery で公開する。

参照: [CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)

観測用イベントの失敗は CIBA の成否に影響させない。これとは別に、Rodauth の慣例に沿う before / after フックを状態変更と同じ DB トランザクション内に設ける。事例調査は [IdM 調査メモ](research/idm-ciba-integration.md) を参照。


## 最初の TDD 実験

ユーザーの依頼により、[最初の縦断部分をTDDで検証](research/tdd-vertical-slice.md)した。実Rodauth・Sequel・SQLiteで14テストが成功し、外側transactionが例外を捕捉する場合には内側savepointが必要であることが分かった。実装契約案を修正した。実験はRuby 4.0.6 / SQLiteに限定し、全体設計・全対応DB・公開可能性の確定とは区別する。

実験後の [Jev再評価](research/jev-tdd-review.md) でも設計方向の維持が選ばれた。Codexは次の限定検証にGOと判断し、PostgreSQL/MySQLで同じシナリオを確認することを次の候補とする。


## DB 横断検証（2026-09-29）

続いてDockerでSQLite 3.53.2・PostgreSQL 17.11（READ COMMITTED）・MySQL 8.4.11（InnoDB / REPEATABLE READ）に同じ14テストを実行し、全て成功した。CIBA本体の変更は不要だった。[環境・結果・限界](research/cross-database-experiment.md)を記録し、`bin/test-databases`で再現できるようにした。未検証の隔離レベル、障害時再試行、他バージョンまで保証する結果ではない。


## 0.1.0 公開候補

ユーザーからの「計測可能なゴールを設定し、初版公開可能なレベルへ進める」依頼により、[公開ゴール](release-goal.md)に沿って実装を進めた。公開名はrodauth-ciba、初版はpoll/login_hint/public subject/静的登録/basic・post client認証。これは実装判断であり、過去の個別質問への回答を捏造したものではない。

現行実装では、条件付きversion更新に加え、PostgreSQL/MySQLはロック付き読み取り、SQLiteはIMMEDIATE transactionを使う。失敗後のsavepoint分離、再入防止、同一承認・拒否再送、Discovery、通知回復とcleanup、明示migrationを含む。実行環境と結果は[公開検証](release-validation.md)に集約する。研究メモにある旧未実装項目や旧テスト数は当時の記録として保持する。

## node-oidc-providerへの整合化（2026-09-30）

ユーザーの依頼により、先行するリリース版を設計・実装の基準として見直す作業を開始した。[対象・証拠・残作業](node-alignment.md)を管理する。現在はbinding_messageの既定policyと差替えAPIを変更済みで、全体の整合化は未完了。過去の公開候補の判断を、この新しい目標の達成証拠には用いない。
