# 0.1.0 公開準備の計測可能なゴール

2026-09-29 ユーザー依頼により開始。外部レジストリへの公開操作は含まず、配布できる成果物を作る。

## 完了条件

- [x] poll / login_hint / public subject / 静的登録のCIBA OPを実装。署名要求・他hint・user_code・refresh・pairwise・DCRの非対応を明記し、誤受理しない。
- [x] Discovery、TLS/form POST、client認証、scope/hint/期限/binding_message、エラー応答を仕様要求に対応付けたテストで検証。
- [x] Ruby承認・拒否・同一再送・競合・本人/クライアント拘束・失効・一度だけの発行・期限・cleanupを実DBで検証。
- [x] before/after、savepoint、最外commit後の観測、callback障害、再入防止、秘密非混入をテスト。
- [x] SQLite/PostgreSQL/MySQLで全テスト成功。Ruby 3.3/3.4/4.0で実行し、実際のバージョンを記録。
- [x] 明示migration、設定リファレンス、導入手順、動くアプリ連携サンプル、運用・責務境界、仕様/テスト対応表を提供。
- [x] gemspec/バージョン/ライセンス/著作者/CHANGELOG/配布ファイルを整備し、gem build成功。生成gemを別環境へインストールし、サンプルまたはsmoke testが成功。
- [x] 実行可能なCIを用意し、既知の公開阻害不具合が残っていないことをレビュー。未検証環境・制約を明記し、Certifiedを称さない。

## 初版の実装判断

過去の未決定案について、今回の実装裁量でpublic subject・静的登録を0.1.0の制限とする。クライアント認証はupstreamのclient_secret_basic / client_secret_postを対象とし、他の認証方式との組み合わせは明示的に設定エラーにする。UI/通知輸送/上流認証/委譲/業務認可はアプリ側。

判定はテスト実績と成果物による。モデルのConfidence、テスト数のみ、予定したCIの存在だけでは完了としない。

完了: 2026-09-29。実績は [公開検証](release-validation.md) を参照。成果物: `pkg/rodauth-ciba-0.1.0.gem`。実レジストリ公開は未実施。
