# Jev との反復評価と Codex の GO 判断

2026-09-29。モデルは jev-1.13.0。追加5回の問い合わせを実施した。新しい設計案をユーザーの合意として扱わない。

## 結論

**検証を含む最初の縦断実装には GO。保存設計の全面確定、全機能の完成、公開・本番導入にはまだ GO を出さない。**

根拠は Jev の数値だけではなく、契約の具体化、仕様確認、上流コードの接続経路、限定された SQLite 実験。低 Confidence の項目を自動採用していない。

## 足切りと反復

Confidence >= 0.8 は案に織り込む候補、0.5以上0.8未満は人がレビュー、0.5未満は採用保留。「情報不足」と「他案」を別の選択肢にした。これは未校正の議論用ルールで、自動実行の許可や正しさの保証ではない。

1. 具体的な API・状態遷移を11観点で評価。保存設計が修正判定。
2. 9個の具体的な欠陥候補を診断。account/client の無効化、保存制約、poll 状態、callback 例外を補足。
3. 再評価では Confidence が下がる項目もあり、保存設計は修正判定が継続。
4. 次の証拠の選択を依頼すると、小規模 SQL 実験が選択確率100%、Confidence 0.99。上流への接続経路も調査。
5. SQLite 実験と上流コードの注意点を追加して再評価。同じ入力を反復して最大値を選ぶ方法は取っていない。

## 評価の推移

数値は Confidence。最終回答が「着手可」でも低値を自動採用しない。

| 観点 | 初回 | 修正後 | 証拠追加後 | 最終回答 |
|---|---:|---:|---:|---|
| 初版範囲 | 0.86 | 0.77 | 0.94 | 着手可 |
| 本人の紐付け | 0.55 | 0.47 | 0.67 | 着手可 |
| 完了 API と再送 | 0.73 | 0.68 | 0.82 | 着手可 |
| 保存設計 | 0.32 | 0.47 | 0.26 | 修正 |
| 通知引き渡し | 0.74 | 0.71 | 0.79 | 着手可 |
| 観測 | 0.70 | 0.67 | 0.80 | 着手可 |
| 並行更新 | 0.47 | 0.44 | 0.57 | 着手可 |
| 期限・cleanup | 0.31 | 0.29 | 0.61 | 着手可 |
| プロトコル方針 | 0.67 | 0.64 | 0.83 | 着手可 |
| 検証計画 | 0.85 | 0.79 | 0.91 | 着手可 |
| 全体の着手阻害要因 | 0.43 | 0.32 | 0.50 | 着手可 |

保存設計の最終分布は修正44%、着手可40%、情報不足13%、他案3%。Jev が設計全体を承認したとは言えない。質問を変えた診断では「具体的な保存上の阻害要因なし」が47%で最上位になるなど、判定は揺れている。

## Codex の判断

本人の固定対応、通知の復旧経路と best-effort の限界、運用期間を明示設定とする契約によって、実装の最初の検証に進める。保存案と全DBの競合動作はまだ検証候補であり、永続的な公開契約として採用しない。

とくに同時更新はモデルの選択確率で安全性を判定しない。SQLite で version の条件付き更新による二重 poll、approve/deny 競合を各20回確認し、例外時の状態と INSERT の rollback、期限切れ、別クライアントの拒否も確認した。Python sqlite3 の SQL 仮説に限定した証拠であり、実 Sequel/Rodauth や PostgreSQL/MySQL の証明ではない。

上流コード調査で、CIBA の create_token が OIDC wrapper を飛ばす可能性、auth_time が現在の最終ログイン時刻から再取得される経路、JSON 用 throw と通常例外の差を確認した。これらを最初の実装ゲートへ組み込んだ。

## 最初の実装ゲート

1. Ruby >=3.3 と実 Sequel/Rodauth 環境を用意する。
2. 実 Rack endpoint で access token と検証可能な ID Token を一度だけ発行し、refresh token を出さない。
3. 署名失敗なら request 消費と grant 作成をともに rollback する。
4. 認証コンテキストの snapshot、pending/slow_down の保存、外側 transaction と観測の順序をテストする。
5. PostgreSQL/MySQL の競合テストと既存 grant フローの回帰テストで、保存案を確定する。

失敗すれば設計を修正する。公開前には gem 名・ライセンス・依存範囲・CI・利用文書も確定する。

## 再現用ファイル

- [実装契約案](../implementation-contract.md)
- [SQL 実験](sqlite-transition-spike.py) / [結果](sqlite-transition-spike-result.json)
- [初回評価入力](jev-refinement-1-request.json) / [回答](jev-refinement-1-response.json)
- [欠陥候補診断入力](jev-diagnosis-request.json) / [回答](jev-diagnosis-response.json)
- [修正後評価入力](jev-refinement-2-request.json) / [回答](jev-refinement-2-response.json)
- [追加証拠の選択入力](jev-storage-diagnosis-request.json) / [回答](jev-storage-diagnosis-response.json)
- [証拠追加後評価入力](jev-refinement-3-request.json) / [回答](jev-refinement-3-response.json)
