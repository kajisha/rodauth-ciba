# CIBA Core仕様項目ごとのJev採点

2026-09-29 / rodauth-ciba 0.1.0候補（OP全体の認証方式制限を外した後） / `jev-1.13.0`。

## 読み方

実装・公開API・テスト・上流の関連メソッドを入力し、159評価単位を採点した。点数は **0〜4の実装証拠スコア**。実装率・正しい確率・認定合格率ではない。総合平均や合格点は設けない。任意機能未対応、クライアント責務、導入アプリ責務を必須欠落と合算しない。

| 水準 | 定義 |
|---|---|
| 0 | 実装の証拠なし、または要求と明確に矛盾 |
| 1 | 設定・足場・接続フックのみ |
| 2 | 主要部分はあるが重要な不足がある |
| 3 | 実装は概ね要求を満たすが、直接の検証証拠が不足 |
| 4 | 実装と直接テストなどの証拠で要求を確認できる |

小数はJevが返した水準の確率加重値。Confidenceは分布の集中度であり、正しさの確率ではない。分類と点数は独立した質問のため、整合しない場合がある。低Confidenceを自動的な失敗扱いにしない。

## 対象と限界

- CIBA Core §4〜§15のプロトコル・セキュリティ・プライバシーに関する要求と任意能力を、人手で159単位に整理した。159は仕様が公式に定める要求数ではない。関連する条件を同じ単位に含む箇所もある。
- 導入・用語・例示・IANA登録手続き・参考文献を実装採点に含めない。参照先OIDC Core/RFCの全要求を再帰的に分解したものでもない。未抽出条項がないと保証する網羅性検査は未実施。
- 現行gemの全Ruby実装とAPI/運用文書を各パケットへ入力。テストは単位群ごとに語句で選んだ10メソッド、上流は関連メソッドの抜粋。パケットにテストがない場合は、実際にテストがないことを意味しない。
- 大きい初期パケットはAPIのmax_tokens_exceededで拒否されたため、16項目ずつ10回に分割。全159項目についてScoreとChoiceの318回答を取得した。
- コードと食い違った7項目を、具体的なコード・テストに絞った別入力で1回再評価。前回の点数や望む結論は渡していない。元の回答は保存し、都合のよい結果への置換はしていない。
- 50 tests /376 assertionsという既存の検証記録を渡した。この採点作業ではテスト再実行・実装修正・gem再ビルドをしていない。
- 成功した11回の使用量: input 354,723 / output 18,678 tokens。API拒否分の利用量は応答に含まれず集計外。

## 人手で確認すべき判定

Jevは理由文を返していない。以下の解釈・根拠は実装者による確認で、Jevの説明ではない。

- **CIBA-038**: 初版対象外のhint。初回の欠落判定から対象外へ変化。
- **CIBA-039**: 初版対象外のhint。初回の欠落判定から対象外へ変化。
- **CIBA-041**: 要人手解釈。gemは文字列受理・必須検証・resolver呼出しを実装。識別子の意味と解決は意図してアプリに委譲。初回の未実装判定は不適切。
- **CIBA-049**: 初版対象外の署名付き要求。JWTクライアント認証とは別。
- **CIBA-070**: クライアント向けhintポリシーの案内は導入先に依存。gemの型制約はAPI文書に記載されるが、導入先の案内まで証明しない。
- **CIBA-079**: 本文はクライアントのopaque扱い。OP実装済み扱いの分類はそのまま採用しない。
- **CIBA-123**: pending分岐と直接テストは存在。低スコアだけでは実装欠陥を示さない。
- **CIBA-128**: 誤判定の疑い。実装はslow_downを継続し、過剰poll回数に応じてinvalid_requestに切り替える分岐はない。この切替はMAYなので必須欠落ではない。
- **CIBA-136**: ciba_error→上流throw_json_response_errorでJSONを構築。低スコアは欠陥の再現結果ではない。
- **CIBA-137**: 要調査。上流response_error_paramsは設定された説明文字列をそのまま格納し、可視範囲にASCII範囲検証がない。この上流メソッドは採点パケットから欠けていた。カスタム説明の境界テストは未実施。
- **CIBA-139**: 既存テストで欠落・重複・複数hintのHTTP400を検証。低スコアのみを不合格扱いしない。

これらの食い違いがあるため、この採点をそのまま公開可否の判定には使わない。特に「login_hint未実装」と「過剰pollのinvalid_request切替実装済み」は、数値だけでは採用できない。

## 全159項目

再評価した行は「初回 → 再評価」で点数を表示する。分類とConfidenceは最後の回答を表示し、元の分布はresults.jsonから確認できる。対象外にも生の点数を残すが、それは準拠性の減点ではない。

| ID / 仕様 | 評価対象 | 点数 / 4 | Jev分類 | Score Confidence | 分類Confidence |
|---|---|---:|---|---:|---:|
| [CIBA-001 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | CIBA grant識別子 | 3.80 | 実装済み判定 | 0.83 | 0.87 |
| [CIBA-002 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | Discoveryの対応モード | 3.95 | 実装済み判定 | 0.95 | 0.98 |
| [CIBA-003 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | Discoveryの開始URL | 3.94 | 実装済み判定 | 0.95 | 0.99 |
| [CIBA-004 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 署名要求の対応表明 | 3.48 | 実装済み判定 | 0.57 | 0.73 |
| [CIBA-005 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | user_codeの対応表明 | 3.64 | 実装済み判定 | 0.70 | 0.87 |
| [CIBA-006 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | Discoveryのgrant_types | 3.92 | 実装済み判定 | 0.93 | 0.99 |
| [CIBA-007 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 認証方式メタデータの共有 | 3.40 | 実装済み判定 | 0.50 | 0.78 |
| [CIBA-008 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 認証署名アルゴリズムの共有 | 1.70 | 任意・対象外 | 0.00 | 0.71 |
| [CIBA-009 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 登録済み配送モード | 3.42 | 実装済み判定 | 0.52 | 0.75 |
| [CIBA-010 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | CIBA grantのクライアント登録 | 3.70 | 実装済み判定 | 0.75 | 0.91 |
| [CIBA-011 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 通知URL登録 | 0.56 | 任意・対象外 | 0.53 | 0.90 |
| [CIBA-012 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 署名要求アルゴリズム登録 | 1.73 | 任意・対象外 | 0.00 | 0.43 |
| [CIBA-013 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | user_codeクライアント設定 | 2.56 | 任意・対象外 | 0.00 | 0.47 |
| [CIBA-014 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | 登録された認証方式 | 3.43 | 実装済み判定 | 0.53 | 0.90 |
| [CIBA-015 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | pairwise sector算出 | 0.35 | 任意・対象外 | 0.71 | 0.66 |
| [CIBA-016 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | pairwise DCR検証 | 0.22 | 任意・対象外 | 0.81 | 0.75 |
| [CIBA-017 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | pairwise鍵所有証明 | 0.17 | 任意・対象外 | 0.86 | 0.77 |
| [CIBA-018 §4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4) | push pairwise sector | 0.04 | 任意・対象外 | 0.97 | 0.94 |
| [CIBA-019 §5](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | poll配送 | 3.78 | 実装済み判定 | 0.81 | 0.93 |
| [CIBA-020 §5](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | ping配送 | 0.08 | 任意・対象外 | 0.93 | 0.69 |
| [CIBA-021 §5](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | push配送 | 0.08 | 任意・対象外 | 0.93 | 0.75 |
| [CIBA-022 §5](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5) | push sender-constrained token | 0.04 | 任意・対象外 | 0.97 | 0.99 |
| [CIBA-023 §7](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7) | 開始APIのTLS | 3.77 | 実装済み判定 | 0.81 | 0.90 |
| [CIBA-024 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 開始APIのPOSTとform | 3.75 | 実装済み判定 | 0.79 | 0.91 |
| [CIBA-025 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 開始APIのクライアント認証 | 3.76 | 実装済み判定 | 0.80 | 0.94 |
| [CIBA-026 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのissuer受理 | 3.65 | 実装済み判定 | 0.71 | 0.87 |
| [CIBA-027 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのToken URL受理 | 3.70 | 実装済み判定 | 0.75 | 0.95 |
| [CIBA-028 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのBackchannel URL受理 | 3.76 | 実装済み判定 | 0.80 | 0.95 |
| [CIBA-029 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | JWT audienceのissuer推奨 | 3.13 | 実装済み判定 | 0.27 | 0.65 |
| [CIBA-030 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | scope必須 | 2.59 | 実装済み判定 | 0.40 | 0.77 |
| [CIBA-031 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | openid scope | 2.67 | 実装済み判定 | 0.49 | 0.81 |
| [CIBA-032 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 追加scope | 2.64 | 実装済み判定 | 0.58 | 0.79 |
| [CIBA-033 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 通知トークン必須条件 | 0.16 | 任意・対象外 | 0.86 | 0.98 |
| [CIBA-034 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 通知トークンの長さと構文 | 0.21 | 任意・対象外 | 0.82 | 0.91 |
| [CIBA-035 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 通知トークンentropy | 0.07 | 任意・対象外 | 0.94 | 0.65 |
| [CIBA-036 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | acr_values受理 | 3.19 | 実装済み判定 | 0.32 | 0.75 |
| [CIBA-037 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 達成したacrの返却 | 2.91 | 実装済み判定 | 0.52 | 0.58 |
| [CIBA-038 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | login_hint_token ※ | 0.32 → 0.02 | 任意・対象外 | 0.98 | 0.58 |
| [CIBA-039 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | id_token_hint ※ | 0.18 → 0.02 | 任意・対象外 | 0.98 | 0.58 |
| [CIBA-040 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | 暗号化id_token_hintの復号 | 0.24 | クライアント責務 | 0.80 | 0.56 |
| [CIBA-041 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | login_hint ※ | 0.13 → 1.75 | 導入アプリ責務 | 0.14 | 0.65 |
| [CIBA-042 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | binding_messageの受理と引継ぎ | 3.10 | 実装済み判定 | 0.25 | 0.32 |
| [CIBA-043 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | binding_messageの関連付け | 1.74 | クライアント責務 | 0.00 | 0.77 |
| [CIBA-044 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | binding_messageの表示適性 | 1.70 | クライアント責務 | 0.00 | 0.71 |
| [CIBA-045 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | user_code | 1.13 | クライアント責務 | 0.06 | 0.80 |
| [CIBA-046 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | requested_expiry構文 | 2.47 | 実装済み判定 | 0.00 | 0.39 |
| [CIBA-047 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | requested_expiryの採用 | 2.20 | 実装済み判定 | 0.00 | 0.53 |
| [CIBA-048 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1) | hintはちょうど一つ | 2.40 | 実装済み判定 | 0.00 | 0.37 |
| [CIBA-049 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のJWT形式 ※ | 0.05 → 0.02 | 任意・対象外 | 0.98 | 0.64 |
| [CIBA-050 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求の非対称署名 | 0.21 | 任意・対象外 | 0.82 | 0.60 |
| [CIBA-051 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のaud | 0.40 | 任意・対象外 | 0.67 | 0.71 |
| [CIBA-052 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のiss | 0.29 | 任意・対象外 | 0.75 | 0.60 |
| [CIBA-053 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のexp | 0.33 | 任意・対象外 | 0.72 | 0.66 |
| [CIBA-054 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のiat | 0.34 | 任意・対象外 | 0.72 | 0.64 |
| [CIBA-055 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のnbf | 0.22 | 任意・対象外 | 0.81 | 0.69 |
| [CIBA-056 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のjti | 0.41 | 任意・対象外 | 0.65 | 0.57 |
| [CIBA-057 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求のrequested_expiry型 | 1.87 | 任意・対象外 | 0.00 | 0.65 |
| [CIBA-058 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 署名要求の内外混在禁止 | 2.02 | 任意・対象外 | 0.00 | 0.41 |
| [CIBA-059 §7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1) | 暗号化要求非対応 | 1.44 | 任意・対象外 | 0.00 | 0.69 |
| [CIBA-060 §7.1.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_codeはOPパスワードと別 | 0.58 | 任意・対象外 | 0.52 | 0.83 |
| [CIBA-061 §7.1.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_codeの例外ポリシー | 0.21 | 任意・対象外 | 0.82 | 0.87 |
| [CIBA-062 §7.1.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_codeの都度入力 | 3.46 | 実装済み判定 | 0.55 | 0.89 |
| [CIBA-063 §7.1.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.2) | user_code変更手段 | 1.37 | 任意・対象外 | 0.00 | 0.78 |
| [CIBA-064 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 登録方式による認証検証 | 3.29 | 実装済み判定 | 0.41 | 0.81 |
| [CIBA-065 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 公開鍵認証の推奨 | 3.14 | 実装済み判定 | 0.28 | 0.65 |
| [CIBA-066 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 署名要求検証 | 0.95 | 任意・対象外 | 0.21 | 0.79 |
| [CIBA-067 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 認証要求パラメータ検証 | 3.57 | 実装済み判定 | 0.64 | 0.80 |
| [CIBA-068 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 複数hintのエラー | 3.02 | 実装済み判定 | 0.35 | 0.83 |
| [CIBA-069 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | hintとユーザーの検証 | 3.02 | 導入アプリ責務 | 0.19 | 0.62 |
| [CIBA-070 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | hintポリシーの伝達 ※ | 0.72 → 0.66 | 欠落判定 | 0.45 | 0.23 |
| [CIBA-071 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 不正または不明hintのエラー | 3.28 | 実装済み判定 | 0.40 | 0.58 |
| [CIBA-072 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 必須パラメータ検証 | 3.63 | 実装済み判定 | 0.69 | 0.89 |
| [CIBA-073 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 未知パラメータの無視 | 3.52 | 実装済み判定 | 0.60 | 0.87 |
| [CIBA-074 §7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2) | 開始エラーの形式 | 3.38 | 実装済み判定 | 0.48 | 0.85 |
| [CIBA-075 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | 受付成功HTTP 200 | 3.53 | 実装済み判定 | 0.61 | 0.87 |
| [CIBA-076 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_id必須と一意性 | 3.17 | 実装済み判定 | 0.31 | 0.78 |
| [CIBA-077 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_id entropy | 2.95 | 実装済み判定 | 0.44 | 0.65 |
| [CIBA-078 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_id文字集合 | 2.86 | 実装済み判定 | 0.33 | 0.60 |
| [CIBA-079 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | auth_req_idのopaque扱い ※ | 2.76 | 実装済み判定 | 0.27 | 0.31 |
| [CIBA-080 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | expires_in | 3.10 | 実装済み判定 | 0.44 | 0.71 |
| [CIBA-081 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | interval | 3.24 | 実装済み判定 | 0.51 | 0.82 |
| [CIBA-082 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | interval既定値 | 3.07 | 実装済み判定 | 0.53 | 0.46 |
| [CIBA-083 §7.3](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3) | 未知応答パラメータ | 1.25 | クライアント責務 | 0.00 | 0.91 |
| [CIBA-084 §7.4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.4) | 受付応答の必須項目確認 | 0.81 | クライアント責務 | 0.32 | 0.90 |
| [CIBA-085 §7.4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.4) | auth_req_id保持 | 1.35 | クライアント責務 | 0.00 | 0.91 |
| [CIBA-086 §7.4](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.4) | クライアント期限管理 | 0.97 | クライアント責務 | 0.19 | 0.64 |
| [CIBA-087 §8](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8) | 認証チャネルとacrの選択 | 1.12 | 導入アプリ責務 | 0.57 | 0.91 |
| [CIBA-088 §8](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8) | 認証後の承認取得 | 1.83 | 導入アプリ責務 | 0.10 | 0.85 |
| [CIBA-089 §10](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10) | 登録モード以外へ配送しない | 2.98 | 実装済み判定 | 0.51 | 0.82 |
| [CIBA-090 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token Endpoint認証 | 3.56 | 実装済み判定 | 0.63 | 0.78 |
| [CIBA-091 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | クライアントpoll間隔 | 1.78 | クライアント責務 | 0.00 | 0.85 |
| [CIBA-092 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | long polling | 0.23 | 任意・対象外 | 0.80 | 0.28 |
| [CIBA-093 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | OP応答時間 | 0.63 | 任意・対象外 | 0.47 | 0.24 |
| [CIBA-094 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | 重複poll禁止 | 0.63 | クライアント責務 | 0.47 | 0.62 |
| [CIBA-095 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | 503とRetry-After | 3.11 | 実装済み判定 | 0.26 | 0.56 |
| [CIBA-096 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Retry-After遵守 | 1.39 | クライアント責務 | 0.00 | 0.83 |
| [CIBA-097 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | pingクライアントのpoll許容 | 0.98 | 任意・対象外 | 0.18 | 0.30 |
| [CIBA-098 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token POST form | 3.71 | 実装済み判定 | 0.76 | 0.98 |
| [CIBA-099 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token grant_type必須 | 3.62 | 実装済み判定 | 0.68 | 0.98 |
| [CIBA-100 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | Token auth_req_id必須 | 3.34 | 実装済み判定 | 0.45 | 0.96 |
| [CIBA-101 §10.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1) | auth_req_idのクライアント束縛 | 3.07 | 実装済み判定 | 0.45 | 0.88 |
| [CIBA-102 §10.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1) | 成功Token応答 | 3.69 | 実装済み判定 | 0.74 | 0.95 |
| [CIBA-103 §10.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1) | 成功後の一回限り消費 | 3.69 | 実装済み判定 | 0.74 | 0.94 |
| [CIBA-104 §10.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1) | 認証承認前のToken禁止 | 3.31 | 実装済み判定 | 0.43 | 0.85 |
| [CIBA-105 §10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping HTTP POST | 0.13 | 任意・対象外 | 0.89 | 0.47 |
| [CIBA-106 §10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping bearer認証 | 0.44 | 任意・対象外 | 0.64 | 0.34 |
| [CIBA-107 §10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping payload | 0.70 | クライアント責務 | 0.41 | 0.32 |
| [CIBA-108 §10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | pingクライアント検証 | 0.28 | 任意・対象外 | 0.77 | 0.48 |
| [CIBA-109 §10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping応答処理 | 0.14 | 任意・対象外 | 0.88 | 0.54 |
| [CIBA-110 §10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | pingリダイレクト禁止 | 0.12 | 任意・対象外 | 0.90 | 0.43 |
| [CIBA-111 §10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2) | ping後の取得 | 0.11 | 任意・対象外 | 0.91 | 0.77 |
| [CIBA-112 §9](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.9) | 通知Endpoint TLS | 0.10 | 任意・対象外 | 0.91 | 0.77 |
| [CIBA-113 §9](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.9) | 通知Endpoint bearer認証 | 0.06 | 任意・対象外 | 0.95 | 0.35 |
| [CIBA-114 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push成功payload | 0.05 | 任意・対象外 | 0.96 | 0.98 |
| [CIBA-115 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push at_hash | 0.39 | 任意・対象外 | 0.68 | 0.96 |
| [CIBA-116 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push auth_req_id claim | 0.20 | 任意・対象外 | 0.83 | 0.95 |
| [CIBA-117 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push rt_hash | 0.18 | 任意・対象外 | 0.85 | 0.95 |
| [CIBA-118 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push受信検証 | 0.13 | 任意・対象外 | 0.89 | 0.48 |
| [CIBA-119 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push応答処理 | 0.08 | 任意・対象外 | 0.93 | 0.83 |
| [CIBA-120 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | pushリダイレクト禁止 | 0.10 | 任意・対象外 | 0.92 | 0.68 |
| [CIBA-121 §10.3.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1) | push未知パラメータ | 0.24 | 任意・対象外 | 0.80 | 0.46 |
| [CIBA-122 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | Tokenエラー形式 | 1.27 | 任意・対象外 | 0.00 | 0.45 |
| [CIBA-123 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | authorization_pending ※ | 2.30 | 実装済み判定 | 0.00 | 0.64 |
| [CIBA-124 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | slow_down | 3.39 | 実装済み判定 | 0.49 | 0.90 |
| [CIBA-125 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | expired_token | 3.69 | 実装済み判定 | 0.74 | 0.94 |
| [CIBA-126 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | access_denied | 3.25 | 実装済み判定 | 0.37 | 0.80 |
| [CIBA-127 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | invalid_grant | 2.96 | 実装済み判定 | 0.13 | 0.83 |
| [CIBA-128 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | 繰返し過剰pollの拒否 ※ | 1.78 → 2.68 | 実装済み判定 | 0.20 | 0.57 |
| [CIBA-129 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | invalid_request後の停止 | 1.59 | クライアント責務 | 0.00 | 0.92 |
| [CIBA-130 §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11) | pushクライアントのToken拒否 | 0.52 | 任意・対象外 | 0.57 | 0.88 |
| [CIBA-131 §12](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | pushエラーJSON | 0.08 | 任意・対象外 | 0.93 | 0.97 |
| [CIBA-132 §12](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push error_description文字集合 | 0.11 | 任意・対象外 | 0.91 | 0.96 |
| [CIBA-133 §12](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push access_denied | 0.10 | 任意・対象外 | 0.92 | 0.94 |
| [CIBA-134 §12](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push expired_token | 0.09 | 任意・対象外 | 0.93 | 0.97 |
| [CIBA-135 §12](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12) | push transaction_failed | 0.10 | 任意・対象外 | 0.92 | 0.96 |
| [CIBA-136 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 開始エラーJSON ※ | 1.47 | 実装済み判定 | 0.00 | 0.33 |
| [CIBA-137 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | error_description文字集合 ※ | 1.04 → 0.74 | 欠落判定 | 0.38 | 0.44 |
| [CIBA-138 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | error_uri文字集合 | 0.69 | 任意・対象外 | 0.43 | 0.30 |
| [CIBA-139 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_request ※ | 1.53 | 実装済み判定 | 0.00 | 0.46 |
| [CIBA-140 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_scope | 2.94 | 実装済み判定 | 0.11 | 0.59 |
| [CIBA-141 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 expired_login_hint_token | 1.04 | 任意・対象外 | 0.13 | 0.46 |
| [CIBA-142 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 unknown_user_id | 0.46 | 任意・対象外 | 0.62 | 0.80 |
| [CIBA-143 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 unauthorized_client | 0.51 | 任意・対象外 | 0.58 | 0.71 |
| [CIBA-144 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 missing_user_code | 0.17 | 任意・対象外 | 0.86 | 0.91 |
| [CIBA-145 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_user_code | 0.13 | 任意・対象外 | 0.89 | 0.90 |
| [CIBA-146 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 400 invalid_binding_message | 3.77 | 実装済み判定 | 0.81 | 0.95 |
| [CIBA-147 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 401 invalid_client | 3.62 | 実装済み判定 | 0.69 | 0.94 |
| [CIBA-148 §13](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13) | 403 access_denied | 1.29 | 導入アプリ責務 | 0.00 | 0.22 |
| [CIBA-149 §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | login_hint_token署名 | 0.06 | 任意・対象外 | 0.95 | 0.92 |
| [CIBA-150 §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | 通知URLの管理権限 | 0.08 | 任意・対象外 | 0.93 | 0.86 |
| [CIBA-151 §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | 期限切れid_token_hint許容 | 0.16 | 任意・対象外 | 0.87 | 0.89 |
| [CIBA-152 §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | id_token_hintのissuerとaudience | 0.27 | 任意・対象外 | 0.78 | 0.79 |
| [CIBA-153 §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | id_token_hint署名 | 0.15 | 任意・対象外 | 0.88 | 0.90 |
| [CIBA-154 §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | push Endpoint保護 | 0.18 | 任意・対象外 | 0.85 | 0.88 |
| [CIBA-155 §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14) | 業務コンテキストの追加 | 0.64 | その他 | 0.47 | 0.37 |
| [CIBA-156 §15](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | プライバシー配慮識別子 | 0.77 | 任意・対象外 | 0.36 | 0.42 |
| [CIBA-157 §15](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | pairwise ID Token hint | 0.26 | 任意・対象外 | 0.78 | 0.77 |
| [CIBA-158 §15](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | 一回限り識別子hint token | 0.45 | 任意・対象外 | 0.62 | 0.75 |
| [CIBA-159 §15](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.15) | Discovery Service hint token | 0.67 | 任意・対象外 | 0.44 | 0.64 |

## 記録と再現性

- [評価単位と参照先](catalog.json) / [機械可読の全結果・全分布](results.json)
- [コード・文書の入力スナップショット](evidence-snapshot.json) / [SHA256 manifest](evidence-manifest.json)
- [絞り込み再評価の入力](focused-request.json) / [回答](focused-response.json)

- Batch 1: [入力](batch-1-request.json) / [回答](batch-1-response.json)
- Batch 2: [入力](batch-2-request.json) / [回答](batch-2-response.json)
- Batch 3: [入力](batch-3-request.json) / [回答](batch-3-response.json)
- Batch 4: [入力](batch-4-request.json) / [回答](batch-4-response.json)
- Batch 5: [入力](batch-5-request.json) / [回答](batch-5-response.json)
- Batch 6: [入力](batch-6-request.json) / [回答](batch-6-response.json)
- Batch 7: [入力](batch-7-request.json) / [回答](batch-7-response.json)
- Batch 8: [入力](batch-8-request.json) / [回答](batch-8-response.json)
- Batch 9: [入力](batch-9-request.json) / [回答](batch-9-response.json)
- Batch 10: [入力](batch-10-request.json) / [回答](batch-10-response.json)

参考: [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)、[TypeSafe Score](https://docs.typesafe.ai/primitives/score)、[Confidence](https://docs.typesafe.ai/confidence)。
