# rodauth-oauth の既存機能との接続

2026-09-28、公式作者ミラーの commit `cac77ec075b41672010126cd6961baf20afccdd7` をコードから調査。実行検証は未実施。以下の対応範囲はまだ採用決定ではない。

## Refresh token

[OIDC の generate_token](https://github.com/HoneyryderChuck/rodauth-oauth/blob/cac77ec075b41672010126cd6961baf20afccdd7/lib/rodauth/features/oidc.rb#L785) は、保存された scope に offline_access が含まれ、生成フラグも有効なら refresh token を生成する。一方、既存の認可要求検証は prompt と response_type に依存するため、CIBA にそのまま流用しない。CIBA での同意と発行条件の検証は別途必要。

## Subject identifier

[既存実装](https://github.com/HoneyryderChuck/rodauth-oauth/blob/cac77ec075b41672010126cd6961baf20afccdd7/lib/rodauth/features/oidc.rb#L387) は public と pairwise を扱うが、pairwise の sector 決定は redirect URI を前提とする経路を含む。CIBA poll では jwks_uri 等に関する追加要件があるため、既存処理を呼ぶだけで対応済みとはしない。初版を public に限定する場合でも、他の OIDC フローの Discovery を不用意に変更しない。

## クライアント登録

[Dynamic Client Registration](https://github.com/HoneyryderChuck/rodauth-oauth/blob/cac77ec075b41672010126cd6961baf20afccdd7/lib/rodauth/features/oauth_dynamic_client_registration.rb) は別 feature であり、既定値に redirect flow の前提がある。CIBA のクライアント metadata と組み合わせ検証の追加が必要になる。

既存の oauth_applications に事前登録したクライアントは DCR を通さず実行時に利用できる。静的登録を選ぶ場合も、CIBA grant、poll モード、クライアント認証などの適格性検証は省略しない。
