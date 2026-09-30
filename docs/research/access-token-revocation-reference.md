# Access-token revocation reference boundary

2026-09-30。`oidc-provider 9.12.2`、Node24.21.0、固定 image の実 HTTP OP で確認。
テストは `test/reference/full-op/lifecycle.mjs`、[ログ](../validation/node-refresh-reference.txt)。

## 実測した既定動作

| 提示する token | 関連 access/refresh token | 保存 Grant | 旧 CIBA 要求 |
|---|---|---|---|
| opaque access token | 無効化 | 保持 | 無効化 |
| refresh token | 無効化 | 削除 | 無効化 |
| structured JWT | `unsupported_token_type` で拒否 | 保持 | 変更しない |

opaque AT は `token_type_hint` 省略、access_token、refresh_token、未知値のいずれでも検索される。
別 confidential client の live token 取消しは400 invalid_request、正当な client の成功は空bodyの200。
取消し後の再送は別 client でも200となる。兄弟ATの introspection は active=false、元のrefreshは invalid_grant。

旧 CIBA 要求の再引換えは invalid_grant だが、保持した Grant を取り消さない。
アプリが別の新しい CIBA 要求を作り、その Grant を backchannelResult に明示的に渡すと新しい発行が可能。
保持 Grant が自動的に新要求を承認するわけではない。

根拠コードは `lib/actions/revocation.js`、`lib/helpers/revoke.js`、
`lib/helpers/defaults.js#revokeGrantPolicy`。最後の policy が AccessToken による revocation の場合だけ false を返す。
単に revoke helper の呼出しを見て「Grant 自体も常に失効する」と推測した前の説明は誤りだった。

## gem の残件

gem の `revoke_ciba_grant` は保存承認の revoked_at を設定するため、AT取消しにそのまま流用すると参照の既定動作と異なる。
最初の namespace 専用 revocation 接続は refresh token のみだった。現在は下記の opaque AT 接続まで実装した。

実装では、保存承認を残したまま、その時点の関連 token と要求を無効化する処理が必要。
refresh を残して AT だけ取り消す実装では次の更新で再発行できてしまい、旧 CIBA 要求を残すと再引換えが保持 Grant を取り消してしまう。
同時更新・取消し・新しい完了の扱いと DB ロック順序を合わせて検証する。
調査時点では refresh source/request を先にロックしてから Grant をロックしていたため、取消しで逆順にまとめて削除する変更は deadlock の危険があった。

JWT の識別だけで既存の他 OAuth token の挙動まで変えない境界も必要。
今回確認した structured JWT は参照 OP が実発行した resource JWT であり、gem 側で未検証 JWT を信用して承認を取り消してよい根拠ではない。

## ロック順序の前提整備

Grant を識別する非locking read の後、Grant、source の順にロックし、source を再読込するよう変更した。
対象は CIBA token 取得、refresh 更新、refresh-token revocation。保存 Grant を指定した completion も Grant を先にロックする。
completion 内で新規作成する Grant は同じ transaction の未公開行なので、他の処理が先にその Grant を取得する経路はない。

pending 要求が最初の read と source lock の間に Grant に結び付いた場合、逆順の追加ロックは取らず、serialization retry と同じ503 temporarily_unavailableへ進む。
scope・account/client・承認状態などの既存検証は locking read 後にも実行する。

PostgreSQL/MySQL の別接続で Grant を保持し、refresh が Grant lock に進む直前で待機させても、その接続が refresh source をロックできることを確認した。
これは旧順序の「refresh が source を保持したまま Grant を待つ」競合を対象とする試験で、任意のアプリ hook まで deadlock が起きないという保証ではない。
SQLite は writer を先に直列化するため、その行ロック専用試験だけ skip。

3 DBの全suiteは各201 tests、failure/errorなし。PostgreSQL/MySQLは1899 assertions・skipなし、SQLiteは1898 assertions・上記1 skip。
[ログ](../validation/grant-lock-order-matrix.txt)。この段階ではAT取消しの token 識別・関連artifact削除自体はまだ未接続だった。

## Opaque AT 接続

保存済み OAuth token 行の hash（hash保存無効時はtoken列）と type=CIBA で識別する。hint を識別根拠には使わない。
取消し要求も常に client 認証を使い、browser session の権限を使わない。未認証の識別readは経路選択のみで、取消し判断はtransaction内の再読込・client照合後に行う。

Grant→token の順でロックし、有効な token の所有clientを確認してから、そのGrantの旧CIBA要求とrefresh sourceを削除、関連access tokenを論理取消しする。
Grant自体は変更しない。短寿命要求の削除によりping deliveryもFK cascadeで消える。
after_revokeフックが失敗すれば削除と論理取消しは全てrollbackする。

保存している取消し済みopaque行は再送識別に使い、空200を返す。旧形式で行を外部cleanupした後の未知opaque tokenはCIBA由来と識別できず上流経路へ戻る。
新規発行は下記namespaceでこの不足を解消した。他のOAuth flowを一律に変えないため、旧形式までnodeの未知token応答と完全に同じにはしていない。

3 DB全suite各205 tests、failure/errorなし（SQLiteのみ行ロック試験1 skip）。[ログ](../validation/access-revocation-matrix.txt)。
Grantの保持と新要求での明示利用、旧要求再引換えが保持Grantを取り消さないこと、関連refresh・兄弟ATの失効、hint各種、別client、update競合、hook rollbackを確認した。

## 発行形式と拒否の境界

新しいopaque CIBA ATは`ciba_at_`を付け、元のOAuth generatorの乱数を使う。通常OAuth生成は変えない。
unknown/cleanup済みでもこのnamespaceなら、client認証後に空200。namespace自体は所有権や取消し対象の根拠にはせず、保存tokenが存在するときは従来どおりclientと有効性を検証する。

新しいCIBA JWTはclaims機能の有無によらず既存のprivate token_id claimを付ける。resource markerを持つ旧JWTも拒否経路で識別できる。
未検証claimはclient認証と拒否検証への経路選択のみ。OPの設定済み鍵・許可された署名方式・issuer・at+jwt型を検証してからunsupported_token_typeを返す。
期限切れも拒否対象なので、この分類専用verifierでは時刻claimを認可条件にしない。通常のJWT decoderやtoken消費の検証は緩めない。
偽造署名、別issuer、ID Token型、alg=noneはinvalid_requestで拒否し、承認を変更しない。

nodeの「headerがJWTなら署名によらず拒否」とは適用範囲が異なる。関係のないOAuth JWTとmarkerのない旧CIBA JWTを一律変更しない境界として明示する。
新JWTのUserInfoは保存発行行へ結び付くため、行削除後は401。旧marker無しJWTの試験は実際の旧wire formatを署名して再現し、別発行の明示claimを借用しない既存動作を確認した。
