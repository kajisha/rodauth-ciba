# node-oidc-providerへの設計・実装の整合化

- 管理PUTと暗号化発行/refreshの重なりを実測。参照OPは途中で更新がcommitしても処理中は旧client snapshot、次回refreshから新鍵を利用。gemも同じ境界で復号・署名・grant数/状態を検証し、Ruby3.4の3 DB各4 tests /46 assertions成功。SQLiteはwriter直列化のため旧/新いずれかの一貫した発行を許し、次回は新鍵を要求。初回の遅すぎる停止点は管理更新を待たせたため、client取得後・消費前へ修正。runtime変更不要。[比較](research/ecdh-encryption-reference-contract.md#management-update-overlapping-issuance)、[DB](validation/encryption-overlap-matrix.txt)。

- 宛先鍵cacheの実TTLを計測。Cache-Control max-age=2で、gemは3秒後にEC/X25519新鍵を取得。参照OPは3秒後も旧鍵を保持し、63,123ms後に取得更新（cache/clockの書換えなし）。Ruby3.4の3 DB各2 tests /64 assertions成功。実期限経過の未検証項目を測定済みに変更し、参照の最低60秒との方針差として記録。runtime cache方針は変更していない。[実測](research/ecdh-encryption-reference-contract.md#actual-cache-expiry-without-mutation)、[参照](validation/node-recipient-real-ttl.txt)、[DB](validation/recipient-real-ttl-matrix.txt)。

- 複数宛先鍵の選択順を修正。参照OPはalg/use一致を優先し同順位は登録順、不正な優先鍵から別鍵へfallbackしない。gemの事前除外を選択後検証へ変更し、RSA最小鍵長/EC点/X25519 agreementの拒否は維持。Ruby3.4の3 DB各7 tests /3,010 assertions、配布gem全smoke/HTTPS検証成功。[比較](research/ecdh-encryption-reference-contract.md#multiple-recipients-and-invalid-preferred-keys)、[DB](validation/recipient-selection-matrix.txt)、[配布](validation/recipient-selection-installed.txt)。

- 暗号化宛先の候補なしを400 invalid_client_metadataへ整合化。初回/refreshの状態はrollbackを維持。RSA key_opsは参照の二段検証も反映し、encrypt+wrapKey併記なら成功、encryptのみは500、wrapKeyのみは400。最終修正はRuby3.4の3 DB各4 tests /112 assertions成功。先行する400応答変更は関連30 tests /4,459 assertions各DBと全371 tests /9,389 assertionsで成功（全体は最後のRSA guard前、SQLite2 skip）。複数鍵fallback・cache方針は残件。[参照](validation/node-recipient-metadata-errors.txt)、[最終DB](validation/recipient-error-final-matrix.txt)、[境界](research/ecdh-encryption-reference-contract.md#recipient-errors-and-rsa-operation-declarations)。

- ECDH公開鍵のkey_ops差を再現・修正。参照は省略/空配列なら発行でき、非空deriveBits/sign/encryptでは公開鍵importが500になる。gemが宣言を無視して発行していたため、選択後に検証してrollbackするよう変更。Ruby3.4の3 DB各12 tests /2,626 assertions、全370 tests /9,350 assertions成功（SQLite2 skip）。use/alg不適合時の参照400とgem500、および複数鍵優先/fallbackは別残件。[比較](research/ecdh-encryption-reference-contract.md#recipient-key-metadata)、[red](validation/ecdh-key-ops-red.txt)、[DB](validation/ecdh-key-ops-matrix.txt)、[全体](validation/ecdh-key-ops-full.txt)。

- ECDHのremote鍵/管理更新を検証。P-256/X25519×opaque/JWTで実HTTPのcache保持・明示失効後更新・503/不正JSONの繰返し拒否・rollback/recoveryを確認。管理APIの拒否時保持・宛先更新・enc既定値/解除も成功。Ruby3.4の3 DB各10 tests /296 assertions、配布gemの実HTTPS/非信頼TLS拒否も成功。runtime変更不要。Docker build cache破損は既存3.4イメージへのソースmountで回避し、全体cacheは削除していない。実TTL・競合更新・cache失敗方針の差は残件。[詳細](research/ecdh-encryption-reference-contract.md#gem-remote-retrieval-and-management)、[DB](validation/ecdh-remote-management-matrix.txt)、[HTTPS](validation/ecdh-remote-installed.txt)。

- ECDHの配布/Ruby下限検証を完了。配布gem32構成で初回/refreshの復号・内部署名検証、Ruby3.3/3.4各361 tests /9,074 assertions成功（SQLite2 skip）。参照OPはP-256直接合意/X25519+KWでremote鍵更新・障害・管理変更を確認。503後の旧鍵再利用はRSA同様で、gemのcache方針との差は未解消。gem側ECDH remote鍵/管理は次の残件。[配布](validation/ecdh-installed.txt)、[Ruby](validation/ecdh-rubies.txt)、[比較](research/ecdh-encryption-reference-contract.md)。

- ECDHの初期実装を追加。4曲線×4鍵方式×6本文方式で発行/refreshを検証し、joseで192トークンを独立復号・内部署名検証。別受信者鍵/epk改変を拒否。不正点・曲線不一致・zero X25519等は発行をrollback。DCR/Discoveryも実発行で確認。3 DB各20 tests /4,144 assertions、全361 tests /9,074 assertions成功（SQLite2 skip）。配布/Ruby下限、remote鍵/管理は残件。[比較・境界](research/ecdh-encryption-reference-contract.md)、[DB](validation/ecdh-matrix.txt)、[独立検証](validation/ecdh-jose.txt)。

- GCMKWの配布/Ruby下限検証を完了。配布gemで共通鍵28構成、Ruby3.3/3.4各358 tests /6,724 assertions成功（SQLite2 skip）。参照OPのECDHは4曲線×4鍵方式×6本文方式の96構成で発行/refresh・復号・内部署名を実測。gemのECDHは未実装として維持。[配布](validation/gcmkw-installed.txt)、[Ruby](validation/gcmkw-rubies.txt)、[ECDH比較](research/ecdh-encryption-reference-contract.md)。

- AES-GCMKWの初期対応を追加。OpenSSLでCEKをラップし、本文暗号化とcompact形式は既存JWE backendを利用。DCR/発行/refreshを含む共通鍵42構成、joseによる84トークンの復号・内部署名・改変拒否を確認。3 DB各17 tests /1,794 assertions、全358 tests /6,724 assertions成功（SQLite2 skip）。新adapterの配布/Ruby下限検証とECDHは残件。[契約](id-token-encryption.md#aes-gcm-key-wrapping)、[DB](validation/gcmkw-matrix.txt)、[全体](validation/gcmkw-full.txt)、[独立検証](validation/gcmkw-jose.txt)。

- 共通鍵ID Token生成時の不要なJWKS取得を修正。参照OPは503 URIでも取得せず成功するが、gemは500になる差を再現。生成中だけ宛先lookupを省き、private_key_jwtは実取得・誤鍵拒否を維持。3 DB各21 tests /1,505 assertions、配布gem16構成と既存TLS検証が成功。[再現](validation/symmetric-jwks-red.txt)、[参照](validation/node-symmetric-jwks.txt)、[DB](validation/symmetric-jwks-matrix.txt)、[配布](validation/symmetric-encryption-installed.txt)。Ruby3.3/3.4各358 tests /6,274 assertions成功（SQLite2 skip）。[Ruby](validation/symmetric-encryption-rubies.txt)。

- 共通鍵暗号化の初期対応を追加。参照OPでdir/AES-KW/AES-GCMKW×6 content方式の42構成を実測。gemはdir/AES-KWの24構成を実装し、hash保存DCR・発行/refresh・鍵欠落rollbackを検証。3 DB各10 tests /1,211 assertions成功、joseで48個の実発行Tokenの復号・内部署名・誤鍵拒否を確認。GCMKW/ECDH、配布/Ruby下限、不要なremote JWKS取得の確認は残件。[契約と証拠](id-token-encryption.md#client-secret-derived-encryption)。

- HMAC署名の配布・Ruby下限検証を完了。Ruby3.3/3.4各354 tests /5,847 assertions成功（SQLite2 skip）。DCR生成secretがHS384/512には短い問題を修正し、関連3 DB各10 tests /439 assertions成功。配布gemの12構成で発行・refresh・hint・backend secret置換を確認。CIBA-153を署名検証の境界についてverifiedへ更新（101 verified /7 partial）。全体の整合化完了ではない。[Ruby](validation/hmac-id-token-rubies.txt)、[配布](validation/hmac-id-token-installed.txt)、[DB](validation/hmac-registration-secret-matrix.txt)。

- CIBA HMAC ID Tokenの鍵所有者を初期修正。署名/hint検証をclient secretへ合わせ、認証済みBasic/POST値をrequest内で再利用し、hash保存と両立。別方式は元secret取得フックを利用でき、欠落/短い鍵でOP鍵へfallbackしない。3 DB各9 tests /421 assertions、全353 tests /5,829 assertions成功（SQLite2 skip）。Node joseも24個の実発行/refresh Tokenを検証しOP鍵を拒否。非CIBA/JWT ATの鍵選択は維持。配布/Ruby下限・追加登録/rotation検証が残り153はpartial維持。[契約](id-token-hint.md#hmac-client-secret-ownership)、[独立検証](validation/hmac-id-token-jose.txt)。

- 現行実装の全体基準を更新。3 DB全351 tests成功（SQLite5,637 assertions/2 skip、PostgreSQL/MySQL5,634 assertions/skipなし）、Ruby3.3/3.4各351 tests/5,637 assertions成功、全参照fixtureと配布gemも成功。監査159項目の全test_refsの存在を確認し、153の古いEdwards/暗号化未実装記述を訂正。153はHMAC鍵所有者の差が残るためpartialを維持し、件数による完了扱いはしていない。[DB](validation/alignment-current-databases.txt)、[Ruby](validation/alignment-current-rubies.txt)、[参照](validation/alignment-current-reference.txt)、[配布](validation/alignment-current-package.txt)。

- 暗号化設定の既定値復帰・解除を参照と比較。enc省略時のCBC既定値、両項目削除後の既存refreshによる署名のみ発行、管理token rotationを確認。無効capabilityでも設定を保存していた問題は、参照が登録拒否せず項目を無視する実測に基づき、保存・返却しない実装へ修正（当初の拒否案から変更）。3 DB各4 tests /81 assertions、Ruby4.0.6全351 tests /5,637 assertions成功（SQLite行ロック2 skip）。[境界](id-token-encryption.md#defaults-removal-and-disabled-registration)、[DB](validation/id-token-encryption-config-matrix.txt)、[全体](validation/id-token-encryption-config-full.txt)。cache失敗後の方針はユーザー確認中で、今回変更していない。

- 暗号化recipientの参照remote-cache/管理APIを実測。cache保持と強制失効後の鍵更新、管理更新の拒否時旧鍵保持・成功時refresh宛先変更は確認できた。gemの管理/取得失敗テストは3 DB各4 tests /98 assertions成功。参照は503失敗後に旧鍵をfresh扱いして次回発行できるが、gemは失敗を成功cacheへ格納しない。また参照は最低60秒を設ける。これらは未解消の差として明記し、同等性や承認済みadaptationとは扱わない。[比較](id-token-encryption.md#reference-remote-cache-and-management-comparison)、[参照](validation/node-encryption-remote.txt)、[DB](validation/id-token-encryption-management-matrix.txt)。

- 暗号化宛先のHTTPS検証で接続先制限の迂回を再現し修正。CIBA発行/refresh中の鍵取得にも安全なHTTP経路を適用し、取得失敗時のhaltを例外へ変えて消費をrollbackする。配布gemで既定loopback拒否・非信頼TLS拒否・資格情報非転送・cache保持/明示失効後の鍵更新・503/不正JSONからの復旧をopaque/JWTで確認。redirect/過大応答も含む3 DB各7 tests /802 assertions成功。[red](validation/id-token-encryption-https-red.txt)、[配布](validation/id-token-encryption-https-installed.txt)、[DB](validation/id-token-encryption-remote-matrix.txt)。実TTLや参照OPの暗号化専用remote-cache比較は未検証。

- 暗号化宛先鍵の選択順を修正。登録順の先頭を選ぶ挙動をredで確認し、参照実装と同じalg/use一致の優先順位へ変更した。参照の実発行でも一致を確認。最終3 DB各10 tests /1,047 assertions、Ruby3.3/3.4各346 tests /5,510 assertions成功（SQLite行ロック2 skip）。配布gemからRSA/Edwards×opaque/JWTの暗号化発行・refresh・復号・署名検証も成功。[鍵選択](validation/id-token-recipient-priority-matrix.txt)、[Ruby](validation/id-token-encryption-rubies.txt)、[配布](validation/id-token-encryption-installed.txt)。HTTPS宛先鍵更新・管理等は引き続き未検証。

- 暗号化ID Tokenの初期実装を追加。任意設定で登録済みRSA宛先鍵へ署名後暗号化し、DCR既定enc・Discovery・鍵用途/サイズ検証を接続。RSA/Edwards署名×RSA暗号化2種×本文暗号化6種の36組合せについて、初回発行/refreshをNode joseで独立復号・内側署名検証・改ざん拒否確認。3 DB各9 tests /1,043 assertions、Ruby4.0.6全345 tests /5,506 assertions成功（SQLite行ロック2 skip）。暗号処理はjwe 1.1.1を利用。対称/ECDH、遠隔鍵更新・管理・配布・Ruby下限の追加検証は残る。[対応範囲](id-token-encryption.md)。

- 暗号化ID Tokenの参照成功経路を実測。RS256/Ed25519/EdDSAのCIBA発行・refreshでRSA-OAEP-256/A256GCMを復号し内側の署名を検証した。一方、gemのRSA経路では暗号化指定が無視される問題を再現し、CIBA ID Token限定の平文返却防止・rollbackを追加。3 DB各7 tests /350 assertions成功。暗号化発行そのものは未実装であり、hint入力の暗号化拒否とは別の残件。[契約・証拠](research/id-token-hint-reference-contract.md#encrypted-output-measured-gap-and-plaintext-fallback-correction)。

- Edwards ID Tokenの追加検証: 配布gemの両署名名×opaque/JWTをNode joseで独立検証し、署名・public JWKS thumbprint・at_hash・改ざん拒否を確認。refreshではpublic/pairwiseのsubject、認証情報、鍵更新、UserInfo、rotation/replay、署名失敗rollbackを確認（3 DB各5 tests /311 assertions）。Ruby3.3/3.4は全341 tests /4,774 assertions成功、SQLite行ロック2 skip。暗号化発行と参照実装との全組合せ比較は未完了。[契約・証拠](research/id-token-hint-reference-contract.md#edwards-refresh-and-pairwise-integration)、[Ruby](validation/edwards-id-token-rubies.txt)。

- Edwards ID Tokenの初期adapterを追加。独立した任意key mapで署名・public OKP JWKS・DCR/Discovery・hint検証/旧鍵保持を接続。関連3 DB各14 tests /549 assertionsと最終3 tests /79 assertions成功。暗号化指定は平文へのfallbackをせず発行rollback。独立相互検証・配布・Ruby/refresh/pairwiseは残る。[契約](id-token-hint.md#explicit-edwards-id-token-keys)、[DB](validation/edwards-id-token-matrix.txt)、[最終](validation/edwards-id-token-final-matrix.txt)。

- ID Token hint の実発行・署名/issuer/audience検証・現在/期限切れ再利用・誤鍵拒否をRS/PS/ES/HS全12アルゴリズムへ拡張。3 DB各7 tests /229 assertions成功。参照実HTTPはEd25519/EdDSAも含む14種で成功し、Edwards ID Token発行/JWKS/hintは残件として具体化。[DB](validation/id-hint-algorithms-matrix.txt)、[参照](validation/node-id-hint-algorithms.txt)。

- 監査の古い判定を再確認。pairwiseの対応2方式と署名要求の11アルゴリズムは現行ソース・負例・独立vector・参照証拠により017/066を検証済みに更新。3 DBの関連31 tests成功（SQLite639、他637 assertions）。093の30秒応答は保証済みとせず、元のgem+deployment責務に従いapp_contractへ分類。[検証](validation/pairwise-signature-audit-current.txt)、[運用責務](operations.md#poll-response-time-deployment-contract)。

- 署名付き要求のjtiを参照実装へ整合化。空文字は受理しnull/非文字列は拒否、同一要求を再送しても以前の承認を引き継がない。client assertionの非空jti/replay防止は維持。3 DB各15 tests /290 assertions成功。[参照](validation/node-signed-jti.txt)、[DB](validation/signed-jti-matrix.txt)。

- OAuth/OIDCの認証方式メタデータから旧assertion-type URNを除去。実際の方式リスト・上流認証dispatch・非CIBAクライアントは維持。参照Discoveryと3 DB各4 tests /162 assertionsで確認し、CIBA-007を検証済み境界に更新。[red](validation/client-auth-metadata-urn-red.txt)、[DB](validation/client-auth-metadata-urn-matrix.txt)、[参照](validation/node-client-auth-metadata-urn.txt)。

- 配布gemで両Edwards名×opaque/JWTの実HTTPS client JWKS認証を確認。既定loopback拒否、非信頼TLS拒否、GETへの資格情報非転送、署名検証済みID Token発行が成功。CIBA設定をEdwards限定にしても無関係なRSA code clientは認証成功（3 DB各5 tests /114 assertions）。CIBA-014/025/064を検証済み境界へ更新し、007の旧URN広告差は残す。[配布](validation/client-auth-edwards-https-installed.txt)、[設定範囲](validation/client-auth-edwards-scope-matrix.txt)。

- Edwards 認証の追加検証:リモートHTTP JWKS・明示cache失効による鍵更新・503/不正JSON・通常code grantを3 DB各5 tests /247 assertionsで確認。nodeでも両Edwards名の実HTTP遠隔鍵認証が成功。Ruby3.3/3.4は全334 tests /4,316 assertions成功（SQLite行ロック2 skip）。配布gemで両endpoint認証・replay拒否・opaque/JWT・ID Token検証を確認。[DB](validation/client-auth-edwards-remote-matrix.txt)、[参照](validation/node-client-auth-edwards-remote.txt)、[Ruby](validation/client-auth-edwards-rubies.txt)、[配布](validation/client-auth-edwards-installed.txt)。

- Edwards client assertion の初期実装。独立した `ciba_client_assertion_signing_algorithms` 設定、DCR/Discovery、client OKP鍵の検証を接続し、既存issuer/audience/期限/replay検証を維持。3 DB各7 tests /231 assertions成功。リモート鍵、配布、Ruby matrix等は残る。[実装境界](research/client-assertion-algorithm-contract.md#initial-edwards-authentication-implementation)、[検証](validation/client-auth-edwards-matrix.txt)。

- Edwards client assertion の未対応を再現。node の14-algorithm試験はEd25519/EdDSAも両endpointで認証成功・別鍵拒否。gemの明示probeは正しいclient鍵でも両方401。署名要求用Edwards実装とは別の、JWT/JWK認証検証とmetadata設定の不足として追跡。[参照](validation/node-client-auth-edwards.txt)、[red](validation/client-auth-edwards-red.txt)、[次の実装境界](research/client-assertion-algorithm-contract.md#confirmed-edwards-client-authentication-gap)。

- 最新の統合検証:3 DB全331 tests成功（SQLite4,217 assertions・行ロック2 skip、PostgreSQL/MySQL4,214 assertions・skipなし）。Ruby3.3/3.4 SQLiteも各331 tests /4,217 assertions成功、同2 skip。配布gemの全smokeも成功。JWT grantパラメータで認証を迂回しない既存testの旧401期待を新しい400へ更新した。[DB](validation/alignment-consolidated-databases.txt)、[Ruby](validation/alignment-consolidated-rubies.txt)、[配布](validation/alignment-consolidated-package.txt)。これは全体の設計差が解消したという判定ではない。

- CIBA の識別情報欠落を400 invalid_requestに整合化。誤った Basic は401とchallengeを維持し、通常 OAuth の経路を変更しない。参照実 HTTP と3 DB各24 tests /535 assertionsで確認。[比較](research/error-response-reference-contract.md#missing-identity-versus-failed-authentication)。

- 署名付き要求の exp/iat/nbf を有限 numeric 値へ整合化。小数を受理し未来 iat 単独では拒否せず、期限切れ exp・未来 nbf は引き続き拒否。node 実 HTTP と3 DBの署名回帰試験で確認。[契約](signed-requests.md#numericdate-alignment)、[実行](validation/signed-numericdate-matrix.txt)。

- ping 通知先の参照を node に整合化。要求受付時の endpoint 固定を外し、送信開始時の現在の client 登録値を使用する。管理 PUT 後の再送は新 endpoint へ同じ通知 credential を送り、mode の poll 変更は引き続き拒否する。前項までに記録した未解消差を修正。[red](validation/ping-current-endpoint-red.txt)、[DB 検証](validation/ping-current-endpoint-matrix.txt)。

- ping 管理 API の競合を参照実 OP と実 TLS で測定。通知先変更後の fresh Client による再送は node では保存済み credential を新 endpoint へ送るが、gem は Ineligible で拒否する。mode の poll 変更後の再送拒否、進行中送信の元 endpoint 保持、token の一度だけの取得は一致。これは未検証ではなく未解消の方針差として維持。[測定](validation/node-ping-management.txt)、[比較](research/ping-reference-contract.md#reference-http-management-race)。

- assertion-type URNをCIBA認証方式として登録できてしまう不具合を再現・修正。参照版同様にCIBA eligibilityで拒否し、共通Discovery・通常OAuthは維持。正規JWT方式と既存OAuthを含め3 DB各4 tests /157 assertions成功。[比較契約](research/client-assertion-algorithm-contract.md#legacy-assertion-type-urn-is-not-a-registered-authentication-method)。

- configured12種類のJWT client assertion（RS/PS/ES/HS）を参照版・gemの両endpointで比較。別鍵拒否とgemの承認後発行を確認、3 DB各1 test /137 assertions成功。CIBA-008を更新しpartial19件。legacy認証方式URNとEdwards client assertionは未確認として保持。[比較契約](research/client-assertion-algorithm-contract.md)。

- pingの200/204応答bodyを読まずに接続を閉じる修正で、サイズ制限による誤失敗を解消。未送信bodyの実TCP試験と、参照／配布gemの140KB実TLS応答が成功。JWKS/sectorのbody制限を維持。CIBA-109を更新しpartial20件。[比較](research/ping-reference-contract.md#ignored-response-body-parity)、[配布](validation/ping-response-body-installed.txt)。

- Node/jose固定Edwards署名をgemへ直接入力。inline／HTTP remote JWKSと改ざん拒否を3 DB各4 tests / 108 assertionsで確認。配布gemでもEd25519／EdDSA × opaque/JWT全4構成で検証済みID Token発行成功。CIBA-050の部分判定を更新、partialは21件。[署名契約](signed-requests.md)、[配布](validation/edwards-installed.txt)。

- Ed25519／EdDSA署名付きCIBA要求を実装。OpenSSLによる局所的なOKP鍵読み込み・署名検証、登録とDiscovery、別鍵・不正curve・用途・alg拒否を追加。3 DB各11 tests / 234 assertions成功、Ruby3.3／3.4全体各324 tests / 3977 assertions成功（SQLite行ロック2 skip）。固定相互運用vector・remote Edwards鍵・配布gem実行は残る。[署名契約](signed-requests.md)、[Ruby](validation/edwards-rubies.txt)、[DB](validation/edwards-request-matrix.txt)。

- partial22項目を差分・検証不足・共通制約へ整理。Ed25519／EdDSA署名付き要求を参照OPで実測し、両方の成功／別鍵拒否を確認。gemでは未実装の具体的差分として保持。[整理](research/alignment-partial-triage.md)、[参照試験](validation/node-signed-edwards.txt)。

- 残り16項目を分類し、159 IDすべてに現判定を付与。未分類0は合格159ではなく、partial・アプリ責務・Client責務・参照非対応を区別する。明示403の事前拒否と混雑応答等13 tests / 116 assertions成功。[監査](requirements-audit-current.md)。

- 通信・認証11項目を再監査、143件再確認／16件未再確認へ更新。両endpointの非TLS・JSON・GET拒否と無変更を追加。JWT audience受理等を含め15 tests / 123 assertions成功。[監査](requirements-audit-current.md)。

- 開始要求20項目を再監査、132件再確認／27件未再確認へ更新。非email hintと未知入力による状態上書き防止、ACR順序と達成値の区別を追加。13 tests / 240 assertions成功。[監査](requirements-audit-current.md)。

- エラー応答15項目を再監査、112件再確認／47件未再確認へ更新。早期認証失敗のCache-Control欠落をCIBA HTTP境界で修正。3 DB各30 tests / 590 assertions成功。[比較](research/error-response-reference-contract.md)。

- push関連18項目を分類し、97件再確認／62件未再確認へ更新。参照版のpush設定拒否を実行確認。gemはpush clientによる既存要求の引換えも拒否、5 tests / 55 assertions成功。条件付き非対応は合格件数に含めない。[比較](research/push-reference-boundary.md)。

- Discoveryと登録9項目を再監査、79件再確認／80件未再確認へ更新。独自開始URLの実利用と不正配送モード拒否を追加。9 tests / 93 assertions成功。認証方式・アルゴリズム全組合せはpartialとして残す。[監査](requirements-audit-current.md)。

- 受付応答の時刻起点を参照OPと実測比較。hint解決後に寿命が始まり、同期dispatch時間をexpires_inから差し引かない挙動が一致。dispatchが寿命を超えると受付直後のpollが期限切れになる共通制約をAPI契約へ記録。実装変更なし。[比較](research/acknowledgement-time-contract.md)。

- 受付応答10項目を再監査し、70件再確認／89件未再確認へ更新。数値型・設定上限を追加検証し5 tests / 74 assertions成功。expires_inの時刻起点は検証後であり、要求受信からの経過時間を含めた保証はpartialとして残す。[監査](requirements-audit-current.md)。

- Token交換の7要件を再監査し、60件再確認／99件未再確認へ更新。成功応答の型・cache headersと未承認時のtoken非包含を追加検証。3 DB各8 tests / 129 assertions成功。[監査](requirements-audit-current.md)、[証跡](validation/token-exchange-audit-current.txt)。

- 長いpairwise JWTのintrospectionをセキュリティ再検証。不正署名・署名なし・subject/発行ID変更の無効化、呼び出し元証明書認証、8192-byte上限とパラメーター限定を回帰へ追加。実装変更なし、3 tests / 45 assertions成功。[証跡](validation/pairwise-mtls-introspection-security.txt)。

- 署名付き要求＋Basic認証のpairwise登録は参照版も拒否することを、Node 24上の実HTTP登録とgem回帰で確認。以前の「未実装差分」という分類を訂正し、実装の制限を維持した。[比較契約](research/pairwise-reference-contract.md#signed-requests-do-not-replace-pairwise-client-authentication)。

- pairwise＋自己署名mTLSを実装。remote x5c認証を所有証明として許可し、DCR・実TLS・証明書更新・refreshを配布gemで確認。JWT introspectionのpairwise subject lookupと1024-byte制限も修正。監査は53件再確認／106件未再確認、署名要求だけの所有証明は未対応。[契約](research/mtls-reference-contract.md#pairwise-self-signed-tls-client-authentication)、[配布](validation/pairwise-mtls-package-final.txt)、[最終DB](validation/pairwise-mtls-final.txt)。

- ping監査16項目を追加し、50件再確認／109件未再確認へ更新。Bearer構文・1024文字境界・CRLF拒否を追加検証。Clientのentropy／通知検証、アプリのendpoint管理権限確認をgem単体の合格と混同しない。response body上限と配送の非exactly-once性は維持。[監査](requirements-audit-current.md)、[試験](validation/ping-audit-current.txt)。

- hint関連の監査11項目を追加し、34件再確認／125件未再確認へ更新。expired_login_hint_tokenと検証障害を無保存・未dispatchまで確認し、pairwise hintでも新規承認が必要な境界を再確認。任意の署名hint形式・単回参照・discovery-service暗号化はアプリ責務／未実装として保持。[監査](requirements-audit-current.md)、[hint](validation/hint-audit-current.txt)、[pairwise](validation/pairwise-hint-audit.txt)。

- 署名付き要求の監査14項目を追加し、現行監査は23件再確認／136件未再確認へ更新。RS/PS/ESの9アルゴリズムをgem・参照OPで受理／誤署名拒否まで実測。時刻claimの型拒否も追加し、局所試験 **6 tests /128 assertions** 成功。jti再送・外側パラメータはClient責務とOP挙動を区別し、参照のEd25519/EdDSAとの差は未完了として残す。[監査](requirements-audit-current.md)、[gem](validation/signed-request-audit-current.txt)、[参照](validation/node-signed-algorithms.txt)。

- 現行構成の[要件再監査](requirements-audit-current.md)を開始。元の159 IDを保持し、user_code関連9件をプロトコル境界・未解消条件・アプリ／Client責務に再分類、150件を未再確認として列挙した。client metadata省略時の回帰を追加し、パスワードとの分離・変更手段を導入契約へ明記。任意機能を含む全要件の完了は未証明。

- 対応下限を含む Ruby3.3.12／3.4.11 の全体回帰を更新。SQLite で各 **306 tests / 3,561 assertions**、失敗・error なし、行ロック2件 skip。[実行ログ](validation/mtls-alignment-rubies.txt)。README／protocol coverage の古い未対応記述を修正し、159項目の初期監査を履歴として明示した。拡張後の規範要件の再監査は別途残る。

- 配布 gem の HTTPS JWKS 証明書更新を opaque／JWT で検証。新証明書による refresh、新旧 token の証明書分離、503中の無保存と復旧が成功。この検証で見つかった JWT introspection の `cnf` 欠落を修正し、live grant・client・subject・binding を照合する。3 DB 各 **14 tests / 307 assertions** 成功。[契約](research/mtls-reference-contract.md#installed-https-certificate-rotation-and-jwt-introspection)、[配布](validation/mtls-remote-installed-final.txt)、[DB](validation/mtls-jwt-introspection-matrix.txt)。実 TTL・複数 process は未検証。

- remote x5c の証明書更新を参照 OP と比較。キャッシュ有効中の旧証明書保持・期限切れ後の同一鍵別証明書への切替を確認。取得失敗を `invalid_client_metadata` に修正し、失敗中の継続拒否・禁止宛先への未接続・復旧を検証。参照版の更新失敗後に旧鍵を再利用する動作は踏襲しない。[契約](research/mtls-reference-contract.md#remote-x5c-rotation-and-retrieval-failures)、[関連3 DB](validation/mtls-remote-matrix.txt)、[最終](validation/mtls-remote-final.txt)、[配布回帰](validation/mtls-remote-package.txt)。配布物での remote rotation 自体は未検証。

- mTLS aliases は参照版でも自動生成されず、アプリの Discovery／TLS 配置で提供する境界と確認。参照 OP と配布 gem で別 TLS ポートの aliases を使う実フローが成功し、canonical issuer と証明書制約を維持。gem の専用ルーターは追加しない。[契約](research/mtls-reference-contract.md#endpoint-aliases-are-application-deployment-configuration)、[配布](validation/mtls-aliases-package.txt)、[参照](validation/node-mtls-aliases.txt)。proxy・path rewrite・remote rotation は未検証。

- mTLS の対応能力と client ごとの binding policy を分離。Discovery は TLS 機能有効時に対応を公開し、CIBA は上流の全体強制設定にかかわらず client metadata で発行を判断する。管理更新後も既発行 binding は維持。3 DB 各 **21 tests / 311 assertions** と配布 gem の実 TLS 4構成が成功。[比較契約](research/mtls-reference-contract.md#capability-versus-client-binding-policy)、[DB](validation/mtls-capability-matrix.txt)、[配布](validation/mtls-capability-package.txt)。

- 配布gemの実TLS検証を動的登録clientへ変更。返されたIDでPKI／自己署名×opaque／JWTの4構成を実行し、CIBA・UserInfo・refresh・管理更新を確認。失敗PUTの設定維持、成功PUTのcredential更新、既発行binding維持と以後の発行policy変更が成功。[配布ログ](validation/mtls-dcr-installed-tls.txt)、[範囲](research/mtls-reference-contract.md#installed-dcr-and-management-over-tls)。

- mTLSのDCR metadataを接続。PKI識別情報一つ・binding真偽値・保存列・自己署名keysを検証し、無効な機能の項目は無視。管理更新時のfalse／省略を保存し、失敗時のrowとcredentialを保持する。自己署名clientを動的登録して発行し、binding無効化後も既発行tokenの証明書要件が残ることを確認。3 DBの関連各 **65 tests** と最終登録ケースが成功。[関連](validation/mtls-registration-matrix.txt)、[最終](validation/mtls-registration-final.txt)、[実TLS参照](validation/node-mtls-registration.txt)。

- 配布gemのmTLSを実Ruby TLSで検証。WEBrickのpeer certificateをcallbackへ渡し、Net::HTTP側もserver証明書／hostnameを検証する。PKI／自己署名×opaque／JWTの4構成でCIBA・binding・UserInfo・refreshを確認し、証明書なし・偽装header・未信頼証明書・同一鍵別証明書の不適切な利用を拒否。[配布ログ](validation/mtls-installed-tls.txt)、[範囲](research/mtls-reference-contract.md#installed-gem-with-a-ruby-tls-server)。DCR・remote rotation・proxy等は残る。

- CIBA mTLS の初期修正を実装。明示的なtrusted certificate callbackを必須にし、PKIのchain／subject判定、自己署名x5c照合、証明書DERのSHA256、opaque／JWT UserInfoの証明書必須、introspection、refreshを接続。二重DPoP binding拒否を永続化前に移して承認消費も防止。3 DB初期全体各 **297 tests**、最終関連各 **30 tests / 541 assertions** 成功。[全体](validation/ciba-mtls-matrix.txt)、[最終](validation/ciba-mtls-final.txt)、[API・残件](research/mtls-reference-contract.md#initial-ciba-correction)。実Ruby TLS／配布artifact・DCR・alias等は未完了。

- mTLS を実証明書の TLS 接続で参照測定。PKI／自己署名方式の CIBA 発行・refresh、証明書全体の SHA256 binding、UserInfo の証明書必須・同一鍵別証明書拒否を確認。Ruby 上流のみでは異なる thumbprint、証明書なし UserInfo 200、自己署名 x5c 認証500を再現した。これは対応完了ではなく修正が必要な差である。[参照](validation/node-mtls-reference.txt)、[Ruby観測](validation/upstream-mtls-probe.txt)、[修正境界](research/mtls-reference-contract.md)。

- `private_key_jwt`／`client_secret_jwt` の issuer audience を CIBA refresh でも受理するよう修正。参照OPは開始・発行・refreshのすべてで受理する一方、gemはrefreshだけ401となる差を再現した。誤audience・assertion再使用を拒否し、通常authorization-codeの条件は維持。3 DB関連各 **59 tests** 成功。[比較](research/refresh-reference-contract.md#jwt-client-assertion-audience)、[DB](validation/assertion-refresh-matrix.txt)。

- OIDC Discovery から欠落していた introspection URL と DPoP 署名アルゴリズムを、実際の OAuth server metadata から引き継ぐよう修正。無効時は非公開、route 名変更や設定したアルゴリズムを保持する。参照版は introspection の認証方式一覧を省略するが、gem は上流の既存一覧も公開する。関連 **43 tests / 686 assertions** と Discovery 経由の配布検証が成功。[統合](validation/discovery-extensions-integration.txt)、[配布](validation/discovery-extensions-package.txt)、[node](validation/node-discovery-extensions.txt)。

- opaque DPoP token が introspection で誤って inactive になる差を再現し修正。CIBA token に限り proof 提示なしで有効性を検索し、保存した `cnf.jkt` と `token_type: DPoP` を返す。client 認証・token/hash 一致・期限・失効は維持し、通常 OAuth の動作を変更しない。resource 向け token の audience/scope も確認。[参照](validation/node-dpop-introspection.txt)、[修正前](validation/dpop-introspection-red.txt)、[配布gem](validation/dpop-introspection-package.txt)。introspection URL の OIDC Discovery 掲載差は残り、現状は OAuth server metadata から取得する。

- POST UserInfo の DPoP method binding／再使用拒否を参照OPで実測。gemではopaque／JWT POST、明示的な平文保存、別名のハッシュ列を追加し、鍵／ath／失効／期限／並行再使用の既存検証も各構成で実行した。3 DBの関連各 **19 tests / 370 assertions** 成功、本体修正は不要。元の保存設定は既にハッシュ保存だったため、未検証範囲の記述を訂正。[DB](validation/dpop-post-storage-matrix.txt)、[node](validation/node-dpop-post.txt)、[境界](research/dpop-reference-contract.md#post-userinfo-and-token-storage)。

- 配布gemのDPoP検証を追加。一時インストールしたコードだけで、動的登録からopaque／JWTのnonce付き発行・署名と鍵binding・UserInfoの正常系と鍵／ath／再使用拒否・新鍵でのrefresh後UserInfoまで検証。CIBA featureとDPoP moduleの読み込み元も検査する。[配布ログ](validation/dpop-installed-package.txt)、[境界](research/dpop-reference-contract.md#installed-artifact-integration)。Ruby4.0.6／SQLite／Rackでの証拠であり、proxy・外部resource server・複数processの保証ではない。

- DPoP server nonce を参照 OP の必須／任意 policy に合わせた。token 400／UserInfo 401 の challenge、有効 nonce による古い iat の受理、endpoint 間の共用と proof 再使用拒否を実測。gem は issuer ごとの共有32-byte secret、期限切れ／rotation、nonce 検証時刻に基づく replay 記録保持を実装。参照が拒否する `iat=0` の差も再現後に修正。修正前の全体各 **281 tests** と、最終 DPoP 各 **15 tests / 267 assertions** が3 DBで成功。[全体](validation/dpop-nonce-matrix.txt)、[最終](validation/dpop-nonce-final.txt)、[node](validation/node-dpop-nonce.txt)、[設定と境界](research/dpop-reference-contract.md#server-nonce-policy-and-replay-retention)。配布artifact・cluster・追加組合せは残る。以下は段階別の履歴。

- `dpop_bound_access_tokens`をCIBA動的登録へ接続。DPoP有効時はJSON booleanを検証し、明示列へ保存、省略時falseと管理応答のfalseを保持する。無効時は未対応metadataとして無視。参照OPも動的登録したclientによる発行／UserInfo／refreshへ変更し、管理PUT失敗時の維持と省略時のfalseを実測。gemでは保存列不足拒否、不正入力の無保存、既発行tokenのbinding保持も確認。3 DBの関連各 **44 tests** 成功。[DB](validation/dpop-registration-matrix.txt)、[node](validation/node-dpop-registration.txt)。nonce・配布artifact・追加組合せは残る。

- CIBA UserInfoのDPoPを実際の`authorization_token`経路へ接続。opaque／JWTともに署名・ath・proof鍵・保存した発行鍵・有効tokenを照合し、再使用を拒否する。upstreamの鍵条件によるORが失効／期限／token一致条件を迂回する問題もCIBA UserInfo限定で修正。通常のCIBA Bearerは保持し、未知token＋既知鍵、改ざんJWT、失効／期限切れ、並行proof再使用を検証。3 DB各 **275 tests** 成功。[DB](validation/ciba-dpop-userinfo-matrix.txt)、[node再使用比較](validation/node-dpop-reference.txt)。nonce、DCR、配布artifact、追加組合せは残る。

- DPoPのCIBA token endpoint境界を実装。ランダムjtiを受理し、署名／公開鍵／時刻／method／URIを検証、発行時にclient別のproof digestを既存ledgerへ同一transactionで保存する。古いproofと再使用を拒否し、競合の敗者・署名失敗では承認とproof claimをrollback。confidential refreshの新鍵をopaque/JWT ATへ結び付ける。3 DB全体各 **273 tests** 成功。[全体](validation/ciba-dpop-matrix.txt)、[実装範囲](research/dpop-reference-contract.md#initial-ciba-token-endpoint-correction)。UserInfo／resource、nonce、DCR等は未完了であり、DPoP対応完了とは扱わない。

- DPoPの参照OP実HTTP試験を追加し成功。pollでproof必須、ランダムjti受理、ATの鍵binding、UserInfoの鍵／ath検査、confidential refreshで新proof鍵の受理と再使用拒否を確認した。upstream Ruby単独有効化ではランダムjti拒否、独自jtiなら古いproofと再使用で発行できる差を実際のgem経路で再現。これを対応済みとは扱わず、CIBA限定の検証・replay保存・UserInfo接続を残件化。[契約](research/dpop-reference-contract.md)、[node](validation/node-dpop-reference.txt)、[upstream再現](validation/upstream-dpop-probe.txt)。本体のDPoP対応は未実装。

- 暗号化ID Token hintを「gem側の未実装差分」とした分類を訂正。node 9.12.2の暗号化機能とOP復号鍵を有効にし、実発行ID Tokenの正しいJWEを送っても、device dispatch前にinvalid_requestとなった。gemも実暗号文で同じ拒否境界を確認し、復号後の署名済みhintは新規承認待ちになる。node全lifecycleとローカルhint試験 **7 tests / 100 assertions** 成功。[node](validation/node-encrypted-hint-reference.txt)、[gem](validation/encrypted-hint-boundary.txt)、[訂正根拠](research/id-token-hint-reference-contract.md#encrypted-hint-boundary-correction-after-direct-measurement)。本体や依存の追加は不要。暗号化ID Tokenの発行対応を証明するものではない。

- DCRの`default_max_age`をnode実OPと比較。不正な負値の201受理と、有効値が応答に出ても保存されない不具合を修正した。非負の安全な整数、JSONの1.0の整数正規化、明示列への保存、列未設定での拒否を実装。失敗した管理PUTで行／credentialを保持し、GETでゼロも返す。3 DB各 **265 tests** 成功後、最後の1.0正規化も各 **1 test / 59 assertions** 成功。[全体](validation/registration-max-age-matrix.txt)、[最終差分](validation/registration-max-age-final.txt)、[node](validation/node-registration-max-age.txt)。これはmetadataの検証・保存であり、認証freshnessの自動適用ではない。

- pairwiseのsector管理更新とopaque/JWT発行が重なる試験を追加。PostgreSQL／MySQLでは発行がclient設定を取得後に停止し、管理更新を先にcommitしてから再開。tokenと保存subjectは旧sectorで一致し、後続UserInfoは新sectorになることを確認。SQLiteはwriter競合とどちらの直列順序も検証。各 **2 tests** 成功、runtime変更不要。[ログ](validation/pairwise-concurrent-matrix.txt)。これはgemのDB境界の検証であり、nodeの同時実行比較やrefresh／鍵更新との競合を証明するものではない。

- Ruby3.3／3.4のSQLite全体試験を現行実装で更新し、各 **262 tests / 2730 assertions**、failure/errorなし（行ロック専用2 skip）を確認。[ログ](validation/pairwise-current-rubies.txt)。以前の211 tests時点からDCR・pairwise・pending sector更新まで検証範囲を更新した。対応表のpairwise hint未対応という古い記述も実装・試験に合わせて修正。全体の整合化完了とは扱わない。

- 承認待ち中のsector管理更新をnode/gemで比較し、内部accountと未承認状態の保持、承認後の新sector subを確認。3 DB各 **2 tests / 88 assertions** 成功、runtime変更不要。[DB](validation/pairwise-pending-matrix.txt)。配布gemのTLS fixtureにもhybrid DCR→実JWKS取得/private_key_jwt→承認→署名検証付きID Token→保存subject/UserInfoまで接続し成功。[配布](validation/pairwise-issuance-package.txt)。JWT assertion ledgerの明示migrationもfixtureに追加した。同時管理更新/発行、配布pairwise JWT/refreshなどは未検証。

- pairwise sector管理更新後の旧token/UserInfoとrefreshをnodeで実測。旧opaque tokenでも現行sectorのsubを返す挙動に合わせ、gem JWTは発行時subを明示migrationのnullable列へ保存して検証するよう修正。すり替えsubは拒否し、既存NULL行は従来検証を保持。3 DB各 **262 tests** 成功（SQLite行ロック専用2 skip）と配布smoke成功。[DB](validation/pairwise-sector-update-matrix.txt)、[配布](validation/pairwise-subject-package.txt)、[node](validation/node-registration-remote-reference.txt)。pending要求・管理更新の競合、配布pairwise発行などは引き続き未完了。

- sector文書の検証時点を整合化。node実OPで既存clientのcache再利用・文書503中の管理更新拒否と復旧後成功を確認し、gemにもclient row digestをキーにする100件LRUを追加。登録/管理は常に再検証、失敗はcacheせず、cold lookupのHTTPはmutex外で行う。3 DBのpairwise関連試験と配布TLS regressionが成功。[DB](validation/sector-cache-matrix.txt)、[配布](validation/sector-cache-package.txt)、[node](validation/node-sector-tls-reference.txt)。static clientも同じ上限を使うこと、独自DB列変更でも再検証する差を明記。管理更新による既存tokenへの影響は残る。

- sector文書だけにリダイレクト追従を追加し、nodeで実測したHTTPS 302の差を解消。各hopの送信先検証・最大20転送・全体2.5秒deadlineを維持し、ping/JWKSの既存挙動は変更しない。配布gemで追従成功とloop/file/拒否IPへの転送拒否・無保存・資格情報非転送を確認。[配布](validation/sector-redirect-package.txt)、[関連3 DB試験](validation/sector-redirect-matrix.txt)。sector文書の取得/cache時点、管理更新、配布pairwise発行などは残る。

- 配布gemの既存TLS fixtureを再利用し、hybrid pairwiseのsector文書を実HTTPSで検証。URI membership、不正JSON/過大body/HTTPエラー、信頼されない証明書で登録拒否・無保存・登録bearer非転送を確認。既存配布smokeも成功。[配布](validation/pairwise-sector-package.txt)。nodeの同等試験は成功したが、同一originの302を追従して有効文書を受理する差を発見（gemは拒否）。[node](validation/node-sector-tls-reference.txt)、[残差](research/pairwise-reference-contract.md)。リダイレクト整合化、管理更新、配布pairwise発行などは未完了。

- pairwise の opaque/JWT refresh を検証。sub・内部account・認証時刻の保持、rotation/replay、別client拒否、不正identifier結果でのrollbackを確認。UserInfoがoffline_accessを属性callbackへ渡して例外になる経路を修正した。node実OPでも更新ID Tokenの署名・subとUserInfo、RefreshToken内部accountを確認。3 DB各 **257 tests** 成功（SQLite 行ロック専用2 skip）。[DB](validation/pairwise-refresh-matrix.txt)、[node](validation/node-registration-remote-reference.txt)。実HTTPS sector文書、管理更新による既存tokenへの影響、配布検証などは残る。

- [pairwise初期実装](pairwise.md)をopt-inで追加。必須アプリidentifier、jwks_uri/明示sectorの選択、private_key_jwt登録条件、sector文書membershipを実装。ID TokenとUserInfoのsub一致、同/異sector、内部account保持、hintから新要求への復元を検証。JWT UserInfoがpairwise subを内部IDとして検索する不足も修正した。3 DB各 **254 tests** 成功後、JWTの最終差分を各 **9 tests / 74 assertions** で確認。[全体](validation/pairwise-matrix.txt)、[最終](validation/pairwise-jwt-final.txt)。sector文書はstub、refresh・管理更新・配布・TLS実証などは未完了であり、pairwise整合化完了とは扱わない。

- pairwise の参照OP実測を追加。Basic・inline JWKSのみ・sector未指定のhybridを拒否し、同一sectorの2 clientでは明示アプリcallbackによる同一pairwise subを署名検証付きで確認した。上流Rubyのredirect URI前提、nodeのjwks_uri由来sector、hintから内部accountへの逆引き責務を[比較契約](research/pairwise-reference-contract.md)へ整理。gemのpublic-only制限は未変更。別sector・hint・UserInfo/refresh・sector文書を含む実装/検証が残る。[nodeログ](validation/node-registration-remote-reference.txt)。

- node 実OPのリモートJWKS比較を追加。既定loopback拒否、明示許可後のcache再利用、同一URLの未知kidで再取得せず旧鍵を維持、管理PUTのURL変更で旧鍵拒否・新鍵受理を実測。gemの対応試験は3 DB各 **1 test / 18 assertions** 成功。既存実装がこの条件で一致するためruntime変更は不要。[node](validation/node-registration-remote-reference.txt)、[gem](validation/registration-remote-cache.txt)。nodeの最低60秒freshnessと上流Rubyのcache policy、同一URLのmetadata更新、複数プロセスは残る比較範囲。

- private_key_jwt のリモートJWKS取得が既存送信先制限を迂回する経路を再現・修正。保護対象のassertion取得にもIP検証・固定、proxy無効、deadline、応答上限を適用し、取得/JSON解析失敗は認証拒否へ。登録した実HTTP endpointで既定拒否、許可後のcache、管理PUTによるURL置換後の旧鍵拒否・新鍵受理を検証。3 DB各 **250 tests** 成功（SQLite 行ロック専用2 skip）。[DBログ](validation/registration-remote-matrix.txt)、[再現](validation/registration-remote-red.txt)。同一URLの未知kid再取得・複数プロセスcache、nodeのremote-cache実測比較は残る。

- inline JWKS の登録検証を node に合わせた。従来は `keys` のないオブジェクトも保存されていたが、構造、対称鍵、認識する鍵型の秘密パラメータ・必須公開フィールド・任意 metadata を検証する。node 実OPで不正構造とRSA秘密フィールドの拒否、空集合の受理を比較。3 DB 各 **249 tests** 成功（SQLite 行ロック専用2 skip）。追加の管理 PUT 拒否・状態/資格情報保持はローカルSQLiteで **1 test / 50 assertions** 成功。[全体](validation/registration-jwks-matrix.txt)、[追加試験](validation/registration-jwks-current.txt)、[契約](research/registration-reference-contract.md)。リモートJWKS、全鍵型の運用、pairwiseなどは未完了。

- `token_endpoint_auth_signing_alg` の登録・適用を修正。不正 metadata の201受理と、RS512指定でもRS256 assertionが通る問題を再現した。登録値を認証方式・広告アルゴリズムで検証し、署名検証時にも保存値を強制する。node実OPでも明示有効化したRS512で比較。3 DB各 **248 tests** 成功後、広告値との一致を加えた最終差分を関連試験で再検証。[全体](validation/registration-algorithm-matrix.txt)、[最終差分](validation/registration-algorithm-final.txt)、[再現と契約](research/registration-reference-contract.md)。HMAC等の追加組合せ、JWK構造検証、pairwiseは残る。

- 動的登録した `private_key_jwt` client を node 実OPと比較。誤鍵・誤 audience・assertion replay の拒否と CIBA 発行を確認し、gem の管理 PUT では登録鍵の置換も検証した。node が Token Endpoint でも issuer audience を受理する差を修正し、CIBA grant のみに適用。3 DB 各 **247 tests** 成功後、最終の適用範囲限定と Token Endpoint の誤 audience 拒否を関連試験で再検証。[全体](validation/registration-jwt-matrix.txt)、[最終差分](validation/registration-jwt-final.txt)、[node実測](validation/node-registration-reference.txt)。リモート鍵の管理更新、algorithm metadata、他の認証方式・pairwise は残る。

- DCR の `authorization_details_types` を node と比較し、型・対応タイプの検証、保存・応答、全体置換での省略時の消去を実装。動的登録した client で resource/RAR/refresh を接続し、登録タイプ削除後の旧 RAR refresh 拒否も確認。3 DB 各 **246 tests** 成功（SQLite 2334 assertions、行ロック専用2 skip、PostgreSQL/MySQL 各2333 assertions）。[DBログ](validation/registration-rar-matrix.txt)。インストール済み gem からも登録、署名検証付き CIBA 発行、管理 bearer rotation、依存行付き削除が成功し、参照契約文書の梱包漏れを修正した。[配布ログ](validation/registration-package.txt)。追加認証方式・残り metadata 検証・pairwise などは未完了。

- DELETE の client→grant 逆順ロックを PostgreSQL で再現し、既存 grant→client の順へ変更。資格情報は事前確認と client ロック後の再確認を行う。PostgreSQL/MySQL の制御付き行ロック試験、実際の DELETE/refresh 同時要求、反対向きの管理 token 提示を検証。SQLite refresh で BusyException が500になっていた経路も503/Retry-Afterへ修正。3 DB 各 **243 tests** 成功（SQLite の行ロック専用2件のみ skip）。[DBログ](validation/registration-concurrency-matrix.txt)、[逆順の再現](validation/registration-delete-lock-red.txt)。新規 consent 作成や任意アプリhookとの全 interleaving、残り metadata、配布検証は未証明。

- 既存 CIBA/通常 OAuth grant を持つ管理 client の DELETE を修正。通常 grant の FK 違反を再現し、認証後に対象 client の OAuth grants と本体を同一 transaction で削除する。refresh・待機 ping の cascade、他 client の保持、誤資格情報で無変更、アプリ独自 FK に阻まれた際の rollback を検証。node は削除後 poll/UserInfo を拒否するが memory adapter の依存行は保持するため、SQL 側の物理削除との差を明記。3 DB 各 **240 tests** 成功（SQLite 行ロック1 skip）。[DBログ](validation/registration-deletion-matrix.txt)、[比較契約](research/registration-reference-contract.md)。削除と発行の競合、残りの登録 metadata、配布検証は未完了。

- DCR の ping・署名付き要求・user code を複合試験。新 client の登録、署名/code 検証、承認、登録 endpoint への ping dispatch、署名 ID Token 発行、通常 poll への全体置換まで確認した（ping transport はこの試験では stub）。node でも複合登録と実署名要求の受理/拒否を実測。false metadata の応答欠落と、保存列のない JWKS を201で返す不具合を修正。3 DB 各 **238 tests** 成功（SQLite 行ロック1 skip）。[DBログ](validation/registration-composition-matrix.txt)、[比較契約](research/registration-reference-contract.md)。RAR/refresh/auth 組合せ、既存 grant 付き削除、配布検証は残る。

- 管理 PUT 成功時の既定 rotation を node に合わせた。新 bearer の応答・保存、旧 bearer 拒否、旧 bearer replay が後継を失効させないこと、明示的な rotation 無効化を検証。応答生成失敗では metadata/credential を同時 rollback し、同一 bearer の並行 PUT は1件のみ発行。SQLite の実測ロック timeout は503/Retry-Afterへ、再試行は401へ変換した。3 DB 各 **236 tests** 成功（SQLite 行ロック1 skip）。[DBログ](validation/registration-rotation-matrix.txt)、[node実測](validation/node-registration-reference.txt)。複合機能・既存 grant 付き削除・配布検証は引き続き未完了。

- 管理 bearer の別 client への提示時に、その発行元資格情報だけを失効させる node の動作を実装。unique SHA-256 lookup 列の明示 migration を追加し、source の行ロックと bcrypt 検証後に verifier/digest を消去する。未知・不正形式の bearer は行を変更しない。3 DB 各 **232 tests** 成功（SQLite 行ロック1 skip）。失効後の unprefixed 偽 bearer も401にする最終差分は各 **1 test / 20 assertions** 成功。[全体](validation/registration-mismatch-matrix.txt)、[最終差分](validation/registration-mismatch-final.txt)。管理 token rotation、同時要求、複合機能・配布検証は引き続き未完了。

- 管理 PUT を node 型の全体置換へ変更。client_id の一致と server 発行項目の禁止、省略 metadata の消去、秘密値保持を検証。CIBA grant 削除後も新管理 bearer の namespace で保護を継続し、従来 bearer の通常 serializer でも verifier を除去。サブパス配下の検証迂回も試験した。3 DB 各 **230 tests** 成功（SQLite 行ロック1 skip）、最後の verifier 除去差分は3 DBで対象試験成功。[全体](validation/registration-replacement-matrix.txt)、[最終差分](validation/registration-replacement-final.txt)。node でも省略名の削除・秘密値保持を実測済み。不一致 bearer の失効、rotation、複合機能、配布検証は残る。

- CIBA DCR の管理用 bearer 発行と bcrypt 保存を追加し、発行された URI/資格情報から GET・PUT・DELETE、他 client の拒否を確認。node の管理 API も実測した結果、全体置換 PUT と client_id 必須、client 不一致時の提示 bearer 失効が gem に未実装と判明。3 DB 各 **227 tests** 成功（SQLite 行ロック1 skip）。[DBログ](validation/registration-management-matrix.txt)、[実測・残件](research/registration-reference-contract.md)。grant のある client 削除、rotation、同時更新、配布検証も未完了。

- DCR レビューで内部 DB 列への書込みと管理レスポンスの登録 token hash 露出を再現・修正。CIBA の登録項目を明示し、未知項目を無視、create 時の秘密値は OP が生成する。node でも未知項目と指定秘密値の扱いを実測した。wrong bearer の更新拒否、内部項目だけの無変更更新、応答の client_id と認証方式の型も検証。3 DB 各 **226 tests** 成功（SQLite の行ロック1件のみ skip）。[DBログ](validation/registration-security-matrix.txt)、[管理 API の残差](research/registration-reference-contract.md)。追加機能と保存列の対応、管理資格情報の発行、完全な管理 API 整合化は残る。

- CIBA 動的登録の初期 opt-in 実装を追加。public/poll の登録から発行まで、Discovery、通常 OAuth 登録の維持、管理 API による grant 削除を検証。既存 CIBA client の subject_type だけを変更できる穴を再現し、保存値との統合検証と更新トランザクションで修正した。3 DB 各 **223 tests** 成功、SQLite の行ロック1件のみ skip。[DBログ](validation/registration-db-matrix.txt)、[比較契約と残件](research/registration-reference-contract.md)。追加機能との複合登録、管理レスポンス、メタデータ入力のセキュリティレビュー、同時更新、配布検証は未完了であり、DCR の公開準備完了とは扱わない。

- 任意の [request_context](request-context.md) を追加。必須アプリvalidator、nullable追加migration、署名内の値だけを使う処理、保存前拒否、通知snapshotへの受渡しを実装。token/観測イベントへは自動展開しない。3 DB各 **216 tests**、failure/errorなし（SQLiteのみ行ロック1 skip）。[DB](validation/request-context-matrix.txt)、[配布gem](validation/request-context-package.txt)。DCR/pairwiseなどは引き続き未完了。

- [計画全体の対応表](alignment-roadmap.md)を現行コード・参照OP・検証ログから更新。Ruby3.3/3.4も211 tests成功（行ロック1 skip）。[ログ](validation/revocation-ruby-matrix.txt)。DCR/pairwise、暗号化hint、追加認証方式、限定エラーAPIなどの残件を分離した。次はrequest_context：参照OPでcallback・保存・拒否順序を実測し、gem側では未対応であることを確認。

- 新opaque ATを`ciba_at_`で識別し、保存行削除後の取消しも空200へ。署名済みCIBA JWTは取消しでunsupported_token_type、偽造markerはinvalid_request。新JWTは常に発行行と結び付け、旧wire formatの互換性も明示fixtureで確認した。3 DB各 **211 tests**、failure/errorなし（SQLiteのみ行ロック試験1 skip）。[DB](validation/access-token-revocation-complete-matrix.txt)、[配布gem](validation/access-token-revocation-package.txt)。[旧形式・他OAuthとの適用範囲の差](research/access-token-revocation-reference.md)は明記した。

- 保存済み opaque CIBA AT の取消しを接続。Grantを保持し、関連AT・refresh・旧要求を無効化する。3 DB全suite各205 tests、failure/errorなし（SQLiteの行ロック試験のみskip）。通常OAuth経路維持とbrowser session流用拒否を追加した最終限定試験も3 DBで成功。[全体](validation/access-revocation-matrix.txt)、[最終差分](validation/access-revocation-final.txt)。[JWTと未知tokenの残件](research/access-token-revocation-reference.md)は未解消。

- AT取消しの前提として Grant→source のロック順序へ統一。CIBA取得・refresh更新/取消し・既存Grantによる完了が対象。3 DB各 **201 tests**、failure/errorなし。PostgreSQL/MySQLでは別接続の行ロック試験も成功し、SQLiteではその1件のみ対象外。[根拠と限界](research/access-token-revocation-reference.md)、[ログ](validation/grant-lock-order-matrix.txt)。AT取消し自体はまだ未接続。

- [AT取消しの実OP比較](research/access-token-revocation-reference.md)で前提を修正。node の既定は関連 token・旧 CIBA 要求を無効化する一方、保存 Grant は保持する。refresh token を提示した取消しとは異なる。保持 Grant を新要求の完了に使えることも確認。既存 `revoke_ciba_grant` の流用では一致しないため、gem の AT取消し実装は未変更。

- 配布 gem の opaque/JWT 複合 smoke に refresh を追加し、migration・rotation・claims/RAR・認証情報保持・取消し・cleanup を一時インストールから確認。Discovery に revocation URL が欠ける不足を発見・修正し、掲載 URL から取消しを実行した。[配布ログ](validation/refresh-package.txt)。修正の限定テストは2 tests/55 assertions成功。access token を提示した grant-wide 取消しは残る。

- refresh の transactional before/after hooks、再検証、再入防止、outer-commit 後の観測イベントを追加。Ruby4.0.6 の3 DBと Ruby3.3/3.4 SQLite の全5環境で各 **200 tests** 成功（1894〜1897 assertions）。[DB](validation/refresh-hooks-matrix.txt)、[Ruby](validation/refresh-ruby-matrix.txt)。フックが変更した承認/client/期限を再検証し、例外時 rollback と非必須 observer を分離。access-token 取消し整合化と配布 gem の refresh 検証は残る。

- refresh の claims/RAR を opaque/JWT 両方で検証し、期限切れ source の cleanup API を追加。有効期限内の使用済み digest を残し、元の要求・現在の承認・更新時の narrowing を分離する。3 DB全 suite 各 **195 tests** 成功（1831〜1834 assertions）。[ログ](validation/refresh-permissions-matrix.txt)。node 実OPでも claims/RAR の rotation 保持を確認。両者の RAR policy はアプリ固有であり、任意の業務権限の同一性は主張しない。

- CIBA refresh token の取消しを上流 revocation endpoint に接続。hint fallback、client 認証、grant-wide 取消し、空200、hook rollback を確認。3 DBで全 **192 tests** 成功後、取消し済み token の再送処理を調整し、最終の限定試験を各 **2 tests / 54 assertions** で再検証。[全体ログ](validation/refresh-revocation-matrix.txt)、[最終差分ログ](validation/refresh-revocation-final.txt)。node 実OPでも同じ hint/再送条件を確認した。access token を提示した取消しの整合化は残る。

- refresh の基本 runtime を保存基盤へ接続。既定無効の opt-in で発行・scope/resource 選択・rotation/replay・署名失敗 rollback を実装し、3 DB 各 **190 tests** 成功（1706〜1709 assertions）。[検証ログ](validation/refresh-runtime-matrix.txt)。[開発段階と残件](refresh-tokens.md)：取消し endpoint、hooks/events、claims/RAR、cleanup、Ruby matrix と配布 gem 検証は未完了。

- refresh 専用の追加保存 migration を実装。既存 token と別に元の要求・認証情報・使用済み digest を保存する。[保存基盤の範囲](research/refresh-reference-contract.md)。SQLite/PostgreSQL/MySQL の限定試験で各 **2 tests / 17 assertions** 成功。refresh の HTTP 受付・発行・更新はまだ未実装。

- refresh の[実 OP 比較](research/refresh-reference-contract.md)を追加。既定の発行条件、更新時 scope 縮小、再利用、認証情報の保存、Grant 取消しを Node 24.21.0 で実測した。gem の refresh は未実装。上流の単一 token 行更新と参照側の独立 RefreshToken モデルの差を解消する必要がある。

2026-09-30。参照対象はリリース版v9.12.2。目的はAPI・責務・処理順序・エラーと再試行の設計を合わせること。現在のテストが通る範囲を、そのまま全体の完了条件へ置き換えない。

## 現在の到達点

| 対象 | 現在の証拠・実装 | 残る確認 |
|---|---|---|
| 参照ソース | リリースv9.12.2の全OPをHTTPで起動し、組込みmemory adapterと実署名でライフサイクルを検証 | 本番用永続adapter・複数プロセスは未検証 |
| 要求TTL・binding_message | 既定/最大TTLは600秒。bindingはnodeと同じ既定の文字集合・1〜20文字で、専用メソッドで変更可能 | 現行テスト成功。Coreの必須制限とは区別する |
| 要求と承認内容 | 保存済みCIBA Grantとbackchannel_result。scope、claims、resource、RARの要求/承認/発行内容を分離。RARは必須アプリpolicyで発行 | claims条件判定、全feature有効化順、RAR専用競合試験・追加policy、全エラー型は未整合 |
| Grantの既定期限 | 新規作成はnode同様14日。専用設定・明示期限で変更可能 | 既存レコードと明示nilは保持。参照OPのadapterによる削除とgemの期限チェックは同一の保存方式ではない |
| AD起動 | 保存後・成功応答前の必須callback。専用ソースでもnodeの同じ順序を確認 | アプリの外側transaction・配送保証は導入側の設計が必要 |
| 共通OIDC処理 | 発行、属性取得、署名/暗号化はrodauth-oauthを利用。CIBAの認証contextとaudienceだけ適応 | 要求claims/resource等、登録・認証方式の差分確認 |
| 結果の取得 | 期限チェック優先、拒否結果の一度だけの取得、再引換え時の関連Grant取消しを反映 | 失敗時rollbackとpoll制限には差が残る |
| 機能範囲 | 既定のpoll/login_hintを維持し、任意のlogin_hint_token resolverとid_token_hint専用検証を追加。claims/resource/RARも任意機能 | 暗号化hint・登録/subject拡張等は[段階計画](alignment-roadmap.md)に沿う残件 |
| 検証 | ping競合検証追加後、Ruby4.0.6のSQLite/PostgreSQL/MySQLとRuby3.3.12/3.4.11のSQLiteで各179テスト成功。node全OPとインストール済みgemの拡張smokeも成功 | 全Ruby×全DBの直積、実アプリの応答喪失・外部副作用は未検証 |

## 検証の根拠と限界

- 最新: ping送信待機中の別接続からの取得、同時再送、署名付き要求/user_code併用を追加検証。5環境で各 **179 tests** 成功（1613〜1616 assertions）。配布gemでは実TLSの不信頼証明書拒否と応答timeoutも確認。実装変更は不要だった。受信側のID重複排除を明記。プロセス停止/複数プロセス配送は未検証。

- 最新: optional [ping](ping.md)を実装。非公開配送テーブル、最外commit後送信、失敗時の結果保持、明示再送、endpoint変更拒否、cleanupを検証。5環境で各 **176 tests** 成功（1590〜1593 assertions）。配布gemの実TLS通知も成功。並行配送、TLS異常、timeoutの追加検証は残る。

- 最新: [CIBA outbound HTTP境界](outbound-http.md)を実装。署名付き要求のremote JWKSに特殊用途IP拒否、DNS検証済みIPへの接続固定、proxy無効化、応答サイズ/時間上限を適用。5環境で各 **171 tests** 成功（1531〜1534 assertions）。配布gemも成功。実TLSエラー/timeout/live DNS rebindingの直接検証とping本体は残る。

- 最新: [pingの実OP/TLS比較](research/ping-reference-contract.md)を追加。通知のBearer/JSON、承認/拒否、200/204、503/302後の結果保持、明示再送、redirect非追従を確認。既定の特殊用途IP拒否も実測し、検証先だけの例外でTLS通知を測定した。gemのpingは未実装。既存remote JWKSにも同じネットワーク防御がない差分を確認したため、transport整合化の残件へ追加。

- 最新: optional [user_code](user-code.md)を実装。必須アプリcallback、client metadata移行、未入力/不一致、raw値非保存、署名付き要求との併用、新承認必須を検証。5環境で各 **166 tests** 成功（1480〜1483 assertions）。node全OP比較と配布gem smokeも成功。コード登録・保存・照合・試行制限はアプリ所有。

- 最新: remote JWKSをloopback HTTPで実検証。cache保持、明示失効後の鍵更新、未知kid、不正応答、503、接続拒否を確認。upstreamの鍵取得503が401になる問題を要求署名の検証境界だけでinvalid_requestへ変換した。5環境で各 **162 tests** 成功（1438〜1441 assertions）。nodeとの全error code一致ではなく、明示した適応。TLS/DNS/分散cacheは残る。

- 最新: [署名付き要求](signed-requests.md)を実装。client metadata移行、登録algorithm/鍵、独立したclient認証、必須claim、署名済み値だけの正規化を検証。5環境で各 **160 tests** 成功（1414〜1417 assertions）。配布gemも署名付き要求で成功。remote JWKSや全algorithm/feature順序は残る。

- 最新: [署名付き要求の実OP比較](research/signed-request-reference-contract.md)を追加。別のclient署名鍵・登録algorithmで受付、client認証分離、必須claim、外側パラメータ除外、承認後の発行を確認。同じJWTの再送は別要求となり、既定では空jtiと未来iatも受理する。upstreamの通常JAR処理はそのまま流用できず、CIBA専用の検証・パラメータ置換が必要。この比較後、gem側にも任意機能として実装した。

- 最新: optional [id_token_hint](id-token-hint.md)を実装。5環境で各 **155 tests** 成功（1336〜1339 assertions）。新承認必須、通常decoderの期限検証維持、retained keys、最大経過時間、RSA/EC/HMACの実発行token再利用を確認。配布gem smokeも成功。azp/typ/time型とHMAC鍵方式の差を文書化した。

- 最新: [id_token_hintの実OP比較](research/id-token-hint-reference-contract.md)を追加。nodeは正しく署名された期限切れhintを新しい承認待ち要求として受理し、issuer/audience/subject/nbf/署名の不正を拒否する。一方azpは未検証だった。rodauth-oauthのverify_claims:falseでは期限切れを受理できないことも実測。この比較後、gemに専用検証境界を実装した。

- 最新: [login_hint_token](login-hint-token.md)をopt-inのアプリresolverとして追加。5環境で各 **149 tests** 成功（1245〜1248 assertions、既存競合試験の分岐差）。node全OPでもresolver/client policy/複数hint拒否/署名済みsubjectを確認し、配布gemの複合フローもhint tokenで実行した。raw tokenを保存しない点は参照OPとの差として記録。本番トークン形式の検証は導入アプリの責務。

- 最新: RARの異なるnarrowing同時pollと発行/取消し競合を追加。旧要求に新形式承認を結び付けた後の機能無効化で、承認内容が無視される問題を再現・修正した。5環境で各 **145 tests** 成功（1199〜1202 assertions、競合時の順序に応じた分岐で件数差）。node参照でもRAR再引換え後のintrospectionから権限が消えることを実測。RAR completion競合・追加policy・機能順のレビューは残る。

- 最新: [RAR](authorization-details.md)を受付・保存承認・必須policy・発行へ接続。5環境で各 **141 tests / 1126 assertions** 成功。型/client/resourceの拒否、改変snapshot、poll拡大、policy出力検証、hook後の再検証、無効化、rollbackを含む。配布gemでもopaque/JWTのRARとclaims/resource併用を確認。RAR専用の同時実行・追加policyレビューは残る。

- 最新: RARの内部形式検証と追加migrationを実装。重複キー・不正UTF-8・深さ/サイズ上限・既存データ保持を検証し、5環境で各 **135 tests / 1082 assertions** 成功。JSONのnative duplicate-key拒否に対応する依存を明示した。RARのHTTP受付、policy、発行への接続は未実装。[進捗と残件](research/rar-reference-contract.md)。

- 最新: [RARのCIBA実OP比較](research/rar-reference-contract.md)を追加。要求・保存Grant・完了結果のrarは自動的に同一視されず、型/client検証、resource選択、発行policyの別々の境界があることを確認した。要求read/deleteから明示承認readだけを発行する試験policyでtoken/introspectionを検証。gem側のRARは未実装。

- 最新: 配布gem検証を基本フローに加えてclaims/resourceのopaque/JWTへ拡張。一時インストールした成果物だけからコードとmigrationを読み、承認・署名・nonce・at_hash・audience・UserInfo拒否・再引換えを確認。[検証ログ](validation/node-alignment-package.txt)。ソースチェックアウトのテストだけで追加機能の配布を判断する不足を解消した。ネットワーク依存解決と公開は未実施。

- 最新: resource JWT introspectionの境界を参照OPで実測し、HTTP400 `unsupported_token_type`へ合わせた。SQLiteで **130 tests / 1020 assertions** 成功。[ログ](validation/resource-introspection-tests.txt)。nodeは全構造化JWTを拒否するが、gemは既存OAuthフローを維持するため検証済みCIBA resource JWTだけを対象とする。[差分と根拠](research/resource-reference-contract.md)。直前の129テストmatrixからDB処理の変更はなく、この追加ケースの他環境再実行は行っていない。

- 最新: resource省略時の選択callback、claims併用、異なる宛先への同時pollを追加検証。上流resource機能の後付け有効化によるJWT audience上書きを再現・修正。5環境で各 **129 tests / 997 assertions** 成功。参照OPでも省略時の選択policyを実測した。以下は過去の段階の記録。

- 最新: オプションの[resource対応](resources.md)を追加。5環境で各 **125 tests** 成功、failure/error/skipなし（960〜961 assertions）。JWT/opaqueのscope・audience、ID Tokenとの分離、UserInfo拒否、policy変更、署名失敗rollback、移行を確認。node全OPでは権限が空のresource選択も実測。選択callback、upstream resource featureとの併用、専用競合試験は残る。

- 最新: claims追加後のレビューで旧JWTと別発行の許可が混ざる問題を再現・修正。[レビュー](security-review.md)。3種類のDBで **117 tests / 896 assertions** 成功。旧JWTへ新しいclaim許可を付与せず、従来のscope経路に限定する。

- 最新: オプションの[claims対応](claims.md)を実装。5環境で各 **116 tests / 889 assertions** 成功。要求と承認の分離、拒否優先、属性取得制限、応答先分離、JWT/opaqueのUserInfoの発行分離・取消しを検証。明示条件の判定はアプリへ委ねるため、完全なclaims対応とはしない。

- 最新: nonceの保存・ID Tokenへの反映・pollによる上書き防止・既存要求を保持する列追加を実装。CIBA必須機能ではなくnodeに合わせた追加対応。[APIと移行](api.md)。上記5環境で各 **111 tests / 812 assertions** 成功。[DBログ](validation/db-matrix-latest.txt)、[Rubyログ](validation/ruby-matrix-latest.txt)。以下の件数は各段階の履歴。

- Grant既定期限の変更後、Ruby4.0.6でSQLite/PostgreSQL/MySQL各 **108 tests / 795 assertions** 成功。[DBログ](validation/db-matrix-latest.txt)。下記Ruby3.3/3.4のmatrixは104テスト時点で、今回の変更後の再実行ではない。

- 追加の[結果エラー境界レビュー](research/completion-error-boundaries.md): nodeの任意エラー受付をpollへ機械的に移植しない。通知例外後の要求保持も完全なnode OPで確認した。gemの追加テスト込みではRuby4.0.6/SQLiteで **105 tests / 783 assertions** 成功。以下のDB/Ruby matrixは104テスト時点の記録。

- `mise exec ruby -- ruby test/run.rb`: **104 runs / 757 assertions、failure/error/skipなし**。[ログ](validation/node-alignment-tests.txt)。
- `node --experimental-vm-modules test/reference/lifecycle.mjs`: Node v26.5.0で成功。[参照テスト](../test/reference/README.md)、[ログ](validation/node-reference-lifecycle.txt)。未改変のhandler/helperを実行するが、永続化・発行・取消し等はスタブ。完全なOP接続試験ではない。
- 両方で、別clientの要求IDでは再利用検知による取消しが起きないことを確認した。
- 保存済みGrantはscopeの共通部分、結果hash改変、別client/account、期限、競合、再送、cleanup後の取消し、カスタムschema/cascadeを検証。
- AD起動は保存済みsnapshot、同期完了、未設定/例外、受付拒否を検証。配送例外後は保存済み要求が残る。
- 属性providerは許可scopeだけを受け取り、未承認emailを取得・発行しない。CIBAのauth_timeはbrowser sessionを参照しない。
- デモは保存済みGrant/result APIを使用し、再送・拒否後の承認・別顧客の決定を検証。
- 配布gemは104テスト時点のコードを再生成し、一時インストールから検証。`mise exec ruby -- ruby bin/verify-package` で再現できる。再引換えによる取消しもsmoke testで確認。依存gemのネットワーク取得は未検証。
- 承認付き実行でDocker接続が可能となった。最新のDB matrixは各104 tests / 757 assertions成功。[ログ](validation/db-matrix-latest.txt)。MySQLで見つかったJWKS列の長さ不足をテストschemaで修正し、migration例の外部キー削除順も修正した。
- npmで固定版の完全なnode OPを取得し、HTTP Discovery・開始・poll・公開鍵による署名検証と内部結果APIを実行した。[再現手順と比較](../test/reference/full-op/README.md)。これは本番adapterの検証やCIBA全機能の適合試験ではない。

## 発行失敗時の設計判断（合意済み）

nodeの参照コードでは、要求消費後に発行が例外になっても、非transactionalなadapterでは消費状態が残る。次のpollはinvalid_grantとGrant取消しになる。gemは同一DB transactionで消費と発行をまとめ、失敗時には両方をrollbackする。

rodauth-oauth 1.7.0のtoken routeは認証・入力検証後にtransactionを開始し、before_tokenとcreate_tokenを内部で呼ぶ。gemのciba_issueフック・要求消費・発行もその境界内にある。nodeの失敗後動作まで合わせるには、消費と発行の境界を分け、[ADR 0003](adr/0003-follow-rodauth-hook-conventions.md)のrollback契約を明確化する必要がある。内部のsavepointを追加するだけでは、外側のrollbackから消費を保護できない。

Jevの[追加比較](research/jev-alignment-alternatives.md)では原子性維持.75、段階的な対応拡張.83となり、助手は初版範囲を最終到達点にせず段階計画を持つ案へ推奨を更新した。ユーザーの合意を[ADR 0004](adr/0004-retain-atomic-issuance-and-stage-alignment.md)に記録し、[再試行・応答喪失・外部副作用の契約](failure-contract.md)を明文化した。個別の将来機能が実装済みであることや、全体の整合化完了を意味しない。runtime方針は変更していない。nodeのadapter全般が非transactionalだとは断定しない。

## 資料

[resourceの実OP比較](research/resource-reference-contract.md)で、リソース別scope、アクセストークンとID Tokenのaudience分離、取得時のresource省略方針を確認した。gemにもオプション機能として実装し、OIDC/APIのscope分離、保存済みaudience、宛先選択callbackを提供する。[対応範囲](resources.md)に未検証の組合せを記載した。

[claimsの実OP比較](research/claims-reference-contract.md)で要求・許可・拒否・応答先の分離を確認し、gemに任意機能として実装した。上流UserInfoも独立した属性取得経路を持つため、両経路を制限し、発行レコードとの結び付けも追加した。

[公開APIの拡張レビュー](research/consent-api-evolution.md)では、ID参照の結果APIを維持できることと、claims/resource/error対応に必要な保存・承認・migrationの変更を整理した。将来機能の実装完了ではない。

[当初の比較](research/node-oidc-provider-comparison.md)は整合化前の履歴。[現在の処理順序と差分](research/node-ciba-lifecycle.md)、[公開API](api.md)を参照。

nodeのGrantは認可内容、rodauth-oauthのoauth_grantsは発行トークン等も保持するため、同名として流用しない。上流id_token_claimsは最終browser loginを無条件に取得するため、CIBAでは単純なsuper呼出しに置換しない。

最初はWeb cache missとshell DNS障害で参照ソースを取得できなかったが、GitHub connectorで解消した。Docker・完全なnode実行環境の不足も、承認付き実行で解消した。通常のsandbox経由のDocker接続自体は引き続き拒否される。
