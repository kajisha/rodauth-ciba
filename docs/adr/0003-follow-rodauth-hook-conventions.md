# 状態変更の拡張点を Rodauth の before / after 慣例に合わせる

CIBA の主要な状態変更に、Rodauth の慣例に沿う before / after フックを設ける。専用フックを設けない案や独自の拡張機構を追加する案に対し、基盤と同じカスタマイズ方法を維持することを優先する。これらは監査専用ではなく、監査機能の導入を CIBA の利用条件にしない。

before / after フックは状態変更と同じ DB トランザクション内で呼ぶ。after は commit 後ではない。フックから伝播する例外では DB の変更をロールバックするが、外部システムへの副作用までは取り消せない。具体的なフック名・対象となる状態変更・エラー応答は今後設計する。

任意の観測用イベントは別の契約とし、通知先の失敗で CIBA の成否を変えず、障害を報告する。Rodauth の既存 audit_logging と CIBA の連携可能範囲は、実装時に検証する。

根拠: [Rodauth の create_account 実装](https://github.com/jeremyevans/rodauth/blob/master/lib/rodauth/features/create_account.rb)、[audit_logging](https://rodauth.jeremyevans.net/rdoc/files/doc/audit_logging_rdoc.html)、[製品比較](../research/idm-ciba-integration.md)。
