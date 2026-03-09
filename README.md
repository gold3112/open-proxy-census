# 🌐 Open Proxy Census

Open Proxy Censusは、世界中に意図せず公開されている「オープンプロキシ」の実態を調査・可視化し、インターネットのセキュリティ向上を目指す研究プロジェクトです。

単なる生存確認に留まらず、プロキシの寿命、使用ソフトウェアの種類、悪用率（ブラックリスト登録状況）などを多角的に分析します。

## 📊 リアルタイム・ダッシュボード
起動後、`http://localhost:8080` で以下の統計をリアルタイムに確認できます：
- **世界地図分布**: どの国にプロキシが集中しているか。
- **応答速度分布**: ユーザー体験に直結するパフォーマンス統計。
- **匿名度レベル**: 利用者のプライバシーが守られているか。
- **ソフトウェア分布**: サーバーで使用されているソフト（Squid, MikroTik, Apache等）の特定。
- **悪用判定 (Abuse Rate)**: DNSBL（Spamhaus等）に登録されている「汚れた」IPの割合。

## ⚙️ システム・アーキテクチャ
高並列パイプライン構造を採用し、数千〜数万件のプロキシを高速に処理します。

```text
[ Collector ] ──> [ Port Scanner ] ──> [ Proxy Tester ] ──> [ Analyzer ] ──> [ Storage ]
      │                (5,000 workers)       (2,000 workers)      (200 workers)        │
      └─ 公開リスト取得      └─ 接続確認            └─ プロキシ機能検証    └─ ソフトウェア判定     └─ SQLite (WAL)
         CIDR展開                                                         ブラックリスト照合
                                                                          WHOIS/Abuse抽出
```

### パイプラインの詳細
1.  **Collector**: 複数の公開リストや指定されたCIDR範囲からターゲットIPを収集。
2.  **Port Scanner**: ターゲットに対して指定ポートの開放を確認（※現在はリストベースのためバイパス可）。
3.  **Proxy Tester**: 実際にHTTPリクエストをプロキシ経由で送信し、生存・速度・国判定を実行。
4.  **Analyzer**: 生存プロキシに対し、`Server`ヘッダーの解析やDNSBL照合を行い、詳細な属性を付与。
5.  **Storage**: 全ての履歴を保存し、平均寿命などの長期的な統計を算出。

## 🚀 クイックスタート

### 1. 依存関係の解決
```bash
go mod tidy
```

### 2. 設定のカスタマイズ
`config.yaml` を編集して、スキャン対象や並列数を調整できます。
```yaml
workers:
  proxy_tester: 2000
  analyzer: 200

targets:
  sources:
    - "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"
```

### 3. 実行
```bash
go run cmd/proxy-census/main.go
```

## 🛠 技術スタック
- **Language**: Go (Goroutines/Channelsによる並列処理)
- **Database**: SQLite (Write-Ahead Loggingモードで高頻度書き込みに対応)
- **Frontend**: Bootstrap 5, Chart.js, jsVectorMap
- **Libraries**: `modernc.org/sqlite`, `github.com/likexian/whois`, `gopkg.in/yaml.v3`

## ⚖️ 免責事項
本プロジェクトは教育および情報提供を目的としています。過度な頻度でのスキャンや、各国の法律に抵触する恐れのある範囲へのアクセスは行わないでください。収集したデータは善意の注意喚起（通知プロジェクト）などのセキュリティ向上目的でのみ使用することを推奨します。
