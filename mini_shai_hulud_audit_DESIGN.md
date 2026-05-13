# Mini Shai-Hulud 監査ツール 要件・基本設計

> ステータス: ドラフト（別リポジトリ立ち上げ前の設計合意用）
> 想定リポ名: `mini_shai_hulud_audit`（仮）
> 前提: 既存の `axios_audit` と同じ PowerShell ベースの構成・思想を踏襲。Glassworm の全 JS Unicode 走査は **別ツール** に委譲し、本ツールは Mini Shai-Hulud 専用とする。

---

## 1. 背景

2026-05-11、TeamPCP による npm + PyPI 両エコシステムを対象とした自己増殖型ワーム「Mini Shai-Hulud」が観測された。

- 影響範囲: 170+ パッケージ（npm + PyPI）
- 主な汚染パッケージ:
  - npm: `@tanstack/*`（`@tanstack/react-router` は週1200万DL）、`@mistralai/mistralai`、`intercom-client@7.0.4`、`@uipath/*`、SAP CAP 系
- 攻撃の構造:
  1. 汚染パッケージのインストール時に `router_init.js` / `router_runtime.js` が実行される
  2. クラウドクレデンシャル・GitHub トークンを窃取
  3. Session messenger（`*.getsession.org`）または `zero.masscan.cloud` 経由で送出
  4. 盗んだ GitHub トークンで他リポへ自己増殖（`shai-hulud` ブランチ作成、汚染ワークフロー追加、self-hosted runner `SHA1HULUD` 登録）
  5. 一部の系統は Bun 1.3.13 をダウンロードしてランタイムに利用

既存の `axios_audit` は単一 CVE 用に作られているため、別キャンペーン用に独立した監査ツールを新設する。

---

## 2. 目的・スコープ

### 目的
- 開発者マシン / 自社管理下の GitHub リポジトリが Mini Shai-Hulud の影響を受けていないかを **検知** する
- 検知された場合の **隔離・修復・ローテーション手順** を提示する
- 既知 IoC リストを外部 JSON 化し、新情報に追随しやすくする

### 対象（In Scope）
- ローカルディスク上の Node.js プロジェクト（`package.json` / lockfile）
- ローカルディスク上の Python プロジェクト（`pyproject.toml` / `requirements*.txt` / `Pipfile` / `setup.py` / `setup.cfg`）
- ローカル Git クローン全般（`.git/` ディレクトリ）
- グローバル / ユーザー / venv / conda / pipx の Python site-packages
- グローバル npm（`npm -g` / `pnpm` / `yarn global`）
- VS Code / Cursor / VSCodium / Open VSX 拡張機能（Mini Shai-Hulud と Glassworm で IoC 経路が一部重なるため最小限の確認のみ）
- ローカル hosts / DNS キャッシュ / netstat
- GitHub Actions self-hosted runner 設定（ローカル）

### 対象外（Out of Scope）
- **全 `.js` / `.py` の不可視 Unicode 走査** → 別ツール（Glassworm 用）に委譲
- C2 サーバとの能動的やり取り（マルウェア解析は研究者に委ねる）
- クラウド監査ログ（CloudTrail / Activity Log / Cloud Audit Logs）の直接取得 → 取得手順とクエリ例の **マニュアル提供** に留める
- 商用 SaaS 連携（Snyk / Wiz / Socket API 等）

---

## 3. 脅威モデル

| アクター | 入り口 | 影響 |
|---|---|---|
| 汚染 npm パッケージ | `npm install` / `pnpm i` / `yarn` / CI 上の `npm ci` | ローカルクレデンシャル流出、ワーム拡散 |
| 汚染 PyPI パッケージ | `pip install` / `uv pip install` / `poetry add` / CI | 同上 |
| 自己増殖した GitHub リポ | 盗まれた PAT / GITHUB_TOKEN で勝手にコミット | コードベース汚染、CI 上で再実行 |
| 不正な self-hosted runner | `SHA1HULUD` ランナーが登録される | 任意のワークフロー実行 |

---

## 4. 検知 IoC 一覧（v0.1 同梱）

### 4.1 汚染パッケージ（npm）
- `@tanstack/*`（具体的な汚染バージョン範囲は IoC JSON で管理）
- `@mistralai/mistralai`
- `intercom-client@7.0.4`
- `@uipath/*`
- SAP CAP（`@sap/cds*` 系の汚染版） ※範囲は IoC JSON 側で随時更新

### 4.2 汚染パッケージ（PyPI）
- 公開情報の精度が低いため v0.1 では空のスケルトンを置き、公開され次第 IoC JSON を更新する運用

### 4.3 ファイル名
- `router_init.js`
- `router_runtime.js`
- tarball サイズ異常（オリジナルの約 3.7 倍）※検出は SHOULD

### 4.4 Git / GitHub
- ブランチ名: `shai-hulud`
- ワークフロー: `.github/workflows/discussion.yaml`、`shai-hulud-workflow.yml`
- self-hosted runner 名: `SHA1HULUD`
- リポジトリ description: `A Mini Shai-Hulud has Appeared`
- コミット作者メール: `[email protected]`、`claude@users.noreply.github.com`
- コミットメッセージ: `OhNoWhatsGoingOnWithGitHub:[Base64...]`
- ブランチ名に Dune 用語（`muad-dib`、`gom-jabbar`、`bene-gesserit` 等）の Dependabot 偽装

### 4.5 ネットワーク
- ドメイン: `*.getsession.org`、`zero.masscan.cloud`、`webhook.site`
- Session ID（参考）: `05f9e609d79eed391015e11380dee4b5c9ead0b6e2e7f0134e6e51767a87323026`
- 異常ダウンロード元: `github.com/oven-sh/bun/releases`（Bun 1.3.13）

### 4.6 クラウド（手動確認手順として提供）
- AWS CloudTrail: `npm install` / `pip install` 直後の `DescribeInstances` / `GetSecretValue` / `ListSecrets`
- Azure Activity Log / GCP Audit Logs: 開発者 IP / CI runner IP からの異常 API

---

## 5. 機能要件

### MUST（v0.1）
| ID | 機能 |
|---|---|
| F1 | Node.js プロジェクトを発見（`package.json` / `*-lock.json` / `pnpm-lock.yaml` / `yarn.lock`） |
| F2 | Python プロジェクトを発見（`pyproject.toml` / `requirements*.txt` / `Pipfile` / `Pipfile.lock` / `poetry.lock` / `uv.lock` / `setup.py` / `setup.cfg`） |
| F3 | Python ランタイムと site-packages を列挙（`py -0p`、各 interpreter の `site.getsitepackages()`、conda envs、pipx venvs、poetry virtualenvs） |
| F4 | ローカル Git クローン（`.git/` ディレクトリ）を発見 |
| F5 | 各 manifest と lockfile を解析し、汚染パッケージ名＋バージョンと照合 |
| F6 | 各 site-packages 直下の `*.dist-info/METADATA` から実体インストール一覧を作り、汚染 PyPI パッケージと照合 |
| F7 | グローバル npm（`npm ls -g`）、pnpm、yarn global の照合 |
| F8 | プロジェクト直下 + `node_modules/*/` 第1階層に `router_init.js` / `router_runtime.js` がないか確認 |
| F9 | 発見した各 Git リポについて、`shai-hulud` ブランチ、疑わしい作者メール、疑わしいコミットメッセージを `git log --all` で検出 |
| F10 | `.github/workflows/discussion.yaml`、`shai-hulud-workflow.yml` の存在確認 |
| F11 | ローカルに登録された GitHub Actions self-hosted runner（`actions-runner/.runner` JSON、Windows サービスの "actions.runner.\*"）の名前を確認し、`SHA1HULUD` が無いか検出 |
| F12 | `hosts` ファイル、DNS クライアントキャッシュ、`netstat -ano` の出力に対し C2 ドメイン / IP 文字列の検索 |
| F13 | 結果を CSV + JSON + TXT サマリで出力。判定（`Compromised` / `NeedsAttention` / `Clean`）を含む verdict ファイルを生成 |
| F14 | すべての IoC を `iocs/*.json` から読み込む（埋め込みハードコードを禁止） |

### SHOULD（v0.2 以降）
| ID | 機能 |
|---|---|
| S1 | tarball サイズ異常検出（lockfile の `integrity` / レジストリ問い合わせ） |
| S2 | npm キャッシュログ (`_logs/`) で汚染パッケージインストール痕跡 |
| S3 | pip ログ / poetry / uv のインストール履歴探索 |
| S4 | `-UpdateIocList` で公開 IoC を取得・上書き |
| S5 | 修復ステージ: 汚染パッケージのアンインストール、`node_modules` / `.venv` の再生成手順、シークレットローテーション手順 |
| S6 | 防御推奨設定の出力（`.npmrc` の `ignore-scripts=true`、`min-release-age`、`onlyBuiltDependencies`、PyPI の `--require-hashes` 推奨等） |
| S7 | VS Code / Cursor / VSCodium / Open VSX 拡張機能の一覧化（疑わしい publisher の検出） |
| S8 | リモート GitHub 組織レポをスキャンする補助モード（PAT 渡しオプション） |

### COULD（v1.0+）
- C1: macOS / Linux 対応（PowerShell 7）
- C2: SBOM 出力（CycloneDX）
- C3: GitHub Actions ワークフローとして登録できる軽量モード
- C4: リアルタイム監視（FileSystemWatcher）

### WON'T
- 全 JS / 全 Py への不可視 Unicode 全文走査（Glassworm 専用ツールに委譲）
- マルウェアの動的解析・サンドボックス実行
- 商用脆弱性 DB との連携

---

## 6. 非機能要件

| ID | 要件 |
|---|---|
| N1 | Windows PowerShell 5.1 互換を最優先（既定環境）。PWSH 7 でも動作 |
| N2 | UTF-8 BOM + CRLF でスクリプトを保存（Shift_JIS 環境で文字化けしないこと） |
| N3 | 既定は完全 Read-Only。修復は明示オプション (`-Remediate`) 必須 |
| N4 | フルスキャンが既定 5 分以内（典型的な開発者マシン、SSD、Node/Python プロジェクト数十） |
| N5 | オフラインで完結（IoC 同梱版で初期動作可、`-UpdateIocList` のみネットワーク） |
| N6 | レポートにシークレット文字列を含めない（gitleaks 的フィルタを通す） |
| N7 | 共有想定でない PII（PowerShell 履歴など）はオプトインで参照、出力時はマスク |
| N8 | 戻り値: Compromised=2、NeedsAttention=1、Clean=0（CI からの利用用） |

---

## 7. アーキテクチャ

### 7.1 ステージ構成（PowerShell スクリプト群）

```
mini_shai_hulud_audit/
├── README.md
├── shai_hulud_audit_run_all.ps1            # オーケストレータ
├── stages/
│   ├── stage1_discover_projects.ps1        # Node / Python / Git クローン発見
│   ├── stage2_enum_python_envs.ps1         # interpreter / site-packages 列挙
│   ├── stage3_scan_manifests.ps1           # manifest + lockfile 解析
│   ├── stage4_check_versions.ps1           # 汚染パッケージ名 + バージョン照合
│   ├── stage5_filesystem_ioc.ps1           # router_init.js 等のファイル IoC
│   ├── stage6_git_history_ioc.ps1          # コミット作者・ブランチ・メッセージ
│   ├── stage7_workflow_runner_ioc.ps1      # .github/workflows + self-hosted runner
│   ├── stage8_network_ioc.ps1              # hosts / DNS / netstat
│   ├── stage9_verdict.ps1                  # 判定集約
│   └── stage10_remediate.ps1               # 修復（明示オプトイン、v0.2+）
├── iocs/
│   ├── compromised_npm.json
│   ├── compromised_pypi.json
│   ├── filenames.json
│   ├── git_authors.json
│   ├── git_branches.json
│   ├── workflows.json
│   ├── runners.json
│   └── network.json
├── tools/
│   └── update_iocs.ps1                     # 公開 IoC リスト取得 (SHOULD)
└── tests/
    └── fixtures/                           # IoC を仕込んだダミーリポ群
```

### 7.2 IoC JSON フォーマット例

`iocs/compromised_npm.json`:
```json
{
  "campaign": "mini-shai-hulud",
  "updated_at": "2026-05-13",
  "source": "TeamPCP wave 2026-05-11",
  "packages": [
    {
      "name": "intercom-client",
      "versions": ["7.0.4"],
      "severity": "High",
      "reference": "https://www.wiz.io/blog/..."
    },
    {
      "name": "@mistralai/mistralai",
      "versions": ["<<TBD>>"],
      "severity": "High",
      "reference": "..."
    }
  ]
}
```

`iocs/filenames.json`:
```json
{
  "campaign": "mini-shai-hulud",
  "files": [
    { "name": "router_init.js", "severity": "High", "scope": "package-root" },
    { "name": "router_runtime.js", "severity": "High", "scope": "package-root" }
  ]
}
```

### 7.3 データフロー

```
        ┌────────────────────────┐
        │ Stage 1: Discover      │
        │   - Node プロジェクト   │
        │   - Python プロジェクト │
        │   - Git クローン        │
        └──────────┬─────────────┘
                   │ ProjectInventory.csv
                   ▼
        ┌────────────────────────┐
        │ Stage 2: Python envs   │
        │   - interpreters       │
        │   - site-packages dirs │
        └──────────┬─────────────┘
                   │ PythonEnvs.csv
                   ▼
   ┌───────────────┼───────────────┐
   ▼               ▼               ▼
┌────────┐    ┌────────┐    ┌────────────┐
│Stage 3 │    │Stage 5 │    │Stage 6     │
│Manifest│    │FS IoC  │    │Git history │
└──┬─────┘    └───┬────┘    └─────┬──────┘
   │              │               │
   ▼              ▼               ▼
┌────────┐    ┌────────┐    ┌────────────┐
│Stage 4 │    │Stage 7 │    │Stage 8     │
│Version │    │Workflow│    │Network IoC │
│Match   │    │+Runner │    │            │
└──┬─────┘    └───┬────┘    └─────┬──────┘
   └──────────────┴───────────────┘
                  ▼
        ┌────────────────────────┐
        │ Stage 9: Verdict       │
        │  Verdict.txt / .json   │
        └────────────────────────┘
```

### 7.4 出力レイアウト

```
ShaiHuludAudit_YYYYMMDD_HHmmss/
├── ProjectInventory.csv
├── PythonEnvs.csv
├── ManifestFindings.csv
├── VersionFindings.csv
├── FilesystemIocFindings.csv
├── GitHistoryFindings.csv
├── WorkflowRunnerFindings.csv
├── NetworkIocFindings.csv
├── Verdict.txt          # 人間可読サマリ
├── Verdict.json         # 機械可読
└── Transcript.log
```

### 7.5 判定ロジック

| 判定 | 条件 |
|---|---|
| **Compromised** | High カテゴリで 1 件以上ヒット（汚染パッケージ＋汚染バージョン、`router_init.js`、`shai-hulud` ブランチ、`SHA1HULUD` ランナー、`*.getsession.org` / `zero.masscan.cloud` への通信痕跡、`OhNoWhatsGoingOnWithGitHub` 文字列 等） |
| **NeedsAttention** | Medium のみ（汚染パッケージ名はあるがバージョン不明、`webhook.site` への古い記述、グローバル npm が取得できなかった、Python interpreter 列挙失敗） |
| **Clean** | High / Medium 共に 0 件 |

---

## 8. 防御策（レポート末尾に出力する推奨設定）

### npm
- `.npmrc` に `ignore-scripts=true`
- `min-release-age=86400`（24-48h 隔離。npm 10.9+）
- `--prefer-online=false` を CI で利用
- `pnpm` の `onlyBuiltDependencies` でビルドフックを許可リスト化

### PyPI
- `pip install --require-hashes` ＋ `requirements.txt` にハッシュ固定
- `pip-tools` / `uv` でロックファイル必須化
- CI で `pip install` 時は分離ネットワーク

### GitHub
- self-hosted runner の登録を Org Policy で制限
- Required reviewers の必須化、`pull_request_target` の禁止
- `GITHUB_TOKEN` を read 限定、Actions の secret は Environment 単位
- `dependabot.yml` を作成側のみ許可、PR 自動マージ条件を CODEOWNERS 必須に

### クラウド
- 短命クレデンシャル（OIDC federation）
- IAM scope を CI ランナー単位で最小化
- CloudTrail / Activity Log に `npm install` 直後の異常 API 呼び出しアラート

---

## 9. CLI 仕様

```powershell
# 既定: フルスキャン
.\shai_hulud_audit_run_all.ps1

# 範囲指定
.\shai_hulud_audit_run_all.ps1 -ScanPaths "C:\Users\me\projects","D:\repos"

# Python site-packages も対象
.\shai_hulud_audit_run_all.ps1 -IncludePythonGlobals

# IoC リストの更新
.\tools\update_iocs.ps1

# 修復（v0.2 以降、明示オプトイン）
.\stages\stage10_remediate.ps1 -ConfirmRemediate
```

終了コード:
- `0`: Clean
- `1`: NeedsAttention
- `2`: Compromised
- `>=10`: 実行エラー

---

## 10. テスト戦略

### 単体
- 各 stage の入力 CSV / JSON に対し期待出力を Pester で検証

### 結合（fixture ベース）
- `tests/fixtures/` に下記ダミーを置き、E2E でフルスキャンを回す
  - 汚染版 `intercom-client@7.0.4` をピン留めした `package.json`
  - `router_init.js` を仕込んだダミー node_modules
  - `shai-hulud` ブランチ + `OhNoWhatsGoingOnWithGitHub:abc==` コミットを持つローカル git
  - `.github/workflows/discussion.yaml` を仕込んだリポ
  - `SHA1HULUD` 名の `actions-runner/.runner` JSON
  - `hosts` 風ダミーファイル

### CI
- GitHub Actions の `windows-latest` で PowerShell 5.1 と 7 双方を実行

---

## 11. リリース計画

| バージョン | スコープ | 状態 |
|---|---|---|
| **v0.1** | MUST（F1-F14）。IoC JSON 同梱、Read-Only スキャン、verdict 出力 | draft |
| **v0.2** | SHOULD の S1-S6。修復ステージ、IoC 自動更新 | planned |
| **v0.3** | S7-S8。リモート Org スキャン、IDE 拡張機能の最小確認 | planned |
| **v1.0** | COULD。macOS/Linux、SBOM、リアルタイム監視 | future |

---

## 12. 既知のリスクと未確定事項

- **PyPI 側 IoC の精度不足**: 公開情報が npm に比べ薄い。v0.1 リリース時点では `compromised_pypi.json` を最小限とし、出る情報に応じて追補する運用が前提。
- **IoC 陳腐化**: 攻撃者が IoC を変えれば検出を逃れる。外部 JSON 化により対応速度を上げる。
- **誤検知**: `intercom-client` を旧来から `7.0.4` 以外のピン留めで使っている利用者を誤検知しない設計（バージョン完全一致が必須）。
- **権限**: ローカルにある他ユーザ・他組織のリポを誤って読まないよう、Stage 1 のスキャン範囲既定はユーザ home + プロジェクトドライブのみとする。
- **PowerShell 5.1 制約**: JSON のスキーマ検証ライブラリが標準で無い。最低限の型チェックで運用する。
- **GitHub MCP / API**: リモート組織スキャン（S8）は PAT 必須となるため、将来 Phase に切り出し。

---

## 13. 既存 `axios_audit` との関係

- **思想・コーディング規約・出力形式は流用**（同じ利用者層、同じ Windows + PowerShell 環境）
- **ロジックは独立**（依存させない。axios_audit が Mini Shai-Hulud に詳しくなる必要はない）
- 既存 axios_audit の README から「他キャンペーンについては別ツール参照」のリンクを追記する程度に留める

---

## 14. オープン論点（v0.1 着手前に確定したいこと）

1. リポジトリ名・公開範囲（public / private / org 内）
2. ライセンス（axios_audit に合わせるか）
3. PyPI IoC の取り扱い: v0.1 同梱を空にして「v0.2 に持ち越し」とするか、最小限の調査をして突っ込むか
4. リモート GitHub Org スキャン（S8）の優先度。v0.2 でいいか v0.1 に押し上げるか
5. 修復ステージ（Stage 10）の責務範囲: アンインストールまでやるか、手順表示までに留めるか
