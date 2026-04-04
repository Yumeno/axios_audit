# Axios / npm サプライチェーン侵害 監査・対応マニュアル

## このマニュアルについて

2026年3月31日、npm パッケージ「axios」が北朝鮮系の攻撃者によるサプライチェーン攻撃を受けました。攻撃者はメンテナーのアカウントを乗っ取り、マルウェア入りのバージョン（1.14.1 と 0.30.4）を公開しました。これらのバージョンをインストールした端末には、リモートアクセス型のマルウェア（RAT）が自動的に仕込まれます。

このマニュアルは、その侵害の影響を受けていないかを確認し、受けていた場合は修復し、今後の同種の攻撃に備えるための手順を説明するものです。

**想定する読者：**

- npm や Node.js を使うが、セキュリティ調査には慣れていない
- 自分のプロジェクトだけでなく、AI 画像生成ツール（Stable Diffusion WebUI 等）や他人のツールもインストールしている
- 手順をひとつずつ実行しながら、最後まで完了したい

**このマニュアルを読めばわかること：**

- 今回の攻撃で何が起きたのか
- 自分の PC が影響を受けているかどうかの確認方法
- 影響を受けていた場合の修復手順
- 今後の攻撃に備えるための設定方法

---

## 今回の攻撃で何が起きたのか

### 攻撃の流れ

```
攻撃者が axios メンテナーの npm アカウントを乗っ取る
  ↓
マルウェア入りの axios 1.14.1 / 0.30.4 を npm に公開
  ↓
開発者や CI/CD が npm install を実行
  ↓
npm が「最新版」として侵害版を取得
  ↓
依存パッケージ plain-crypto-js がインストールされる
  ↓
plain-crypto-js の postinstall スクリプトが自動実行
  ↓
Windows / macOS / Linux それぞれに対応した RAT（遠隔操作マルウェア）がインストールされる
  ↓
RAT が攻撃者のサーバー（sfrclak.com）に接続し、端末の情報を送信
```

### 侵害ウィンドウ

マルウェア入りバージョンが npm に公開されていた時間帯：

- UTC: 2026年3月31日 00:21 〜 03:29（約3時間）
- JST: 2026年3月31日 09:21 〜 12:29

この時間帯に `npm install` を実行し、axios の最新版を取得したシステムが影響を受けた可能性があります。

### Windows での侵害の痕跡

RAT は Windows に以下のファイルとレジストリを残します。

| 痕跡 | 場所 | 意味 |
|------|------|------|
| wt.exe | `C:\ProgramData\wt.exe` | PowerShell のコピー。RAT の実行に使われる |
| system.bat | `C:\ProgramData\system.bat` | 再起動時に RAT を再起動するバッチファイル |
| レジストリキー | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` | system.bat を自動起動する永続化設定 |
| C2 通信 | `sfrclak.com:8000` / `142.11.206.73` / `142.11.206.72` | 攻撃者のサーバーへの通信 |

wt.exe が消えていても、system.bat とレジストリキーが残っていれば、再起動のたびに RAT が復活します。

---

## 監査の進め方

### 全体像

監査は3つのフェーズに分かれています。**まずフェーズ 1 を実行して結果を確認し、侵害が見つかった場合だけフェーズ 2 に進みます。**

```
┌─ フェーズ 1: 診断と判定（まずこれを実行）───────────┐
│  Stage 1  PC 内のプロジェクトを棚卸し               │
│  Stage 2  設定ファイルと lockfile の確認             │
│  Stage 3  axios の実バージョン確認                  │
│  Stage 4  npm ログと IOC（侵害の痕跡）の確認        │
│  Stage 5  WSL 環境の確認（WSL を使う場合のみ）      │
│  Stage 6  自動判定レポート生成                      │
└──────────────────────────────────────────────────────┘
          ↓ 結果を確認 → 侵害が見つかった場合のみ ↓
┌─ フェーズ 2: 修復（侵害検出時のみ）─────────────────┐
│  Stage 7  侵害の修復                                │
│  Stage 8  修復後の検証                              │
└──────────────────────────────────────────────────────┘
          ↓ 侵害の有無にかかわらず ↓
┌─ フェーズ 3: 今後の防御 ─────────────────────────────┐
│  npm の設定を変更して、同種の攻撃を防ぐ             │
│  （AuditVerdict.txt の末尾に案内が表示されます）     │
└──────────────────────────────────────────────────────┘
```

### スクリプト一覧

| ファイル名 | 役割 |
|-----------|------|
| `axios_audit_run_all.ps1` | 一括実行スクリプト（Stage 1〜6 を連続実行） |
| `axios_audit_stage1_discover_repos.ps1` | プロジェクト棚卸し |
| `axios_audit_stage2_scan_manifests.ps1` | lockfile / manifest 確認 |
| `axios_audit_stage3_check_versions.ps1` | axios 実バージョン確認 |
| `axios_audit_stage4_logs_ioc.ps1` | npm ログ + IOC 確認 |
| `axios_audit_stage5_wsl_optional.ps1` | WSL 確認（任意） |
| `axios_audit_stage6_verdict.ps1` | 自動判定レポート生成 |
| `axios_audit_stage7_remediate.ps1` | 修復実行 |
| `axios_audit_stage8_verify.ps1` | 修復後検証 |

すべてのスクリプトは UTF-8 BOM + CRLF で保存されています。Windows の日本語環境（SJIS）でもそのまま動作します。

---

## 監査前の注意

### やらないでほしいこと

監査が終わるまで、以下の操作を行わないでください。

- `npm cache clean --force`
- `npm install` / `npm update`
- lockfile の再生成
- 「念のため」の削除

理由は、監査に必要なログや痕跡を消してしまう可能性があるためです。

### すでに cache を消してしまった場合

監査の意味はまだあります。npm ログの証拠力は下がりますが、プロジェクトの棚卸し、lockfile の確認、実バージョン確認、IOC 確認は引き続き有効です。そのまま進めてください。

---

## 手順 1: 診断を実行する（Stage 1〜6）

### 準備

1. すべてのスクリプトを同じフォルダに置く
2. PowerShell でそのフォルダに移動する

```powershell
cd "c:\users\自分のユーザー名\desktop\axios侵害調査"
```

### 実行

```powershell
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1
```

デフォルトでは Stage 1〜6（診断と判定）だけが実行されます。修復（Stage 7/8）は自動実行されません。

### 特定のフォルダだけ調べたい場合

全ドライブの走査は時間がかかります。「ここだけ確認したい」という場合は `-ScanPaths` で対象を絞れます。

```powershell
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -ScanPaths "C:\Users\me\projects","D:\repos"
```

### 途中から再実行する場合

スクリプトの修正後に特定の Stage だけやり直したい場合、`-StartFrom` で指定できます。前回の監査フォルダが自動的に使われます。

```powershell
# Stage 3 からやり直す（Stage 1, 2 の結果は前回のものを流用）
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 3

# 監査フォルダを明示的に指定する場合
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 3 -OutputDir .\AxiosNpmAudit_20260404_075723
```

`-OutputDir` を省略すると、カレントディレクトリ内の最新の `AxiosNpmAudit_*` フォルダが自動的に使われます。

### オプション一覧

| オプション | 動作 |
|-----------|------|
| （なし） | 全ドライブ走査 + Stage 1〜6 を実行 |
| `-ScanPaths "パス1","パス2"` | 指定パスだけを走査 |
| `-StartFrom N` | Stage N から再開（2以降は既存の監査フォルダが必要） |
| `-OutputDir "パス"` | 既存の監査フォルダを明示指定（`-StartFrom` と併用） |
| `-SkipWSL` | WSL の確認をスキップ（WSL が見つからない場合は自動スキップ） |
| `-DryRunOnly` | 侵害検出時に Stage 7 をドライランだけ実行 |
| `-AutoRemediate` | 侵害検出時に Stage 7→8 を自動実行 |

---

## 手順 2: 結果を確認する

### 結果の場所

実行が完了すると、コンソールに判定結果のサマリが表示されます。

```
  --------------------------------------------------------
  判定結果:

    侵害は検出されませんでした

    侵害確定:  0 件
    要確認:    0 件
    要強化:    7 件
    対策不要:  1189 件
    システム IOC: 0 件
```

詳細は監査フォルダ内の `AuditVerdict.txt` に記載されています。

### AuditVerdict.txt の読み方

レポートは以下の構成になっています。

```
■ 全体サマリ
  - 侵害確定:   0 件
  - 要確認:     2 件
  - 要強化:     7 件
  - 対策不要:   1187 件
  - システム IOC: 0 件

■ npm ログ（侵害ウィンドウ内の操作）   ← 該当がある場合のみ表示

■ プロジェクト別判定
  [対策不要] (自作) C:\Users\me\projects\my-app
  [対策不要] (他作) C:\Users\me\stable-diffusion-webui
  [要強化]   (他作) C:\Users\me\Dify\dify
  [要確認]   (自作) C:\Users\me\projects\some-project
  [侵害確定] (自作) C:\Users\me\projects\infected-app    ← これが出たら手順 3 へ

■ 次のステップ

■ 今後の npm サプライチェーン攻撃への防御策
```

### 判定ラベルの意味

**プロジェクトの判定：**

| レポート表示 | 意味 | 次にやること |
|-------------|------|------------|
| `[侵害確定]` | マルウェアの痕跡が見つかった | 手順 3（修復）に進む |
| `[要確認]` | 判定しきれないが追加確認が必要 | レポートの理由を読んで手動で確認 |
| `[要強化]` | 今回の侵害はないが、npm の防御設定が不十分 | レポート末尾の防御策を実施 |
| `[対策不要]` | 問題なし | 何もしなくてよい |

**プロジェクトの作者：**

| レポート表示 | 意味 |
|-------------|------|
| `(自作)` | 自分が開発しているプロジェクト（git の user.name と remote URL から推定） |
| `(他作)` | 他者が開発したプロジェクト（clone したもの） |
| `(作者不明)` | 推定できなかった（レポートを見て手動で判断してください） |

### 侵害確定の条件

次のいずれか1つでも該当すると `[侵害確定]` になります。

- `plain-crypto-js` がファイルシステム上に存在（ディレクトリの存在だけで確定）
- `axios@1.14.1` または `0.30.4` が `npm list` で確認済み
- `C:\ProgramData\wt.exe` が存在
- `C:\ProgramData\system.bat` が存在
- `HKCU\...\Run\MicrosoftUpdate` レジストリキーが存在
- `sfrclak.com` の DNS キャッシュヒット
- `142.11.206.73` / `142.11.206.72` への通信記録

`plain-crypto-js` のディレクトリ存在と、RAT のファイル／レジストリの存在は、それだけで侵害確定と判断して問題ありません。

### 監査フォルダの中身

```
AxiosNpmAudit_YYYYMMDD_HHMMSS/
  RepoInventory.csv           ← Stage 1: プロジェクト一覧
  ManifestFindings.csv        ← Stage 2: lockfile の痕跡
  AxiosVersionFindings.csv    ← Stage 3: 実バージョン
  NpmLogFindings.csv          ← Stage 4: npm ログ
  IocFindings.csv             ← Stage 4: IOC
  WSL_Findings.txt            ← Stage 5: WSL（実行時のみ）
  AuditVerdict.txt            ← Stage 6: ★ まずこれを読む ★
  AuditVerdict.csv            ← Stage 6: 機械可読な判定
  RemediationDryRun.txt       ← Stage 7: ドライラン結果
  RemediationLog.csv          ← Stage 7: 修復ログ
  ManualActions.txt           ← Stage 7: ★ 手動対応リスト ★
  PostRemediationVerdict.txt  ← Stage 8: 修復前後の比較
  BeforeAfterDiff.csv         ← Stage 8: 差分データ
  PreRemediation_Backup/      ← Stage 8: 修復前のバックアップ
  RunAll_Summary.txt          ← 一括実行サマリ
  Stage*_Summary.txt          ← 各 Stage のサマリ
  Stage*_Transcript.txt       ← 各 Stage の詳細ログ
```

---

## 手順 3: 侵害が見つかった場合の修復（Stage 7/8）

**侵害が検出されなかった場合、この手順は不要です。** 手順 4（今後の防御策）に進んでください。

### まずドライランで確認する

ドライランでは実際の変更は行わず、「何が実行されるか」だけを表示します。

```powershell
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -DryRunOnly
```

`-OutputDir` を省略すると、最新の `AxiosNpmAudit_*` フォルダが自動的に使われます。ドライラン結果は `RemediationDryRun.txt` に記録されます。

### 修復を実行する

ドライランの内容を確認した上で、修復を実行します。

```powershell
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -AutoRemediate
```

Stage 7（修復）が完了すると、自動的に Stage 8（修復後検証）が実行され、修復前と修復後の差分が `BeforeAfterDiff.csv` に記録されます。

### 修復で行われること

**作者に応じて修復の範囲が変わります：**

| アクション | 自作プロジェクト | 他作プロジェクト |
|-----------|----------------|----------------|
| RAT ファイル・レジストリの削除 | 実行する | 実行する |
| plain-crypto-js ディレクトリの削除 | 実行する | 実行する |
| axios のダウングレード | 実行する（1.14.0 or 0.30.3） | 実行しない（手順案内のみ） |
| npm キャッシュのクリア | 実行する | 実行する |

他作プロジェクトでは `npm install --save`（package.json と lockfile を書き換える操作）は実行しません。upstream との同期が壊れるためです。代わりに「node_modules を削除して `npm ci --ignore-scripts` で再インストールしてください」という手順を案内します。

### 修復後にやること（手動）

Stage 7 は `ManualActions.txt` を生成します。スクリプトでは自動化できない作業がリストアップされています。

1. クレデンシャル・シークレットのローテーション（API キー、npm トークン、SSH 鍵等）
2. CI/CD パイプラインの確認（侵害ウィンドウ中にビルドが走っていないか）
3. npm の全体防御設定の適用（手順 4 を参照）
4. 自作プロジェクトの場合の追加推奨（lockfile コミット、npm ci の使用）
5. RAT が実行された形跡がある場合の OS 再インストール検討

### 通し実行オプション（上級者向け）

診断から修復まで一気に実行したい場合は、以下のオプションがあります。ただし、結果を確認する前に修復が実行されるため、通常は推奨しません。

```powershell
# 侵害検出時にドライランだけ自動実行
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -DryRunOnly

# 侵害検出時に修復→検証まで全自動
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -AutoRemediate
```

---

## 手順 4: 今後の防御策を適用する

**侵害の有無にかかわらず、全員が対象です。**

AuditVerdict.txt の末尾にも、この PC の npm に防御設定が適用済みかどうかを自動チェックした結果が表示されています。

### なぜ axios のピン止めでは不十分なのか

今回たまたま axios が狙われましたが、同じ手口（メンテナーアカウント乗っ取り → 最新版タグの差し替え）は任意のパッケージに対して起こり得ます。実際に、axios の前後数日で Trivy、LiteLLM、Telnyx、Checkmarx が同様の手口で侵害されています。

axios だけをピン止めしても、他の依存パッケージが攻撃されれば同じことです。

### パッケージ名に関係なく効く防御策

以下の設定は、特定のパッケージではなく、この PC で実行されるすべての npm install に対して効きます。

#### 防御策 A: postinstall スクリプトの実行を禁止する（最重要）

```
npm config set ignore-scripts true
```

今回の攻撃を含め、npm サプライチェーン攻撃の大半は postinstall フック（パッケージのインストール直後に自動実行されるスクリプト）を使ってマルウェアを実行します。これを全面禁止するだけで、攻撃チェーンの最終段を断ち切れます。

postinstall を正当に使うパッケージ（ネイティブアドオンのビルド等）は個別に対処します：

```
npm rebuild パッケージ名
```

#### 防御策 B: 新しいバージョンの即時採用を避ける（クールダウン）

```
npm config set min-release-age 7
```

公開から7日以内のバージョンのインストールを拒否します。今回の侵害版は約3時間で削除されたので、7日待てば絶対に踏みません。ほとんどの攻撃は公開後数時間〜数日で発覚・削除されるため、この設定だけで大半を回避できます。

緊急のパッチを今すぐ入れたい場合は、都度オプションで上書きできます：

```
npm install パッケージ名 --min-release-age=0
```

#### 防御策 C: lockfile のコミットと npm ci（自作プロジェクトの場合）

自分が開発しているプロジェクトでは、追加で以下を実施してください：

- `package-lock.json` を Git にコミットする
- CI/CD では `npm install` ではなく `npm ci` を使う

`npm ci` は lockfile に書かれたバージョンだけを厳密に再現し、lockfile と package.json に矛盾があればエラーで止まります。

### まとめ：いますぐ実行してほしい2行

```
npm config set ignore-scripts true
npm config set min-release-age 7
```

侵害の有無にかかわらず、npm を使っているすべての人に推奨します。この2行で、今回の axios 攻撃を含む大半の npm サプライチェーン攻撃を防げます。

---

## 各 Stage の詳細

### Stage 1: プロジェクト棚卸し

**目的：** PC 内のどこに npm / Node.js 系プロジェクトがあるかを洗い出す。

**やっていること：**
- 全ドライブ（または `-ScanPaths` で指定されたパス）を走査し、`package.json` や `.git` を持つディレクトリを探す
- `node_modules` の中は掘らない（依存パッケージ自体のフォルダとプロジェクト本体を区別するため）
- git リポジトリの場合、作者を推定する（自作か他作か）

**作者推定のロジック（完全ではありません）：**
- remote が未設定（ローカルのみ）→ 自作と推定
- remote URL に自分の git ユーザー名が含まれる → 自作と推定
- remote あり + 自分のコミットなし → 他作と推定
- 上記で判断できない場合 → 作者不明（レポートでユーザーに確認を促す）

**出力：** `RepoInventory.csv`

### Stage 2: lockfile / manifest 確認

**目的：** 各プロジェクトの設定ファイルに、侵害の強い痕跡がないかを確認する。

**見つけたら危険なもの：**
- `plain-crypto-js` — 正規の axios にこの依存は存在しない。見つかった時点で侵害確定
- `axios@1.14.1` / `axios@0.30.4` — 侵害版のバージョン番号
- `@shadanai/openclaw` / `@qqbrowser/openclaw-qbot` — 同じマルウェアを配布する関連パッケージ

**追加で確認していること：**
- `node_modules/plain-crypto-js` ディレクトリの直接存在確認（マルウェアが package.json を正規版に書き戻すアンチフォレンジック機能を持つため、テキスト検索では見つからない場合がある）
- `package.json` 内の axios のバージョン指定が浮動（`^` / `~`）かどうか（今後の防御状態の指標として使用）

**出力：** `ManifestFindings.csv`

### Stage 3: axios 実バージョン確認

**目的：** 各プロジェクトで実際にインストールされている axios のバージョンを確認する。

lockfile に何か書いてあっても、実際に `node_modules` に入っているバージョンが異なる場合があります。`npm list axios --all` で実際の解決バージョンを確認します。

**出力：** `AxiosVersionFindings.csv`

### Stage 4: npm ログ + IOC 確認

**目的：** npm の操作ログと、Windows 上の侵害痕跡（IOC）を確認する。

**npm ログで確認すること：** npm ログの検索パターンは、今回の侵害に直接関連するものに限定しています。npm ログは PC 全体で共有されるグローバルな情報であり、特定のプロジェクトには紐付かないため、Stage 6 ではプロジェクト単位の判定には使わず、システムレベルの情報として独立して表示します。

**IOC で確認すること：**

| 確認項目 | 意味 |
|---------|------|
| `C:\ProgramData\wt.exe` | RAT のペイロード |
| `C:\ProgramData\system.bat` | RAT の永続化バッチ |
| `HKCU\...\Run\MicrosoftUpdate` レジストリキー | 再起動時の RAT 自動起動 |
| DNS キャッシュ内の `sfrclak` | C2 サーバーへの名前解決履歴 |
| netstat で `142.11.206.73` / `142.11.206.72` | C2 サーバーへの通信 |
| `:8000` ポートの通信 | C2 通信の可能性（他の通信との区別が必要） |

**出力：** `NpmLogFindings.csv`, `IocFindings.csv`

### Stage 5: WSL 確認（任意）

**目的：** WSL（Windows Subsystem for Linux）内にも npm プロジェクトがある場合、Windows 側の確認だけでは見落とす可能性がある。

**出力：** `WSL_Findings.txt`

### Stage 6: 自動判定レポート生成

**目的：** Stage 1〜5 の結果を集約し、プロジェクトごとに判定を出す。

プロジェクトの作者に応じて推奨アクションが変わります。他作プロジェクトに対しては package.json の書き換えを推奨しません。レポート末尾には、侵害の有無にかかわらず「今後の npm サプライチェーン攻撃への防御策」が表示され、この PC の npm に `ignore-scripts` と `min-release-age` が設定されているかどうかを自動チェックして案内します。

**出力：** `AuditVerdict.txt`（まずこれを読む）, `AuditVerdict.csv`

### Stage 7: 修復実行（侵害検出時のみ）

**目的：** 侵害確定と判定されたプロジェクトとシステムに対して、修復アクションを実行する。ドライラン→確認→実行の方式で、修復前に「何が実行されるか」を表示します。

**出力：** `RemediationLog.csv`, `ManualActions.txt`, `RemediationDryRun.txt`

### Stage 8: 修復後検証（修復した場合のみ）

**目的：** Stage 7 の修復が正しく完了したことを確認する。Stage 2〜4 と Stage 6 を自動的に再実行し、修復前後の差分を記録します。

**出力：** `PostRemediationVerdict.txt`, `BeforeAfterDiff.csv`

---

## よくある質問

### Q. 先に `npm cache clean --force` をしてしまいました。もう意味はありませんか？

意味はあります。npm ログの証拠力は下がりますが、プロジェクト棚卸し、lockfile 確認、実バージョン確認、IOC 確認は引き続き有効です。

### Q. Stable Diffusion WebUI (A1111) の拡張で axios が使われていました。どうすれば？

A1111 自体は Python ベースですが、一部の拡張が Node.js を使います。やるべきことは：

1. この監査スクリプトを実行して、`plain-crypto-js` や侵害版バージョンがないか確認する
2. 見つからなければ、今回の攻撃の影響は受けていない
3. 拡張の package.json を自分で書き換える必要はない（拡張の作者が管理するもの）
4. 防御策 A / B の npm 設定を適用しておけば、今後の攻撃にも備えられる

### Q. 全ドライブ走査が遅すぎます。

`-ScanPaths` で対象を絞ってください：

```powershell
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -ScanPaths "C:\Users\me\projects"
```

初回は全ドライブ走査で棚卸しをして、2回目以降は `-StartFrom` と `-ScanPaths` で特定フォルダだけ再確認する、という使い方を推奨します。

### Q. 他作プロジェクトで侵害が見つかりました。ダウングレードは自動で行われますか？

行われません。他作プロジェクトでは `npm install --save`（package.json と lockfile を書き換える操作）は実行しません。IOC の除去（plain-crypto-js の削除、RAT ファイルの削除）とキャッシュクリアのみ自動で行い、ダウングレードは手順案内に留めます。

他作プロジェクトで侵害版が見つかった場合は：
1. node_modules フォルダを丸ごと削除
2. `npm ci --ignore-scripts` で lockfile 通りに再インストール
3. それでも侵害版が入る場合は、そのリポジトリの使用を一時停止し、作者に報告

### Q. `:8000` ポートの通信が見つかりました。隔離が必要ですか？

それだけでは判断しません。相手先 IP と PID を確認してください。Chrome で Google Meet / WebRTC の通信に `:8000` が使われることがあります。相手先が `142.11.206.73` / `142.11.206.72` であれば高リスクですが、それ以外の IP であれば通常の通信の可能性が高いです。

### Q. `ignore-scripts true` に設定したら、何かが動かなくなりました。

postinstall を正当に使うパッケージ（esbuild、fsevents、node-sass 等のネイティブアドオン）が影響を受けます。該当パッケージだけ個別にビルドしてください：

```
npm rebuild パッケージ名
```

どのパッケージが postinstall を使っているか調べるには：

```
npm ci --ignore-scripts
npx can-i-ignore-scripts
```

### Q. `min-release-age 7` に設定したら、最新版がインストールできません。

仕様通りの動作です。公開から7日以内のバージョンは拒否されます。すぐに必要な場合は：

```
npm install パッケージ名 --min-release-age=0
```

### Q. `npm config set min-release-age 7` がエラーになります。

`min-release-age` は npm v11.10 以降で追加された機能です。お使いの npm が古い場合はエラーになります。

```
npm --version
```

でバージョンを確認し、v11.10 未満の場合は npm だけをアップグレードしてください（Node.js はそのままで OK）：

```
npm install -g npm@latest
```

Node.js が古い場合（v18 未満など）は Node.js ごとアップグレードしてください：

```
# Node.js 公式サイトから LTS 版をインストール（npm も同梱）
https://nodejs.org/

# または nvm-windows を使っている場合
nvm install lts
nvm use lts
```

アップグレード後に再度 `npm config set min-release-age 7` を実行してください。なお、`min-release-age` が使えなくても `ignore-scripts true` だけで今回の攻撃は防げます。両方設定するのが理想ですが、まずは `ignore-scripts` を優先してください。

---

## 既知の制限

- Stage 1 の作者推定は完全ではありません。fork したリポジトリやチームリポジトリは「作者不明」と判定される場合があります。レポート内の `(作者不明)` 表示を見たら、そのプロジェクトが自分のものかどうかを手動で判断してください。
- Stage 4 の npm ログの時刻判定は、ログファイルの更新時刻に基づく推定です。操作が実行された正確な時刻とは異なる場合があります。
- Stage 7 の修復は「最低限の除去」です。侵害が確定した端末は、公開情報上も「そのマシンを侵害済みとして扱う」ことが推奨されています。単なる依存差し替えだけで安心とは言い切れないため、RAT の痕跡が見つかった場合は OS の再インストールを検討してください。
- monorepo や npm workspace 構成のプロジェクトでは、依存解決が通常と異なるため、Stage 3 の `npm list` が正確でない場合があります。
- すべてのスクリプトは UTF-8 BOM 付きですが、スクリプトファイルを別のエディタで編集して保存すると BOM が失われる場合があります。日本語の表示が文字化けする場合は、エディタの保存設定を「UTF-8 with BOM」にしてください。

---

## 検出対象の一覧

### 侵害版パッケージ

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js`（全バージョン）
- `@shadanai/openclaw`（バージョン 2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2）
- `@qqbrowser/openclaw-qbot@0.0.130`

### Windows IOC

- `C:\ProgramData\wt.exe`
- `C:\ProgramData\system.bat`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`
- DNS キャッシュ内の `sfrclak`
- `142.11.206.73`（C2 サーバー）
- `142.11.206.72`（C2 サーバー）

### WSL / Linux IOC

- `/tmp/ld.py`

### C2 通信のフィンガープリント

- 接続先: `sfrclak.com:8000`
- URI パス: `/6202033`
- POST ボディ: `packages.npm.org/product0`（macOS）, `product1`（Windows）, `product2`（Linux）
- User-Agent: `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`
