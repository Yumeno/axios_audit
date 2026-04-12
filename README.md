# Axios npm サプライチェーン侵害 監査ツールキット

2026年3月31日に発生した npm パッケージ「axios」へのサプライチェーン攻撃（axios 1.14.1 / 0.30.4）について、自分の PC が影響を受けているかを診断し、必要に応じて修復するための PowerShell スクリプト群です。

## 想定環境

- **OS:** Windows 10 / 11（日本語環境）
- **シェル:** Windows PowerShell 5.1 以降（Windows 標準搭載）
- **ファイルシステム:** システムロケールが Shift_JIS（cp932）の標準的な日本語 Windows 環境で動作します。スクリプト自体は UTF-8 BOM + CRLF で保存されています。
- **npm:** Node.js / npm がインストール済みであること（バージョン確認・修復に使用）。npm がなくてもプロジェクト棚卸しと IOC 確認は実行できます。
- **nvm-windows 利用時の注意:** nvm-windows 経由で Node.js を管理している場合、PowerShell 5.1 のスクリプト実行コンテキストでは npm に PATH が通らないことがあります。スクリプトは環境変数 `NVM_SYMLINK` / `NVM_HOME` を参照して自動的に PATH を補完しますが、それでも npm が見つからない場合は、スクリプト実行前に手動で PATH を追加してください：
  ```powershell
  $env:PATH = "$env:NVM_SYMLINK;$env:PATH"
  ```

## インストール

インストーラーはありません。スクリプト一式を任意のフォルダに配置するだけで使えます。

```powershell
# 例: デスクトップにフォルダを作って配置
mkdir "$HOME\Desktop\axios_audit"
# このリポジトリのファイルをすべてそのフォルダにコピー
```

Git でクローンする場合：

```powershell
git clone https://github.com/<owner>/axios_audit.git "$HOME\Desktop\axios_audit"
```

## 使い方

### 診断（Stage 1〜6）

```powershell
cd "$HOME\Desktop\axios_audit"
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1
```

全ドライブを走査し、Node.js プロジェクトの棚卸し → lockfile 確認 → axios バージョン確認 → IOC（侵害痕跡）確認 → 判定レポート生成を一括で実行します。

結果は `AxiosNpmAudit_YYYYMMDD_HHMMSS/AuditVerdict.txt` に出力されます。

### 特定のフォルダだけ調べたい場合

```powershell
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -ScanPaths "C:\Users\me\projects","D:\repos"
```

### 侵害が見つかった場合の修復

```powershell
# まずドライランで修復内容を確認
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -DryRunOnly

# 確認後、修復を実行
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -AutoRemediate
```

**修復ポリシー:**

- **1.x 系:** 自動 remediation で `1.15.0` に exact pin（`--save-exact --package-lock-only` → `npm ci`）
- **0.x 系:** backport 未確定のため自動 remediation なし（手順案内のみ）
- **自作リポジトリ (`Mine`):** lockfile 更新 → クリーン再構築 → 署名検証の 3 段階
- **他作/不明リポジトリ:** デフォルトで report-only（repo tree を変更しない）

他作/不明リポジトリのローカル cleanup を許可する場合:

```powershell
powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -AutoRemediate -AllowThirdPartyRepoMutation
```

## 注意事項

- Stage 7/8（侵害検出時の修復・検証）は、実際の侵害環境での動作検証を行っていません。修復を実行する前に、必ず `-DryRunOnly` で内容を確認してください。
- 本ツールは侵害の有無を判定する補助ツールであり、検出結果の最終判断はご自身で行ってください。

## 詳細マニュアル

攻撃の背景、各 Stage の詳しい説明、判定結果の読み方、修復後の手動対応、今後の防御策については **[axios_audit_manual.md](axios_audit_manual.md)** を参照してください。

## ライセンス

パブリックドメイン。自由に使用・改変・再配布できます。
