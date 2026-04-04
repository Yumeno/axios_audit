[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDir,
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$remediationLog = Join-Path $OutputDir 'RemediationLog.csv'
$dryRunTxt      = Join-Path $OutputDir 'RemediationDryRun.txt'
$manualTxt      = Join-Path $OutputDir 'ManualActions.txt'
$summaryTxt     = Join-Path $OutputDir 'Stage7_Summary.txt'
$transcript     = Join-Path $OutputDir 'Stage7_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

# ============================================================
# 判定結果読み込み
# ============================================================
$verdictCsv = Join-Path $OutputDir 'AuditVerdict.csv'
$iocCsv     = Join-Path $OutputDir 'IocFindings.csv'

if (-not (Test-Path $verdictCsv)) {
    Write-Host '[ERROR] AuditVerdict.csv が見つかりません。先に Stage 6 を実行してください。' -ForegroundColor Red
    Stop-Transcript | Out-Null
    return
}

$verdicts = Import-Csv $verdictCsv
$iocs     = if (Test-Path $iocCsv) { Import-Csv $iocCsv } else { @() }
$versionCsv = Join-Path $OutputDir 'AxiosVersionFindings.csv'
$versions = if (Test-Path $versionCsv) { Import-Csv $versionCsv } else { @() }
$compromisedProjects = @($verdicts | Where-Object { $_.Verdict -eq 'Compromised' })
$highIocs = @($iocs | Where-Object { $_.Severity -eq 'High' })

if ($compromisedProjects.Count -eq 0 -and $highIocs.Count -eq 0) {
    Write-Host '[INFO] 侵害確定のプロジェクトも高リスク IOC も検出されていません。修復は不要です。' -ForegroundColor Green
    Stop-Transcript | Out-Null
    return
}

# ============================================================
# 修復アクション収集
# ============================================================
$actions = New-Object System.Collections.ArrayList
$logEntries = New-Object System.Collections.ArrayList
$manualActions = New-Object System.Collections.ArrayList

function Plan-Action {
    param(
        [string]$Category,
        [string]$Target,
        [string]$Description,
        [string]$Command
    )
    [void]$actions.Add([pscustomobject]@{
        Category    = $Category
        Target      = $Target
        Description = $Description
        Command     = $Command
        Status      = 'Planned'
    })
}

function Log-Action {
    param(
        [string]$Category,
        [string]$Target,
        [string]$Description,
        [string]$Status,
        [string]$Detail
    )
    [void]$logEntries.Add([pscustomobject]@{
        Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Category    = $Category
        Target      = $Target
        Description = $Description
        Status      = $Status
        Detail      = $Detail
    })
}

# --- システムレベル IOC 修復 ---
$programDataWt  = Join-Path $env:ProgramData 'wt.exe'
$programDataBat = Join-Path $env:ProgramData 'system.bat'
$regKeyPath     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$regValueName   = 'MicrosoftUpdate'

if (Test-Path $programDataWt) {
    Plan-Action -Category 'IOC-File' -Target $programDataWt -Description 'RAT ペイロード wt.exe を削除' -Command "Remove-Item -LiteralPath '$programDataWt' -Force"
}
if (Test-Path $programDataBat) {
    Plan-Action -Category 'IOC-File' -Target $programDataBat -Description 'RAT 永続化バッチ system.bat を削除' -Command "Remove-Item -LiteralPath '$programDataBat' -Force"
}
try {
    $regValue = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction Stop
    if ($regValue) {
        Plan-Action -Category 'IOC-Registry' -Target "$regKeyPath\$regValueName" -Description 'RAT 永続化レジストリキーを削除' -Command "Remove-ItemProperty -Path '$regKeyPath' -Name '$regValueName' -Force"
    }
} catch {}

# --- プロジェクトレベル修復 ---
foreach ($proj in $compromisedProjects) {
    $path = $proj.Path
    $projOwnership = if ($proj.PSObject.Properties['Ownership']) { $proj.Ownership } else { 'Unknown' }

    # plain-crypto-js ディレクトリ削除（所有者を問わず実行 — IOC 除去）
    $plainCryptoDir = Join-Path $path 'node_modules\plain-crypto-js'
    if (Test-Path $plainCryptoDir) {
        Plan-Action -Category 'Package' -Target $plainCryptoDir -Description "plain-crypto-js ディレクトリを削除" -Command "Remove-Item -LiteralPath '$plainCryptoDir' -Recurse -Force"
    }

    # 関連パッケージ削除（所有者を問わず実行 — IOC 除去）
    foreach ($relPkg in @('node_modules\@shadanai\openclaw', 'node_modules\@qqbrowser\openclaw-qbot')) {
        $relDir = Join-Path $path $relPkg
        if (Test-Path $relDir) {
            Plan-Action -Category 'Package' -Target $relDir -Description "関連侵害パッケージを削除" -Command "Remove-Item -LiteralPath '$relDir' -Recurse -Force"
        }
    }

    # axios ダウングレード — 自分のプロジェクトのみ実行
    # 他者のリポジトリでは package.json / lockfile を書き換えない
    # （npm install --save は package.json と lockfile を変更するため）
    $pkgJsonPath = Join-Path $path 'package.json'
    if ((Test-Path $pkgJsonPath) -and $projOwnership -eq 'Mine') {
        $safeVersion = '1.14.0'
        $projVer = @($versions | Where-Object { $_.RepoPath -eq $path })
        foreach ($pv in $projVer) {
            if ($pv.Status -eq 'HighRiskVersionFound' -and $pv.AxiosVersion -eq '0.30.4') {
                $safeVersion = '0.30.3'
                break
            }
        }
        Plan-Action -Category 'Downgrade' -Target $path -Description "axios を安全なバージョン ($safeVersion) にダウングレード" -Command "Push-Location '$path'; npm install axios@$safeVersion --save --ignore-scripts 2>&1; Pop-Location"
    } elseif ((Test-Path $pkgJsonPath) -and $projOwnership -ne 'Mine') {
        # 他者 / 不明のリポジトリ: ダウングレードはせず手順案内のみ
        Plan-Action -Category 'Info' -Target $path -Description "[手順案内] 他者のリポジトリのため自動ダウングレードはスキップ。node_modules を削除して npm ci --ignore-scripts で再インストールしてください" -Command "Write-Host '[INFO] $path は他者のリポジトリです。手動で対応してください。'"
    }
}

# --- npm cache clean ---
if ($actions.Count -gt 0) {
    Plan-Action -Category 'Cache' -Target 'npm cache' -Description 'npm キャッシュをクリア（侵害版の再インストール防止）' -Command 'npm cache clean --force 2>&1'
}

# --- 手動アクション ---
[void]$manualActions.Add('========================================')
[void]$manualActions.Add('  手動対応チェックリスト')
[void]$manualActions.Add("  生成日時: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$manualActions.Add('========================================')
[void]$manualActions.Add('')
[void]$manualActions.Add('以下の項目はスクリプトでは自動化できません。手動で確認・対応してください。')
[void]$manualActions.Add('')

[void]$manualActions.Add('[ ] 1. クレデンシャル・シークレットのローテーション')
[void]$manualActions.Add('     - .env ファイル内の API キー')
[void]$manualActions.Add('     - npm access token (npm token list で確認、npm token revoke で失効)')
[void]$manualActions.Add('     - Git credential store / Git credential manager のトークン')
[void]$manualActions.Add('     - AWS / GCP / Azure のアクセスキー・サービスアカウントキー')
[void]$manualActions.Add('     - SSH 鍵（侵害端末で使用していた鍵ペア）')
[void]$manualActions.Add('     - データベース接続パスワード')
[void]$manualActions.Add('     - CI/CD パイプラインのシークレット（GitHub Actions secrets 等）')
[void]$manualActions.Add('')

[void]$manualActions.Add('[ ] 2. CI/CD パイプラインの確認')
[void]$manualActions.Add('     - 侵害ウィンドウ中（2026-03-31 00:21〜03:15 UTC）にビルドが走っていないか確認')
[void]$manualActions.Add('     - GitHub Actions / GitLab CI / Jenkins のログを確認')
[void]$manualActions.Add('     - デプロイ済みアーティファクトの再ビルドを検討')
[void]$manualActions.Add('')

[void]$manualActions.Add('[ ] 3. この PC の npm を今後の攻撃に備えて強化する')
[void]$manualActions.Add('')
[void]$manualActions.Add('     今回は axios が狙われましたが、同じ手口はどのパッケージにも起こり得ます。')
[void]$manualActions.Add('     axios だけをピン止めしても、他のパッケージが攻撃されれば同じことです。')
[void]$manualActions.Add('     以下の設定はパッケージ名に関係なく、この PC の npm 全体に効きます。')
[void]$manualActions.Add('')
[void]$manualActions.Add('     [最重要] postinstall スクリプトの実行を禁止:')
[void]$manualActions.Add('       npm config set ignore-scripts true')
[void]$manualActions.Add('')
[void]$manualActions.Add('       → npm サプライチェーン攻撃の大半は postinstall 経由です。')
[void]$manualActions.Add('         これを禁止するだけで攻撃チェーンの最終段を断ち切れます。')
[void]$manualActions.Add('         postinstall が必要なパッケージは個別に: npm rebuild パッケージ名')
[void]$manualActions.Add('')
[void]$manualActions.Add('     [重要] 新しいバージョンの即時採用を避ける（クールダウン）:')
[void]$manualActions.Add('       npm config set min-release-age 7    ※ npm v11.10 以降で利用可能')
[void]$manualActions.Add('')
[void]$manualActions.Add('       → 公開から 7 日以内のバージョンのインストールを拒否します。')
[void]$manualActions.Add('         今回の侵害版は約 3 時間で削除されたので、7 日待てば踏みません。')
[void]$manualActions.Add('         緊急パッチを即座に適用したい場合は都度:')
[void]$manualActions.Add('           npm install パッケージ名 --min-release-age=0')
[void]$manualActions.Add('')

[void]$manualActions.Add('[ ] 4. 自分が開発しているプロジェクトの場合（追加で推奨）')
[void]$manualActions.Add('     - package-lock.json を Git にコミット')
[void]$manualActions.Add('     - CI/CD では npm install ではなく npm ci を使用')
[void]$manualActions.Add('     - （上記 3 の設定と組み合わせることで、lockfile に書かれた')
[void]$manualActions.Add('       バージョンだけを厳密に再現し、かつスクリプト実行も禁止できます）')
[void]$manualActions.Add('')

if ($highIocs.Count -gt 0) {
    [void]$manualActions.Add('[ ] 5. [重要] RAT が実行された形跡があります')
    [void]$manualActions.Add('     - この端末からアクセスしたすべてのサービスのパスワードを変更')
    [void]$manualActions.Add('     - 可能であれば OS の再インストール（クリーンインストール）を推奨')
    [void]$manualActions.Add('     - ネットワーク管理者にインシデント報告')
    [void]$manualActions.Add('')
}

# ============================================================
# ドライラン表示
# ============================================================
$dryRunReport = New-Object System.Collections.ArrayList
[void]$dryRunReport.Add('========================================')
[void]$dryRunReport.Add('  修復アクション一覧（ドライラン）')
[void]$dryRunReport.Add("  生成日時: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$dryRunReport.Add('========================================')
[void]$dryRunReport.Add('')

$actionIndex = 0
foreach ($a in $actions) {
    $actionIndex++
    [void]$dryRunReport.Add("  [$actionIndex] $($a.Category)")
    [void]$dryRunReport.Add("      対象: $($a.Target)")
    [void]$dryRunReport.Add("      操作: $($a.Description)")
    [void]$dryRunReport.Add('')
}

[void]$dryRunReport.Add("  合計: $($actions.Count) 件の自動修復アクション")
[void]$dryRunReport.Add('')

$dryRunReport | Out-File -FilePath $dryRunTxt -Encoding UTF8

# コンソール表示
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  修復アクション一覧' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

$actionIndex = 0
foreach ($a in $actions) {
    $actionIndex++
    Write-Host "  [$actionIndex] $($a.Description)" -ForegroundColor Yellow
    Write-Host "      対象: $($a.Target)"
    Write-Host ''
}

Write-Host "  合計: $($actions.Count) 件の自動修復アクション" -ForegroundColor Cyan
Write-Host ''

# ============================================================
# ドライランモードまたは確認
# ============================================================
if ($DryRun) {
    Write-Host '  [DryRun] ドライランモードです。実際の修復は行いません。' -ForegroundColor Yellow
    Write-Host "  詳細: $dryRunTxt"
    Write-Host "  手動対応: $manualTxt"
    $manualActions | Out-File -FilePath $manualTxt -Encoding UTF8
    Stop-Transcript | Out-Null
    return
}

if (-not $Force) {
    Write-Host '  上記のアクションを実行してよいですか？' -ForegroundColor Yellow
    Write-Host '  実行する場合は Y を入力してください。' -ForegroundColor Yellow
    Write-Host '  （キャンセルする場合は他のキーを押してください）' -ForegroundColor Yellow
    Write-Host ''
    $confirm = Read-Host '  実行しますか? (Y/N)'
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host '  キャンセルしました。修復は実行されませんでした。' -ForegroundColor Yellow
        Write-Host "  ドライラン結果: $dryRunTxt"
        $manualActions | Out-File -FilePath $manualTxt -Encoding UTF8
        Stop-Transcript | Out-Null
        return
    }
}

# ============================================================
# 修復実行
# ============================================================
Write-Host ''
Write-Host '  修復を実行しています...' -ForegroundColor Cyan
Write-Host ''

$successCount = 0
$failCount = 0

foreach ($a in $actions) {
    Write-Host "  実行中: $($a.Description)..." -NoNewline
    try {
        $savedEnc = [Console]::OutputEncoding
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $result = Invoke-Expression $a.Command 2>&1 | Out-String
        [Console]::OutputEncoding = $savedEnc
        $a.Status = 'Success'
        $successCount++
        Write-Host ' OK' -ForegroundColor Green
        Log-Action -Category $a.Category -Target $a.Target -Description $a.Description -Status 'Success' -Detail $result.Trim()
    } catch {
        [Console]::OutputEncoding = $savedEnc
        $a.Status = 'Failed'
        $failCount++
        Write-Host ' FAILED' -ForegroundColor Red
        Log-Action -Category $a.Category -Target $a.Target -Description $a.Description -Status 'Failed' -Detail $_.Exception.Message
    }
}

# ============================================================
# 出力
# ============================================================
$logEntries | Export-Csv -Path $remediationLog -NoTypeInformation -Encoding UTF8
$manualActions | Out-File -FilePath $manualTxt -Encoding UTF8

@(
    '=== Stage 7 Summary ===',
    "OutputDir          : $OutputDir",
    "RemediationLog.csv : $remediationLog",
    "ManualActions.txt  : $manualTxt",
    "TotalActions       : $($actions.Count)",
    "Succeeded          : $successCount",
    "Failed             : $failCount"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  修復結果' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  成功: $successCount 件" -ForegroundColor Green
Write-Host "  失敗: $failCount 件" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
Write-Host ''
Write-Host "  修復ログ: $remediationLog"
Write-Host "  手動対応: $manualTxt"
Write-Host ''
Write-Host '  [重要] 手動対応チェックリストを必ず確認してください。' -ForegroundColor Yellow
Write-Host "         $manualTxt" -ForegroundColor Yellow
Write-Host ''
Write-Host '  修復後の検証には Stage 8 を実行してください:' -ForegroundColor Cyan
Write-Host "    powershell -ExecutionPolicy Bypass -File .\axios_audit_stage8_verify.ps1 -OutputDir `"$OutputDir`"" -ForegroundColor White
Write-Host ''

Stop-Transcript | Out-Null
