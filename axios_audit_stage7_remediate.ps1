[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDir,
    [switch]$DryRun,
    [switch]$Force,
    [switch]$AllowThirdPartyRepoMutation,
    [switch]$AllowUnknownRepoMutation
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
# ヘルパー関数
# ============================================================

function Get-RecommendedAxiosVersion {
    param([string]$ResolvedAxiosVersion)

    if ($ResolvedAxiosVersion -match '^1\.') {
        return '1.15.0'
    }

    # 0.x は backport 未確定のため自動 remediation しない
    return $null
}

function Get-RepoRemediationMode {
    param(
        [string]$Ownership,
        [switch]$AllowThirdPartyRepoMutation,
        [switch]$AllowUnknownRepoMutation
    )

    switch ($Ownership) {
        'Mine'       { return 'OwnedFull' }
        'ThirdParty' { return $(if ($AllowThirdPartyRepoMutation) { 'ExternalLocalCleanup' } else { 'ReportOnly' }) }
        'Unknown'    { return $(if ($AllowUnknownRepoMutation) { 'ExternalLocalCleanup' } else { 'ReportOnly' }) }
        default      { return 'ReportOnly' }
    }
}

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
# RemediationDisposition が存在する場合はそちらを使用、なければ従来の Verdict ベース
$hasDisposition = $verdicts.Count -gt 0 -and $verdicts[0].PSObject.Properties['RemediationDisposition']

if ($hasDisposition) {
    $remediationTargets = @($verdicts | Where-Object {
        $_.RemediationDisposition -eq 'AutoUpgrade' -or
        $_.RemediationDisposition -eq 'ManualReview' -or
        $_.RemediationDisposition -eq 'ReportOnly' -and ($_.Verdict -eq 'Compromised' -or $_.Verdict -eq 'Vulnerable')
    })
} else {
    $remediationTargets = @($verdicts | Where-Object { $_.Verdict -eq 'Compromised' })
}

$highIocs = @($iocs | Where-Object { $_.Severity -eq 'High' })

if ($remediationTargets.Count -eq 0 -and $highIocs.Count -eq 0) {
    Write-Host '[INFO] 修復が必要なプロジェクトも高リスク IOC も検出されていません。修復は不要です。' -ForegroundColor Green
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
        [string]$Command,
        [string]$Phase = '',
        [string]$Mode  = ''
    )
    [void]$actions.Add([pscustomobject]@{
        Category    = $Category
        Target      = $Target
        Description = $Description
        Command     = $Command
        Phase       = $Phase
        Mode        = $Mode
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
    Plan-Action -Category 'IOC-File' -Target $programDataWt -Description 'RAT ペイロード wt.exe を削除' -Command "Remove-Item -LiteralPath '$programDataWt' -Force" -Phase 'SystemIOC'
}
if (Test-Path $programDataBat) {
    Plan-Action -Category 'IOC-File' -Target $programDataBat -Description 'RAT 永続化バッチ system.bat を削除' -Command "Remove-Item -LiteralPath '$programDataBat' -Force" -Phase 'SystemIOC'
}
try {
    $regValue = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction Stop
    if ($regValue) {
        Plan-Action -Category 'IOC-Registry' -Target "$regKeyPath\$regValueName" -Description 'RAT 永続化レジストリキーを削除' -Command "Remove-ItemProperty -Path '$regKeyPath' -Name '$regValueName' -Force" -Phase 'SystemIOC'
    }
} catch {}

# --- プロジェクトレベル修復 ---
foreach ($proj in $remediationTargets) {
    $path = $proj.Path
    $projOwnership = if ($proj.PSObject.Properties['Ownership']) { $proj.Ownership } else { 'Unknown' }
    $mode = Get-RepoRemediationMode `
        -Ownership $projOwnership `
        -AllowThirdPartyRepoMutation:$AllowThirdPartyRepoMutation `
        -AllowUnknownRepoMutation:$AllowUnknownRepoMutation

    switch ($mode) {
        'OwnedFull' {
            # --- IOC パッケージ削除 ---
            $plainCryptoDir = Join-Path $path 'node_modules\plain-crypto-js'
            if (Test-Path $plainCryptoDir) {
                Plan-Action -Category 'Package' -Target $plainCryptoDir -Description "plain-crypto-js ディレクトリを削除" -Command "Remove-Item -LiteralPath '$plainCryptoDir' -Recurse -Force" -Phase 'IOC-Cleanup' -Mode $mode
            }
            foreach ($relPkg in @('node_modules\@shadanai\openclaw', 'node_modules\@qqbrowser\openclaw-qbot')) {
                $relDir = Join-Path $path $relPkg
                if (Test-Path $relDir) {
                    Plan-Action -Category 'Package' -Target $relDir -Description "関連侵害パッケージを削除" -Command "Remove-Item -LiteralPath '$relDir' -Recurse -Force" -Phase 'IOC-Cleanup' -Mode $mode
                }
            }

            # --- axios remediation (lockfile-first + exact pin) ---
            $pkgJsonPath = Join-Path $path 'package.json'
            if (Test-Path $pkgJsonPath) {
                $projVer = @($versions | Where-Object { $_.RepoPath -eq $path })
                foreach ($pv in $projVer) {
                    $targetVersion = Get-RecommendedAxiosVersion -ResolvedAxiosVersion $pv.AxiosVersion

                    if ($null -ne $targetVersion) {
                        # Phase A: metadata-only (lockfile + package.json の exact pin)
                        Plan-Action -Category 'LockfileUpdate' `
                            -Target $path `
                            -Description "axios を exact pin で安全版 ($targetVersion) に更新し、lockfile のみ更新" `
                            -Command "Push-Location '$path'; npm install axios@$targetVersion --save-exact --package-lock-only --ignore-scripts 2>&1; Pop-Location" `
                            -Phase 'MetadataOnly' -Mode $mode

                        # Phase B: clean reinstall
                        Plan-Action -Category 'Reinstall' `
                            -Target $path `
                            -Description "node_modules を削除して npm ci --ignore-scripts で再構築" `
                            -Command "Push-Location '$path'; if (Test-Path '.\node_modules') { Remove-Item -LiteralPath '.\node_modules' -Recurse -Force }; npm ci --ignore-scripts 2>&1; Pop-Location" `
                            -Phase 'Reinstall' -Mode $mode

                        # Phase C: verify
                        Plan-Action -Category 'Verify' `
                            -Target $path `
                            -Description "npm registry signatures を検証" `
                            -Command "Push-Location '$path'; npm audit signatures 2>&1; Pop-Location" `
                            -Phase 'Verify' -Mode $mode
                    } else {
                        # 0.x: 自動 remediation しない — manual-only
                        Plan-Action -Category 'Info' `
                            -Target $path `
                            -Description ('[0.x] backport 未確定のため自動 remediation を行いません。maintainer への確認または 1.x への移行を検討してください (検出バージョン: ' + $pv.AxiosVersion + ')') `
                            -Command "Write-Host '[INFO] 0.x requires manual decision: $path'" `
                            -Phase 'ReportOnly' -Mode $mode
                    }
                }
            }
        }

        'ExternalLocalCleanup' {
            # opt-in された外部リポジトリ: node_modules 配下の IOC 除去のみ
            $plainCryptoDir = Join-Path $path 'node_modules\plain-crypto-js'
            if (Test-Path $plainCryptoDir) {
                Plan-Action -Category 'Package' -Target $plainCryptoDir -Description '[外部 repo / opt-in] plain-crypto-js ディレクトリを削除' -Command "Remove-Item -LiteralPath '$plainCryptoDir' -Recurse -Force" -Phase 'IOC-Cleanup' -Mode $mode
            }
            foreach ($relPkg in @('node_modules\@shadanai\openclaw', 'node_modules\@qqbrowser\openclaw-qbot')) {
                $relDir = Join-Path $path $relPkg
                if (Test-Path $relDir) {
                    Plan-Action -Category 'Package' -Target $relDir -Description '[外部 repo / opt-in] 関連侵害パッケージを削除' -Command "Remove-Item -LiteralPath '$relDir' -Recurse -Force" -Phase 'IOC-Cleanup' -Mode $mode
                }
            }

            Plan-Action -Category 'Info' `
                -Target $path `
                -Description '[外部 repo / opt-in] node_modules 配下のローカル cleanup のみ実行。package.json / lockfile は変更しません' `
                -Command "Write-Host '[INFO] external repo local cleanup mode: $path'" `
                -Phase 'ReportOnly' -Mode $mode
        }

        'ReportOnly' {
            # デフォルト: 外部/不明リポジトリには一切変更しない
            Plan-Action -Category 'Info' `
                -Target $path `
                -Description ('[外部 repo] 自動変更は行いません。手順案内のみ生成します (所有者: ' + $projOwnership + ')') `
                -Command "Write-Host '[INFO] report-only: $path'" `
                -Phase 'ReportOnly' -Mode $mode
        }
    }
}

# --- npm cache clean ---
$hasActualActions = @($actions | Where-Object { $_.Category -ne 'Info' }).Count -gt 0
if ($hasActualActions) {
    Plan-Action -Category 'Cache' -Target 'npm cache' -Description 'npm キャッシュをクリア（侵害版の再インストール防止）' -Command 'npm cache clean --force 2>&1' -Phase 'Cleanup'
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

# --- 外部/不明リポジトリ向け手順案内 ---
$externalProjects = @($remediationTargets | Where-Object {
    $own = if ($_.PSObject.Properties['Ownership']) { $_.Ownership } else { 'Unknown' }
    $own -ne 'Mine'
})

if ($externalProjects.Count -gt 0) {
    $nextManualNum = if ($highIocs.Count -gt 0) { 6 } else { 5 }
    [void]$manualActions.Add('[ ] ' + $nextManualNum + '. 外部/不明リポジトリの手動対応')
    [void]$manualActions.Add('')
    [void]$manualActions.Add('     以下のリポジトリは自動修復の対象外です。')
    [void]$manualActions.Add('     upstream の maintainer に報告し、以下の手順で対応してください。')
    [void]$manualActions.Add('')
    foreach ($ep in $externalProjects) {
        $epOwn = if ($ep.PSObject.Properties['Ownership']) { $ep.Ownership } else { 'Unknown' }
        [void]$manualActions.Add('     [' + $epOwn + '] ' + $ep.Path)
    }
    [void]$manualActions.Add('')
    [void]$manualActions.Add('     対応手順:')
    [void]$manualActions.Add('       1. upstream maintainer に侵害を報告')
    [void]$manualActions.Add('       2. node_modules を全削除: Remove-Item -LiteralPath .\node_modules -Recurse -Force')
    [void]$manualActions.Add('       3. npm ci --ignore-scripts で再インストール')
    [void]$manualActions.Add('       4. それでも侵害版が入る場合は利用停止を検討')
    [void]$manualActions.Add('')

    $nextManualNum++
    [void]$manualActions.Add('[ ] ' + $nextManualNum + '. 0.x 系 axios を使用しているプロジェクトの対応')
    [void]$manualActions.Add('')
    [void]$manualActions.Add('     0.x 系は backport の修正版が未確定のため、自動 remediation は行いません。')
    [void]$manualActions.Add('     以下のいずれかで対応してください:')
    [void]$manualActions.Add('       - upstream maintainer に確認し、修正版がリリースされたら更新')
    [void]$manualActions.Add('       - axios 1.x 系への移行を検討')
    [void]$manualActions.Add('       - 侵害版 (0.30.4) がインストールされていないことを確認し、当面は現行版を維持')
    [void]$manualActions.Add('')
}

# ============================================================
# ドライラン表示
# ============================================================
$dryRunReport = New-Object System.Collections.ArrayList
[void]$dryRunReport.Add('========================================')
[void]$dryRunReport.Add('  修復アクション一覧（ドライラン）')
[void]$dryRunReport.Add("  生成日時: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$dryRunReport.Add('')
[void]$dryRunReport.Add('  Remediation Policy:')
[void]$dryRunReport.Add('    - 1.x 系: 自動 remediation target = 1.15.0 (exact pin)')
[void]$dryRunReport.Add('    - 0.x 系: 自動 remediation なし (manual-only)')
[void]$dryRunReport.Add("    - ThirdParty repo mutation: $(if ($AllowThirdPartyRepoMutation) { 'Enabled' } else { 'Disabled (default)' })")
[void]$dryRunReport.Add("    - Unknown repo mutation:    $(if ($AllowUnknownRepoMutation) { 'Enabled' } else { 'Disabled (default)' })")
[void]$dryRunReport.Add('========================================')
[void]$dryRunReport.Add('')

# フェーズごとにグループ表示
$phaseOrder = @('SystemIOC', 'IOC-Cleanup', 'MetadataOnly', 'Reinstall', 'Verify', 'ReportOnly', 'Cleanup')
$phaseLabels = @{
    'SystemIOC'    = 'システムレベル IOC 除去'
    'IOC-Cleanup'  = 'パッケージレベル IOC 除去'
    'MetadataOnly' = 'Phase A: lockfile + exact pin 更新'
    'Reinstall'    = 'Phase B: クリーン再構築'
    'Verify'       = 'Phase C: 署名検証'
    'ReportOnly'   = 'レポートのみ（自動変更なし）'
    'Cleanup'      = 'キャッシュクリーンアップ'
}

$actionIndex = 0
foreach ($phase in $phaseOrder) {
    $phaseActions = @($actions | Where-Object { $_.Phase -eq $phase })
    if ($phaseActions.Count -eq 0) { continue }

    $label = if ($phaseLabels.ContainsKey($phase)) { $phaseLabels[$phase] } else { $phase }
    [void]$dryRunReport.Add("  --- $label ---")
    [void]$dryRunReport.Add('')

    foreach ($a in $phaseActions) {
        $actionIndex++
        $modeTag = if ($a.Mode) { " [$($a.Mode)]" } else { '' }
        [void]$dryRunReport.Add("  [$actionIndex] $($a.Category)$modeTag")
        [void]$dryRunReport.Add("      対象: $($a.Target)")
        [void]$dryRunReport.Add("      操作: $($a.Description)")
        [void]$dryRunReport.Add('')
    }
}

[void]$dryRunReport.Add("  合計: $($actions.Count) 件のアクション (うち自動実行: $((@($actions | Where-Object { $_.Category -ne 'Info' }).Count)) 件)")
[void]$dryRunReport.Add('')

$dryRunReport | Out-File -FilePath $dryRunTxt -Encoding UTF8

# コンソール表示
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  修復アクション一覧' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

$actionIndex = 0
foreach ($phase in $phaseOrder) {
    $phaseActions = @($actions | Where-Object { $_.Phase -eq $phase })
    if ($phaseActions.Count -eq 0) { continue }

    $label = if ($phaseLabels.ContainsKey($phase)) { $phaseLabels[$phase] } else { $phase }
    Write-Host "  --- $label ---" -ForegroundColor Magenta
    Write-Host ''

    foreach ($a in $phaseActions) {
        $actionIndex++
        $color = if ($a.Category -eq 'Info') { 'DarkGray' } else { 'Yellow' }
        Write-Host "  [$actionIndex] $($a.Description)" -ForegroundColor $color
        Write-Host "      対象: $($a.Target)"
        Write-Host ''
    }
}

Write-Host "  合計: $($actions.Count) 件のアクション (うち自動実行: $((@($actions | Where-Object { $_.Category -ne 'Info' }).Count)) 件)" -ForegroundColor Cyan
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
$skipCount = 0

foreach ($a in $actions) {
    # Info カテゴリは実行せずスキップ
    if ($a.Category -eq 'Info') {
        $a.Status = 'Skipped'
        $skipCount++
        Write-Host "  スキップ: $($a.Description)" -ForegroundColor DarkGray
        Log-Action -Category $a.Category -Target $a.Target -Description $a.Description -Status 'Skipped' -Detail 'レポートのみ'
        continue
    }

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
    "Failed             : $failCount",
    "Skipped            : $skipCount",
    '',
    'Remediation Policy:',
    '  1.x target       : 1.15.0 (exact pin)',
    '  0.x target       : manual-only (backport pending)',
    "  ThirdParty repos : $(if ($AllowThirdPartyRepoMutation) { 'LocalCleanup (opt-in)' } else { 'ReportOnly (default)' })",
    "  Unknown repos    : $(if ($AllowUnknownRepoMutation) { 'LocalCleanup (opt-in)' } else { 'ReportOnly (default)' })"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  修復結果' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  成功: $successCount 件" -ForegroundColor Green
Write-Host "  失敗: $failCount 件" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  スキップ: $skipCount 件 (レポートのみ)" -ForegroundColor DarkGray
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
