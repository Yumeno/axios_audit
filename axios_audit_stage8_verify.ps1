[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$postVerdictTxt = Join-Path $OutputDir 'PostRemediationVerdict.txt'
$diffCsv        = Join-Path $OutputDir 'BeforeAfterDiff.csv'
$summaryTxt     = Join-Path $OutputDir 'Stage8_Summary.txt'
$transcript     = Join-Path $OutputDir 'Stage8_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

# ============================================================
# 修復前の判定結果を保存
# ============================================================
$beforeVerdictCsv = Join-Path $OutputDir 'AuditVerdict.csv'
$beforeIocCsv     = Join-Path $OutputDir 'IocFindings.csv'

if (-not (Test-Path $beforeVerdictCsv)) {
    Write-Host '[ERROR] AuditVerdict.csv が見つかりません。先に Stage 6 を実行してください。' -ForegroundColor Red
    Stop-Transcript | Out-Null
    return
}

$beforeVerdicts = Import-Csv $beforeVerdictCsv
$beforeIocs     = if (Test-Path $beforeIocCsv) { Import-Csv $beforeIocCsv } else { @() }

$beforeCompromised = @($beforeVerdicts | Where-Object { $_.Verdict -eq 'Compromised' }).Count
$beforeVulnerable  = @($beforeVerdicts | Where-Object { $_.Verdict -eq 'Vulnerable' }).Count
$beforeNeedsReview = @($beforeVerdicts | Where-Object { $_.Verdict -eq 'NeedsReview' }).Count
$beforeClean       = @($beforeVerdicts | Where-Object { $_.Verdict -eq 'Clean' }).Count
$beforeHighIocs    = @($beforeIocs | Where-Object { $_.Severity -eq 'High' }).Count

Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  修復後の検証を開始します' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host '  修復前の状態:' -ForegroundColor Yellow
Write-Host "    侵害確定: $beforeCompromised / 脆弱性: $beforeVulnerable / 要確認: $beforeNeedsReview / 白: $beforeClean / IOC: $beforeHighIocs"
Write-Host ''

# ============================================================
# 修復前ファイルをバックアップ（上書き防止）
# ============================================================
$backupDir = Join-Path $OutputDir 'PreRemediation_Backup'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

foreach ($f in @('ManifestFindings.csv', 'AxiosVersionFindings.csv', 'IocFindings.csv', 'AuditVerdict.csv', 'AuditVerdict.txt')) {
    $src = Join-Path $OutputDir $f
    if (Test-Path $src) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $backupDir $f) -Force
    }
}

Write-Host '  修復前の結果ファイルをバックアップしました。' -ForegroundColor Green
Write-Host "    $backupDir"
Write-Host ''

# ============================================================
# Stage 2〜4 を再実行
# ============================================================
$repoCsv = Join-Path $OutputDir 'RepoInventory.csv'
if (-not (Test-Path $repoCsv)) {
    Write-Host '[ERROR] RepoInventory.csv が見つかりません。' -ForegroundColor Red
    Stop-Transcript | Out-Null
    return
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Stage 2 再実行
$stage2Script = Join-Path $scriptDir 'axios_audit_stage2_scan_manifests.ps1'
if (Test-Path $stage2Script) {
    Write-Host '  Stage 2（manifest 確認）を再実行中...' -ForegroundColor Cyan
    try {
        & $stage2Script -RepoInventoryCsv $repoCsv -OutputDir $OutputDir
        Write-Host '  Stage 2 完了。' -ForegroundColor Green
    } catch {
        Write-Host "  Stage 2 でエラー: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [WARN] Stage 2 スクリプトが見つかりません: $stage2Script" -ForegroundColor Yellow
}

# Stage 3 再実行
$stage3Script = Join-Path $scriptDir 'axios_audit_stage3_check_versions.ps1'
if (Test-Path $stage3Script) {
    Write-Host '  Stage 3（バージョン確認）を再実行中...' -ForegroundColor Cyan
    try {
        & $stage3Script -RepoInventoryCsv $repoCsv -OutputDir $OutputDir
        Write-Host '  Stage 3 完了。' -ForegroundColor Green
    } catch {
        Write-Host "  Stage 3 でエラー: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [WARN] Stage 3 スクリプトが見つかりません: $stage3Script" -ForegroundColor Yellow
}

# Stage 4 再実行
$stage4Script = Join-Path $scriptDir 'axios_audit_stage4_logs_ioc.ps1'
if (Test-Path $stage4Script) {
    Write-Host '  Stage 4（IOC 確認）を再実行中...' -ForegroundColor Cyan
    try {
        & $stage4Script -OutputDir $OutputDir
        Write-Host '  Stage 4 完了。' -ForegroundColor Green
    } catch {
        Write-Host "  Stage 4 でエラー: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [WARN] Stage 4 スクリプトが見つかりません: $stage4Script" -ForegroundColor Yellow
}

# Stage 6 再実行（判定レポート再生成）
$stage6Script = Join-Path $scriptDir 'axios_audit_stage6_verdict.ps1'
if (Test-Path $stage6Script) {
    Write-Host '  Stage 6（判定レポート）を再生成中...' -ForegroundColor Cyan
    try {
        & $stage6Script -OutputDir $OutputDir
        Write-Host '  Stage 6 完了。' -ForegroundColor Green
    } catch {
        Write-Host "  Stage 6 でエラー: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [WARN] Stage 6 スクリプトが見つかりません: $stage6Script" -ForegroundColor Yellow
}

# ============================================================
# 修復後の判定結果を読み込み
# ============================================================
$afterVerdictCsv = Join-Path $OutputDir 'AuditVerdict.csv'
$afterIocCsv     = Join-Path $OutputDir 'IocFindings.csv'

$afterVerdicts = if (Test-Path $afterVerdictCsv) { Import-Csv $afterVerdictCsv } else { @() }
$afterIocs     = if (Test-Path $afterIocCsv)     { Import-Csv $afterIocCsv }     else { @() }

$afterCompromised = @($afterVerdicts | Where-Object { $_.Verdict -eq 'Compromised' }).Count
$afterVulnerable  = @($afterVerdicts | Where-Object { $_.Verdict -eq 'Vulnerable' }).Count
$afterNeedsReview = @($afterVerdicts | Where-Object { $_.Verdict -eq 'NeedsReview' }).Count
$afterClean       = @($afterVerdicts | Where-Object { $_.Verdict -eq 'Clean' }).Count
$afterHighIocs    = @($afterIocs | Where-Object { $_.Severity -eq 'High' }).Count

# ============================================================
# 差分レポート生成
# ============================================================
$diffResults = New-Object System.Collections.ArrayList

# Before の全プロジェクトと After を比較
$afterLookup = @{}
foreach ($av in $afterVerdicts) { $afterLookup[$av.Path] = $av }

foreach ($bv in $beforeVerdicts) {
    $afterEntry = $afterLookup[$bv.Path]
    $afterVerdict = if ($afterEntry) { $afterEntry.Verdict } else { 'NotFound' }
    $changed = $bv.Verdict -ne $afterVerdict

    [void]$diffResults.Add([pscustomobject]@{
        Path          = $bv.Path
        BeforeVerdict = $bv.Verdict
        AfterVerdict  = $afterVerdict
        Changed       = $changed
        BeforeReasons = $bv.Reasons
        AfterReasons  = if ($afterEntry) { $afterEntry.Reasons } else { '' }
    })
}

$diffResults | Export-Csv -Path $diffCsv -NoTypeInformation -Encoding UTF8

# ============================================================
# テキストレポート
# ============================================================
$report = New-Object System.Collections.ArrayList

[void]$report.Add('========================================')
[void]$report.Add('  修復後の検証レポート')
[void]$report.Add("  生成日時: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$report.Add('========================================')
[void]$report.Add('')

[void]$report.Add('■ 修復前 → 修復後')
[void]$report.Add("  - 侵害確定: $beforeCompromised 件 → $afterCompromised 件  $(if ($afterCompromised -eq 0 -and $beforeCompromised -gt 0) { '✓ 解消' } elseif ($afterCompromised -gt 0) { '✗ 残存' } else { '-' })")
[void]$report.Add("  - 脆弱性:   $beforeVulnerable 件 → $afterVulnerable 件  $(if ($afterVulnerable -eq 0 -and $beforeVulnerable -gt 0) { '✓ 解消' } elseif ($afterVulnerable -gt 0) { '✗ 残存' } else { '-' })")
[void]$report.Add("  - 要確認:   $beforeNeedsReview 件 → $afterNeedsReview 件  $(if ($afterNeedsReview -le $beforeNeedsReview) { '✓' } else { '✗ 増加' })")
[void]$report.Add("  - 白寄り:   $beforeClean 件 → $afterClean 件")
[void]$report.Add("  - IOC:      $beforeHighIocs 件 → $afterHighIocs 件  $(if ($afterHighIocs -eq 0 -and $beforeHighIocs -gt 0) { '✓ 解消' } elseif ($afterHighIocs -gt 0) { '✗ 残存' } else { '-' })")
[void]$report.Add('')

# 変化したプロジェクト
$changedProjects = @($diffResults | Where-Object { $_.Changed -eq $true })
if ($changedProjects.Count -gt 0) {
    [void]$report.Add('■ 判定が変化したプロジェクト')
    [void]$report.Add('')
    foreach ($cp in $changedProjects) {
        [void]$report.Add("  $($cp.Path)")
        [void]$report.Add("    修復前: $($cp.BeforeVerdict) → 修復後: $($cp.AfterVerdict)")
        [void]$report.Add('')
    }
}

# 残存する手動対応
$manualTxt = Join-Path $OutputDir 'ManualActions.txt'
if (Test-Path $manualTxt) {
    [void]$report.Add('■ 残存する手動対応')
    [void]$report.Add("  → $manualTxt を確認してください。")
    [void]$report.Add('')
}

# 結論
[void]$report.Add('■ 結論')
[void]$report.Add('')
if ($afterCompromised -eq 0 -and $afterVulnerable -eq 0 -and $afterHighIocs -eq 0) {
    [void]$report.Add('  → 自動修復は完了しました。侵害確定・脆弱性・高リスク IOC はゼロです。')
    if (Test-Path $manualTxt) {
        [void]$report.Add('  → 手動対応チェックリストが残っています。')
        [void]$report.Add('    すべてのチェック項目を完了すれば監査終了です。')
    }
} else {
    [void]$report.Add('  → まだ解消されていない項目があります。')
    [void]$report.Add('  → AuditVerdict.txt を確認し、追加対応を実施してください。')
}
[void]$report.Add('')
[void]$report.Add("修復前バックアップ: $backupDir")

$report | Out-File -FilePath $postVerdictTxt -Encoding UTF8

# サマリ
@(
    '=== Stage 8 Summary ===',
    "OutputDir                 : $OutputDir",
    "PostRemediationVerdict.txt: $postVerdictTxt",
    "BeforeAfterDiff.csv       : $diffCsv",
    "Before_Compromised        : $beforeCompromised",
    "After_Compromised         : $afterCompromised",
    "Before_Vulnerable         : $beforeVulnerable",
    "After_Vulnerable          : $afterVulnerable",
    "Before_HighIOC            : $beforeHighIocs",
    "After_HighIOC             : $afterHighIocs"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

# コンソール表示
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  修復後の検証結果' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  侵害確定: $beforeCompromised → $afterCompromised" -ForegroundColor $(if ($afterCompromised -eq 0) { 'Green' } else { 'Red' })
Write-Host "  脆弱性:   $beforeVulnerable → $afterVulnerable" -ForegroundColor $(if ($afterVulnerable -eq 0) { 'Green' } else { 'Yellow' })
Write-Host "  IOC:      $beforeHighIocs → $afterHighIocs" -ForegroundColor $(if ($afterHighIocs -eq 0) { 'Green' } else { 'Red' })
Write-Host "  要確認:   $beforeNeedsReview → $afterNeedsReview" -ForegroundColor $(if ($afterNeedsReview -eq 0) { 'Green' } else { 'Yellow' })
Write-Host ''
if ($afterCompromised -eq 0 -and $afterVulnerable -eq 0 -and $afterHighIocs -eq 0) {
    Write-Host '  [OK] 自動修復は完了しました。' -ForegroundColor Green
    Write-Host '       手動対応チェックリストを確認して監査を完了してください。' -ForegroundColor Yellow
} else {
    Write-Host '  [!] まだ解消されていない項目があります。' -ForegroundColor Red
}
Write-Host ''
Write-Host "  詳細: $postVerdictTxt"
Write-Host ''

Stop-Transcript | Out-Null
