<#
.SYNOPSIS
  Axios / npm 監査スクリプト一括実行

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1
  powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -SkipWSL
  powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -ScanPaths "C:\Users\me\projects","D:\repos"
  powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -DryRunOnly
  powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -AutoRemediate
  powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 4 -OutputDir .\AxiosNpmAudit_20260402_220000
#>
[CmdletBinding()]
param(
    [string[]]$ScanPaths,
    [switch]$SkipWSL,
    [switch]$AutoRemediate,
    [switch]$DryRunOnly,
    [switch]$AllowThirdPartyRepoMutation,
    [switch]$AllowUnknownRepoMutation,
    [int]$StartFrom = 1,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# OutputDir の決定
# StartFrom のバリデーション
if ($StartFrom -lt 1 -or $StartFrom -gt 8) {
    Write-Host '  [ERROR] -StartFrom は 1〜8 の範囲で指定してください。' -ForegroundColor Red
    exit 1
}

if ($OutputDir) {
    # 明示指定あり
    $outputDir = [System.IO.Path]::GetFullPath($OutputDir)
    if (-not (Test-Path $outputDir)) {
        Write-Host ('  [ERROR] 指定された OutputDir が見つかりません: ' + $outputDir) -ForegroundColor Red
        exit 1
    }
} elseif ($StartFrom -gt 1) {
    # 途中再開だが OutputDir 未指定 → 最新の監査フォルダを自動検出
    $latest = Get-ChildItem ((Get-Location).Path) -Directory |
        Where-Object { $_.Name -like 'AxiosNpmAudit_*' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($latest) {
        $outputDir = $latest.FullName
        Write-Host ('  -OutputDir 未指定のため、最新の監査フォルダを使用: ' + $outputDir) -ForegroundColor Yellow
    } else {
        Write-Host '  [ERROR] -StartFrom 2 以降を指定する場合は -OutputDir で既存の監査フォルダを指定するか、' -ForegroundColor Red
        Write-Host '          カレントディレクトリに AxiosNpmAudit_* フォルダが必要です。' -ForegroundColor Red
        exit 1
    }
} else {
    # Stage 1 から新規開始
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputDir = Join-Path ((Get-Location).Path) "AxiosNpmAudit_$timestamp"
}

Write-Host ''
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host '  Axios / npm 監査 一括実行スクリプト' -ForegroundColor Cyan
Write-Host ('  開始: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host ('  スクリプト格納先: ' + $scriptDir)
Write-Host ('  結果出力先:       ' + $outputDir)
if ($StartFrom -gt 1) {
    Write-Host ('  再開ステージ:     Stage ' + $StartFrom + ' から') -ForegroundColor Yellow
}
if ($ScanPaths -and $ScanPaths.Count -gt 0) {
    Write-Host ('  走査対象:         ' + ($ScanPaths -join ', ')) -ForegroundColor Cyan
} elseif ($StartFrom -le 1) {
    Write-Host '  走査対象:         全ローカルドライブ'
}
Write-Host ''

# ============================================================
# ヘルパー
# ============================================================
$stageResults = New-Object System.Collections.ArrayList
$overallStart = Get-Date

function Write-Sep {
    Write-Host '--------------------------------------------------------' -ForegroundColor DarkGray
}

function Run-Stage {
    param(
        [int]$Num,
        [string]$Label,
        [string]$FileName,
        [hashtable]$Params
    )

    Write-Sep
    Write-Host ('  Stage ' + $Num + ' - ' + $Label) -ForegroundColor Cyan
    Write-Sep

    $filePath = Join-Path $scriptDir $FileName
    if (-not (Test-Path $filePath)) {
        Write-Host '  [SKIP] スクリプトが見つかりません' -ForegroundColor Yellow
        [void]$stageResults.Add([pscustomobject]@{
            Stage = $Num; Name = $Label; Status = 'Skipped'; Duration = ''; Detail = 'ファイル未検出'
        })
        return $false
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $filePath @Params
        $sw.Stop()
        $dur = $sw.Elapsed.ToString('mm\:ss')
        Write-Host ('  [OK] 完了 (' + $dur + ')') -ForegroundColor Green
        Write-Host ''
        [void]$stageResults.Add([pscustomobject]@{
            Stage = $Num; Name = $Label; Status = 'OK'; Duration = $dur; Detail = ''
        })
        return $true
    } catch {
        $sw.Stop()
        $dur = $sw.Elapsed.ToString('mm\:ss')
        $errMsg = $_.Exception.Message
        Write-Host ('  [ERROR] ' + $errMsg) -ForegroundColor Red
        Write-Host ''
        [void]$stageResults.Add([pscustomobject]@{
            Stage = $Num; Name = $Label; Status = 'Error'; Duration = $dur; Detail = $errMsg
        })
        return $false
    }
}

# ============================================================
# repoCsv のパス（Stage 2, 3 で使用）
# ============================================================
$repoCsv = Join-Path $outputDir 'RepoInventory.csv'

# ============================================================
# Stage 1
# ============================================================
if ($StartFrom -le 1) {
    $stage1Params = @{ OutputDir = $outputDir }
    if ($ScanPaths -and $ScanPaths.Count -gt 0) {
        $stage1Params['ScanPaths'] = $ScanPaths
    }
    $ok1 = Run-Stage -Num 1 -Label 'プロジェクト棚卸し' -FileName 'axios_audit_stage1_discover_repos.ps1' -Params $stage1Params

    if (-not $ok1) {
        Write-Host '  Stage 1 が失敗したため、監査を中断します。' -ForegroundColor Red
        exit 1
    }

    if (-not (Test-Path $repoCsv)) {
        Write-Host '  [ERROR] RepoInventory.csv が生成されませんでした。' -ForegroundColor Red
        exit 1
    }

    $repoCount = @(Import-Csv $repoCsv).Count
    Write-Host ('  -> ' + $repoCount + ' 件のプロジェクト候補を検出') -ForegroundColor White
    Write-Host ''
} else {
    # 途中再開: RepoInventory.csv の存在確認
    if (-not (Test-Path $repoCsv)) {
        Write-Host ('  [ERROR] RepoInventory.csv が見つかりません: ' + $repoCsv) -ForegroundColor Red
        Write-Host '  Stage 1 を先に実行してください。' -ForegroundColor Red
        exit 1
    }
    Write-Host ('  Stage 1 スキップ（既存の RepoInventory.csv を使用）') -ForegroundColor DarkGray
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 1; Name = 'プロジェクト棚卸し'; Status = 'Skipped'; Duration = ''; Detail = '途中再開'
    })
}

# ============================================================
# Stage 2
# ============================================================
if ($StartFrom -le 2) {
    Run-Stage -Num 2 -Label 'lockfile / manifest 確認' -FileName 'axios_audit_stage2_scan_manifests.ps1' -Params @{
        RepoInventoryCsv = $repoCsv
        OutputDir = $outputDir
    } | Out-Null
} else {
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 2; Name = 'lockfile / manifest 確認'; Status = 'Skipped'; Duration = ''; Detail = '途中再開'
    })
}

# ============================================================
# Stage 3
# ============================================================
if ($StartFrom -le 3) {
    Run-Stage -Num 3 -Label 'Axios 実バージョン確認' -FileName 'axios_audit_stage3_check_versions.ps1' -Params @{
        RepoInventoryCsv = $repoCsv
        OutputDir = $outputDir
    } | Out-Null
} else {
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 3; Name = 'Axios 実バージョン確認'; Status = 'Skipped'; Duration = ''; Detail = '途中再開'
    })
}

# ============================================================
# Stage 4
# ============================================================
if ($StartFrom -le 4) {
    Run-Stage -Num 4 -Label 'npm ログ + IOC 確認' -FileName 'axios_audit_stage4_logs_ioc.ps1' -Params @{
        OutputDir = $outputDir
    } | Out-Null
} else {
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 4; Name = 'npm ログ + IOC 確認'; Status = 'Skipped'; Duration = ''; Detail = '途中再開'
    })
}

# ============================================================
# Stage 5 (WSL)
# ============================================================
if ($StartFrom -le 5) {
    if ($SkipWSL) {
        Write-Sep
        Write-Host '  Stage 5 - WSL 確認 [SKIP] -SkipWSL が指定されました' -ForegroundColor Yellow
        Write-Sep
        Write-Host ''
        [void]$stageResults.Add([pscustomobject]@{
            Stage = 5; Name = 'WSL 確認'; Status = 'Skipped'; Duration = ''; Detail = '-SkipWSL 指定'
        })
    } else {
        $wslOk = $false
        try {
            $wslList = & wsl.exe -l -q 2>$null
            if ($wslList) { $wslOk = $true }
        } catch {}

        if ($wslOk) {
            Run-Stage -Num 5 -Label 'WSL 確認' -FileName 'axios_audit_stage5_wsl_optional.ps1' -Params @{
                OutputDir = $outputDir
            } | Out-Null
        } else {
            Write-Sep
            Write-Host '  Stage 5 - WSL 確認 [SKIP] WSL が検出されませんでした' -ForegroundColor Yellow
            Write-Sep
            Write-Host ''
            [void]$stageResults.Add([pscustomobject]@{
                Stage = 5; Name = 'WSL 確認'; Status = 'Skipped'; Duration = ''; Detail = 'WSL 未検出'
            })
        }
    }
} else {
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 5; Name = 'WSL 確認'; Status = 'Skipped'; Duration = ''; Detail = '途中再開'
    })
}

# ============================================================
# Stage 6
# ============================================================
if ($StartFrom -le 6) {
    $ok6 = Run-Stage -Num 6 -Label '自動判定レポート生成' -FileName 'axios_audit_stage6_verdict.ps1' -Params @{
        OutputDir = $outputDir
    }
} else {
    $ok6 = $true
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 6; Name = '自動判定レポート生成'; Status = 'Skipped'; Duration = ''; Detail = '途中再開'
    })
}

# ============================================================
# Stage 7/8 判断
# ============================================================
$needsFix = $false
$verdictCsv = Join-Path $outputDir 'AuditVerdict.csv'
$iocCsv = Join-Path $outputDir 'IocFindings.csv'

$needsVulnFix = $false
if ($ok6 -and (Test-Path $verdictCsv)) {
    $vRows = Import-Csv $verdictCsv
    $compCount = @($vRows | Where-Object { $_.Verdict -eq 'Compromised' }).Count
    $vulnCount = @($vRows | Where-Object { $_.Verdict -eq 'Vulnerable' }).Count

    $iocRows = if (Test-Path $iocCsv) { Import-Csv $iocCsv } else { @() }
    $hiCount = @($iocRows | Where-Object { $_.Severity -eq 'High' }).Count

    if ($compCount -gt 0 -or $hiCount -gt 0) { $needsFix = $true }
    if ($vulnCount -gt 0) { $needsVulnFix = $true }
}

# -StartFrom 7 or 8 の場合は、オプションに関係なく実行する
$explicitStage7 = ($StartFrom -eq 7)
$explicitStage8 = ($StartFrom -eq 8)

if ($needsFix -or $needsVulnFix -or $explicitStage7 -or $explicitStage8) {
    if ($needsFix) {
        Write-Host '========================================================' -ForegroundColor Red
        Write-Host '  侵害が検出されました' -ForegroundColor Red
        Write-Host '========================================================' -ForegroundColor Red
        Write-Host ''
    } elseif ($needsVulnFix) {
        Write-Host '========================================================' -ForegroundColor Yellow
        Write-Host '  既知の脆弱性を持つ axios バージョンが検出されました' -ForegroundColor Yellow
        Write-Host '========================================================' -ForegroundColor Yellow
        Write-Host ''
    }

    # Stage 7 共通パラメータ
    $stage7Params = @{
        OutputDir = $outputDir
        AllowThirdPartyRepoMutation = $AllowThirdPartyRepoMutation
        AllowUnknownRepoMutation    = $AllowUnknownRepoMutation
    }

    if ($DryRunOnly) {
        # ドライランのみ
        $stage7Params['DryRun'] = $true
        Run-Stage -Num 7 -Label '修復（ドライラン）' -FileName 'axios_audit_stage7_remediate.ps1' -Params $stage7Params | Out-Null

        Write-Host '  ドライランのみ実行しました。実際の修復は以下で実行してください。' -ForegroundColor Yellow
        Write-Host ('    powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -AutoRemediate') -ForegroundColor White
        Write-Host ''

    } elseif ($AutoRemediate -or $explicitStage7) {
        # -AutoRemediate または -StartFrom 7 の場合は実行
        $stage7Params['Force'] = $true
        $ok7 = Run-Stage -Num 7 -Label '修復実行' -FileName 'axios_audit_stage7_remediate.ps1' -Params $stage7Params
        if ($ok7 -or $explicitStage8) {
            Run-Stage -Num 8 -Label '修復後検証' -FileName 'axios_audit_stage8_verify.ps1' -Params @{
                OutputDir = $outputDir
            } | Out-Null
        }

    } elseif ($explicitStage8) {
        # -StartFrom 8 の場合は Stage 8 のみ
        Run-Stage -Num 8 -Label '修復後検証' -FileName 'axios_audit_stage8_verify.ps1' -Params @{
            OutputDir = $outputDir
        } | Out-Null

    } else {
        # デフォルト: Stage 7/8 は実行せず、手動実行コマンドを案内
        Write-Sep
        Write-Host '  Stage 7/8 - 修復は自動実行されません（安全のため）' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  侵害の詳細を AuditVerdict.txt で確認した上で、以下のコマンドで修復してください。' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '    ドライラン（何が実行されるか確認）:' -ForegroundColor White
        Write-Host ('      powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -DryRunOnly -OutputDir "' + $outputDir + '"') -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '    修復実行:' -ForegroundColor White
        Write-Host ('      powershell -ExecutionPolicy Bypass -File .\axios_audit_run_all.ps1 -StartFrom 7 -AutoRemediate -OutputDir "' + $outputDir + '"') -ForegroundColor DarkGray
        Write-Host ''
        Write-Sep
        [void]$stageResults.Add([pscustomobject]@{
            Stage = 7; Name = '修復'; Status = 'Skipped'; Duration = ''; Detail = '手動実行を推奨'
        })
        [void]$stageResults.Add([pscustomobject]@{
            Stage = 8; Name = '修復後検証'; Status = 'Skipped'; Duration = ''; Detail = '修復未実行'
        })
    }
} else {
    Write-Sep
    Write-Host '  Stage 7 - 修復 [SKIP] 侵害・脆弱性ともに未検出のため修復不要' -ForegroundColor Green
    Write-Host '  Stage 8 - 修復後検証 [SKIP] 修復不要' -ForegroundColor Green
    Write-Sep
    Write-Host ''
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 7; Name = '修復'; Status = 'Skipped'; Duration = ''; Detail = '侵害未検出'
    })
    [void]$stageResults.Add([pscustomobject]@{
        Stage = 8; Name = '修復後検証'; Status = 'Skipped'; Duration = ''; Detail = '修復不要'
    })
}

# ============================================================
# 最終サマリ
# ============================================================
$totalTime = ((Get-Date) - $overallStart).ToString('mm\:ss')

Write-Host ''
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host '  監査完了' -ForegroundColor Cyan
Write-Host ('  所要時間: ' + $totalTime) -ForegroundColor Cyan
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''

Write-Host '  Stage 実行結果:' -ForegroundColor White
foreach ($sr in $stageResults) {
    $c = switch ($sr.Status) { 'OK' { 'Green' }; 'Skipped' { 'Yellow' }; 'Error' { 'Red' } }
    $d = if ($sr.Detail) { ' - ' + $sr.Detail } else { '' }
    $t = if ($sr.Duration) { ' (' + $sr.Duration + ')' } else { '' }
    Write-Host ('    Stage ' + $sr.Stage + ' [' + $sr.Status + ']' + $t + ' ' + $sr.Name + $d) -ForegroundColor $c
}

Write-Host ''

# 判定結果サマリ
$verdictCsvFinal = Join-Path $outputDir 'AuditVerdict.csv'
$iocCsvFinal = Join-Path $outputDir 'IocFindings.csv'
if (Test-Path $verdictCsvFinal) {
    $vRowsFinal = Import-Csv $verdictCsvFinal
    $cCompromised  = @($vRowsFinal | Where-Object { $_.Verdict -eq 'Compromised' }).Count
    $cNeedsReview  = @($vRowsFinal | Where-Object { $_.Verdict -eq 'NeedsReview' }).Count
    $cHardening    = @($vRowsFinal | Where-Object { $_.Verdict -eq 'Hardening' }).Count
    $cClean        = @($vRowsFinal | Where-Object { $_.Verdict -eq 'Clean' }).Count
    $cHighIoc = 0
    if (Test-Path $iocCsvFinal) {
        $cHighIoc = @(Import-Csv $iocCsvFinal | Where-Object { $_.Severity -eq 'High' }).Count
    }

    Write-Host '  --------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '  判定結果:' -ForegroundColor Cyan
    Write-Host ''
    if ($cCompromised -eq 0 -and $cHighIoc -eq 0) {
        Write-Host '    侵害は検出されませんでした' -ForegroundColor Green
    } else {
        Write-Host '    侵害が検出されました' -ForegroundColor Red
    }
    Write-Host ''
    Write-Host "    侵害確定:   $cCompromised 件" -ForegroundColor $(if ($cCompromised -gt 0) { 'Red' } else { 'Green' })
    Write-Host "    要確認:     $cNeedsReview 件" -ForegroundColor $(if ($cNeedsReview -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "    要強化:     $cHardening 件" -ForegroundColor $(if ($cHardening -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "    対策不要:   $cClean 件" -ForegroundColor Green
    Write-Host "    システム IOC: $cHighIoc 件" -ForegroundColor $(if ($cHighIoc -gt 0) { 'Red' } else { 'Green' })
    Write-Host ''
    Write-Host '  --------------------------------------------------------' -ForegroundColor DarkGray
}

Write-Host ('  結果フォルダ: ' + $outputDir) -ForegroundColor White
Write-Host ''

$vtxt = Join-Path $outputDir 'AuditVerdict.txt'
if (Test-Path $vtxt) {
    Write-Host '  まず読むべきファイル:' -ForegroundColor Yellow
    Write-Host ('    ' + $vtxt) -ForegroundColor White
    Write-Host ''
}

$mtxt = Join-Path $outputDir 'ManualActions.txt'
if (Test-Path $mtxt) {
    Write-Host '  手動対応チェックリスト:' -ForegroundColor Yellow
    Write-Host ('    ' + $mtxt) -ForegroundColor White
    Write-Host ''
}

# npm 全体防御策の案内
Write-Host '  --------------------------------------------------------' -ForegroundColor DarkGray
Write-Host '  npm サプライチェーン攻撃への防御設定:' -ForegroundColor Cyan
Write-Host ''

$cfgIgnore = $null
$cfgAge = $null
try {
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Set-StrictMode -Off
    $cfgIgnore = (& npm config get ignore-scripts 2>$null)
    $cfgAge = (& npm config get min-release-age 2>$null)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = $savedEAP
} catch {
    $ErrorActionPreference = $savedEAP
}

$ignoreOk = ($cfgIgnore -eq 'true')
$ageOk = ($cfgAge -and $cfgAge -ne 'undefined' -and $cfgAge -ne '0')

if ($ignoreOk) {
    Write-Host '    ignore-scripts  = true   ✓' -ForegroundColor Green
} else {
    Write-Host ('    ignore-scripts  = ' + $(if ($cfgIgnore) { $cfgIgnore } else { '(未設定)' }) + '  ✗ 未設定') -ForegroundColor Yellow
}
# npm バージョンを取得して min-release-age の対応可否を判定
$npmVersionStr = $null
try { Set-StrictMode -Off; $npmVersionStr = (& npm --version 2>$null) } catch {} finally { Set-StrictMode -Version Latest }
$npmSupportsAge = $false
if ($npmVersionStr -match '^(\d+)\.(\d+)') {
    $npmMajor = [int]$Matches[1]; $npmMinor = [int]$Matches[2]
    $npmSupportsAge = ($npmMajor -gt 11 -or ($npmMajor -eq 11 -and $npmMinor -ge 10))
}

if ($npmSupportsAge) {
    if ($ageOk) {
        Write-Host ('    min-release-age = ' + $cfgAge + '      ✓') -ForegroundColor Green
    } else {
        Write-Host ('    min-release-age = ' + $(if ($cfgAge) { $cfgAge } else { '(未設定)' }) + '  ✗ 未設定') -ForegroundColor Yellow
    }
} else {
    Write-Host ('    min-release-age = (npm v11.10 以降で利用可能。現在 v' + $npmVersionStr + ')') -ForegroundColor DarkGray
}

Write-Host ''
if ($ignoreOk -and ($ageOk -or -not $npmSupportsAge)) {
    Write-Host '    この PC の npm 防御設定は適用済みです。' -ForegroundColor Green
    if (-not $npmSupportsAge) {
        Write-Host '    ※ min-release-age は npm v11.10 以降で利用可能です。npm のアップグレードを推奨します。' -ForegroundColor DarkGray
    }
} else {
    Write-Host '    以下のコマンドで、今後の攻撃に備えてください:' -ForegroundColor Yellow
    Write-Host ''
    if (-not $ignoreOk) {
        Write-Host '      npm config set ignore-scripts true' -ForegroundColor White
    }
    if (-not $ageOk -and $npmSupportsAge) {
        Write-Host '      npm config set min-release-age 7' -ForegroundColor White
    }
    if (-not $npmSupportsAge) {
        Write-Host '      npm のアップグレード後: npm config set min-release-age 7  (v11.10 以降)' -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '    詳細は AuditVerdict.txt の「今後の防御策」セクションを参照。' -ForegroundColor DarkGray
}
Write-Host ''

# サマリをファイルにも保存
$sumFile = Join-Path $outputDir 'RunAll_Summary.txt'
$sumLines = @(
    '=== Axios npm 監査 一括実行サマリ ===',
    ('実行日時: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
    ('所要時間: ' + $totalTime),
    ''
)
foreach ($sr in $stageResults) {
    $d = if ($sr.Detail) { ' - ' + $sr.Detail } else { '' }
    $t = if ($sr.Duration) { ' (' + $sr.Duration + ')' } else { '' }
    $sumLines += ('  Stage ' + $sr.Stage + ' [' + $sr.Status + ']' + $t + ' ' + $sr.Name + $d)
}
$sumLines += ''
$sumLines += ('結果フォルダ: ' + $outputDir)
$sumLines += ''
$sumLines += 'npm 防御設定:'
$sumLines += ('  ignore-scripts  = ' + $(if ($cfgIgnore) { $cfgIgnore } else { '(未設定)' }) + $(if ($ignoreOk) { '  OK' } else { '  未設定' }))
$sumLines += ('  min-release-age = ' + $(if ($cfgAge) { $cfgAge } else { '(未設定)' }) + $(if ($ageOk) { '  OK' } else { '  未設定' }))
$sumLines | Out-File -FilePath $sumFile -Encoding UTF8
