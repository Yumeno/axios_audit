[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$verdictCsv = Join-Path $OutputDir 'AuditVerdict.csv'
$verdictTxt = Join-Path $OutputDir 'AuditVerdict.txt'
$summaryTxt = Join-Path $OutputDir 'Stage6_Summary.txt'
$transcript = Join-Path $OutputDir 'Stage6_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

# ============================================================
# 入力ファイル読み込み
# ============================================================
$repoCsv         = Join-Path $OutputDir 'RepoInventory.csv'
$manifestCsv     = Join-Path $OutputDir 'ManifestFindings.csv'
$versionCsv      = Join-Path $OutputDir 'AxiosVersionFindings.csv'
$npmLogCsv       = Join-Path $OutputDir 'NpmLogFindings.csv'
$iocCsv          = Join-Path $OutputDir 'IocFindings.csv'
$wslTxt          = Join-Path $OutputDir 'WSL_Findings.txt'

$repos     = if (Test-Path $repoCsv)     { Import-Csv $repoCsv }     else { @() }
$manifests = if (Test-Path $manifestCsv) { Import-Csv $manifestCsv } else { @() }
$versions  = if (Test-Path $versionCsv)  { Import-Csv $versionCsv }  else { @() }
$npmLogs   = if (Test-Path $npmLogCsv)   { Import-Csv $npmLogCsv }   else { @() }
$iocs      = if (Test-Path $iocCsv)      { Import-Csv $iocCsv }      else { @() }
$wslExists = Test-Path $wslTxt

# ============================================================
# システムレベル IOC 判定
# ============================================================
$systemCompromised = $false
$systemIocDetails = New-Object System.Collections.ArrayList

$highIocs = @($iocs | Where-Object { $_.Severity -eq 'High' })
foreach ($ioc in $highIocs) {
    $systemCompromised = $true
    [void]$systemIocDetails.Add("[IOC] $($ioc.Type): $($ioc.Indicator) — $($ioc.Detail)")
}

# ============================================================
# システムレベル: npm ログの侵害ウィンドウ判定
# ============================================================
# npm ログは PC 全体で共有されるグローバルな情報であり、
# 特定のプロジェクトには紐付かない。システムレベルとして扱う。
$suspiciousLogCount = 0
$suspiciousLogDetails = New-Object System.Collections.ArrayList
foreach ($logEntry in $npmLogs) {
    if ($logEntry.InSuspiciousWindowJst -eq 'True' -or $logEntry.InSuspiciousWindowJst -eq $true) {
        $suspiciousLogCount++
        if ($suspiciousLogDetails.Count -lt 5) {
            [void]$suspiciousLogDetails.Add("  $($logEntry.LastWriteTimeInJst) | $($logEntry.Pattern) | $($logEntry.Line)")
        }
    }
}

# ============================================================
# プロジェクト別判定
# ============================================================
$verdictResults = New-Object System.Collections.ArrayList
$countCompromised = 0
$countNeedsReview = 0
$countHardening = 0
$countClean = 0

# 全プロジェクトパスと所有者情報を集める
$allPaths = @{}
foreach ($r in $repos) {
    if ($r.Path) {
        $ownership = if ($r.PSObject.Properties['Ownership']) { $r.Ownership } else { 'Unknown' }
        $allPaths[$r.Path] = $ownership
    }
}

foreach ($path in ($allPaths.Keys | Sort-Object)) {
    $verdict = 'Clean'
    $ownership = $allPaths[$path]  # 'Mine', 'ThirdParty', or 'Unknown'
    $reasons = New-Object System.Collections.ArrayList
    $actions = New-Object System.Collections.ArrayList

    # --- Manifest findings ---
    $projManifests = @($manifests | Where-Object { $_.RepoPath -eq $path })
    foreach ($mf in $projManifests) {
        if ($mf.Severity -eq 'Compromised') {
            $verdict = 'Compromised'
            [void]$reasons.Add("plain-crypto-js ディレクトリが存在")
            [void]$actions.Add("[自動修復] node_modules/plain-crypto-js を削除")
        }
        if ($mf.Severity -eq 'HighConfidence' -and $mf.Pattern -match 'plain-crypto-js') {
            if ($verdict -ne 'Compromised') { $verdict = 'Compromised' }
            [void]$reasons.Add("lockfile に plain-crypto-js の記述あり")
        }
        if ($mf.Severity -eq 'HighConfidence' -and $mf.Pattern -match 'axios@1\.14\.1|axios@0\.30\.4') {
            if ($verdict -ne 'Compromised') { $verdict = 'Compromised' }
            [void]$reasons.Add("lockfile に侵害版バージョン ($($mf.Pattern)) の記述あり")
            [void]$actions.Add("[自動修復] axios を安全なバージョンにダウングレード")
        }
        if ($mf.Severity -eq 'HighConfidence' -and $mf.Pattern -match 'openclaw') {
            if ($verdict -ne 'Compromised') { $verdict = 'Compromised' }
            [void]$reasons.Add("関連侵害パッケージ ($($mf.Pattern)) が見つかりました")
        }
        if ($mf.Severity -eq 'NeedsReview' -and $mf.Pattern -match 'node_modules.*axios') {
            $axiosConfirmedSafe = $false
            # 完全一致またはサブディレクトリの Stage 3 結果も含めて確認
            # （親リポジトリの RepoPath と worktree 等の子パスの粒度が異なるため）
            $pathWithSep = $path.TrimEnd('\') + '\'
            foreach ($vf in @($versions | Where-Object { $_.RepoPath -eq $path -or $_.RepoPath.StartsWith($pathWithSep) })) {
                if ($vf.Status -eq 'ObservedVersion' -or $vf.Status -eq 'NoAxiosResolved') {
                    $axiosConfirmedSafe = $true
                    break
                }
            }
            if (-not $axiosConfirmedSafe) {
                if ($verdict -eq 'Clean') { $verdict = 'NeedsReview' }
                [void]$reasons.Add("node_modules/axios が存在（バージョン確認が必要）")
            }
        }
    }

    # --- Version findings ---
    $projVersions = @($versions | Where-Object { $_.RepoPath -eq $path })
    $hasAxios = $false
    foreach ($vf in $projVersions) {
        if ($vf.Status -eq 'CompromisedPlainCryptoJsFound') {
            $verdict = 'Compromised'
            [void]$reasons.Add("node_modules/plain-crypto-js ディレクトリが存在（Stage 3 確認）")
        }
        if ($vf.Status -eq 'HighRiskVersionFound') {
            $verdict = 'Compromised'
            [void]$reasons.Add("npm list で侵害版 axios@$($vf.AxiosVersion) を確認")
            [void]$actions.Add("[自動修復] axios を安全なバージョンにダウングレード")
        }
        if ($vf.Status -eq 'ObservedVersion') {
            $hasAxios = $true
        }
        if ($vf.Status -eq 'NpmUnavailable') {
            if ($verdict -eq 'Clean') { $verdict = 'NeedsReview' }
            [void]$reasons.Add("npm が利用不可のためバージョン確認ができていません")
        }
    }

    # --- npm 全体の防御状態チェック ---
    # axios だけピン止めしても他のパッケージが同じ攻撃を受ければ同じこと。
    # 個別パッケージへの対処ではなく、npm の動作全体を制限する防御策を案内する。
    # （浮動バージョンの検出は「防御が不十分である可能性の指標」として残す）
    $floatingFindings = @($manifests | Where-Object { $_.RepoPath -eq $path -and $_.Pattern -eq 'axios-floating-version' })
    if ($floatingFindings.Count -gt 0 -and $verdict -eq 'Clean') {
        # 侵害はないが、同種の攻撃に対する備えが不十分
        $verdict = 'Hardening'
        [void]$reasons.Add("npm の依存解決で意図しないバージョンが入り得る状態です（axios に ^ / ~ 指定あり。他のパッケージも同様の可能性）")
    }

    # --- npm ログの判定はプロジェクト単位には行わない ---
    # npm ログはグローバル（PC 全体で共有）であり、特定のプロジェクトに
    # 紐付けられない。プロジェクト単位の verdict に混ぜると、
    # 無関係なプロジェクトまで NeedsReview になるため、
    # npm ログの確認結果はシステムレベルの情報としてレポート末尾に表示する。

    # アクション追加
    if ($verdict -eq 'Compromised') {
        [void]$actions.Add("[自動修復] npm cache clean --force")
        [void]$actions.Add("[手動] このプロジェクトで使用していた全シークレット・認証情報をローテーション")
        [void]$actions.Add("[手動] .env / 環境変数内の API キー・トークンを再発行")
        if ($ownership -eq 'ThirdParty') {
            [void]$actions.Add("[注意] 他者のリポジトリです。IOC 除去とキャッシュクリアは必要ですが、lockfile やバージョン変更を upstream に push しないでください")
        }
    }
    if ($verdict -eq 'NeedsReview' -and $reasons.Count -eq 0) {
        [void]$reasons.Add("追加確認が必要です")
    }

    # 集計
    switch ($verdict) {
        'Compromised'  { $countCompromised++ }
        'NeedsReview'  { $countNeedsReview++ }
        'Hardening'    { $countHardening++ }
        'Clean'        { $countClean++ }
    }

    [void]$verdictResults.Add([pscustomobject]@{
        Path      = $path
        Verdict   = $verdict
        Ownership = $ownership
        Reasons   = ($reasons | Select-Object -Unique) -join '; '
        Actions   = ($actions | Select-Object -Unique) -join '; '
    })
}

# ============================================================
# テキストレポート生成
# ============================================================
$report = New-Object System.Collections.ArrayList

[void]$report.Add('========================================')
[void]$report.Add('  Axios / npm 監査判定レポート')
[void]$report.Add("  生成日時: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$report.Add('========================================')
[void]$report.Add('')

# システムレベル IOC
if ($systemCompromised) {
    [void]$report.Add('■ [緊急] システムレベル IOC が検出されました')
    [void]$report.Add('')
    foreach ($d in $systemIocDetails) {
        [void]$report.Add("  $d")
    }
    [void]$report.Add('')
    [void]$report.Add('  → Stage 7（修復スクリプト）を直ちに実行してください。')
    [void]$report.Add('  → RAT 永続化ファイルとレジストリの除去が必要です。')
    [void]$report.Add('  → 修復後、すべてのクレデンシャルのローテーションが必要です。')
    [void]$report.Add('')
}

# サマリ
[void]$report.Add('■ 全体サマリ')
[void]$report.Add("  - 監査対象プロジェクト: $($allPaths.Count) 件")
[void]$report.Add("  - 侵害確定:   $countCompromised 件")
[void]$report.Add("  - 要確認:     $countNeedsReview 件")
[void]$report.Add("  - 要強化:     $countHardening 件")
[void]$report.Add("  - 対策不要:   $countClean 件")
[void]$report.Add("  - システム IOC: $($highIocs.Count) 件")
if (-not $wslExists) {
    [void]$report.Add("  - WSL 確認:    未実施（Stage 5 未実行）")
}
[void]$report.Add('')

# npm ログ（システムレベル）
if ($suspiciousLogCount -gt 0) {
    [void]$report.Add('■ npm ログ（侵害ウィンドウ内の操作）')
    [void]$report.Add('')
    [void]$report.Add("  侵害ウィンドウ（JST 2026-03-31 09:21〜12:29）内のログ: $suspiciousLogCount 件")
    [void]$report.Add('')
    [void]$report.Add('  注意: npm ログは PC 全体で共有されるため、特定のプロジェクトには紐付きません。')
    [void]$report.Add('  また、ログファイルの更新時刻に基づく推定であり、厳密な証拠ではありません。')
    [void]$report.Add('  この時間帯に npm install を実行した記憶がある場合は、')
    [void]$report.Add('  そのとき何をインストールしたかを思い出してください。')
    [void]$report.Add('')
    foreach ($ld in $suspiciousLogDetails) {
        [void]$report.Add($ld)
    }
    if ($suspiciousLogCount -gt 5) {
        [void]$report.Add("  ... 他 $($suspiciousLogCount - 5) 件（NpmLogFindings.csv を参照）")
    }
    [void]$report.Add('')
}

# プロジェクト別
[void]$report.Add('■ プロジェクト別判定')
[void]$report.Add('')

foreach ($v in ($verdictResults | Sort-Object Verdict, Path)) {
    $icon = switch ($v.Verdict) {
        'Compromised' { '[侵害確定]' }
        'NeedsReview' { '[要確認]  ' }
        'Hardening'   { '[要強化]  ' }
        'Clean'       { '[対策不要]' }
    }
    $ownerTag = switch ($v.Ownership) {
        'Mine'       { '(自作)' }
        'ThirdParty' { '(他作)' }
        default      { '(作者不明)' }
    }
    [void]$report.Add("  $icon $ownerTag $($v.Path)")
    if ($v.Reasons) {
        foreach ($r in ($v.Reasons -split '; ')) {
            [void]$report.Add("           理由: $r")
        }
    }
    if ($v.Actions) {
        foreach ($a in ($v.Actions -split '; ')) {
            [void]$report.Add("           → $a")
        }
    }
    [void]$report.Add('')
}

# 次のステップ
[void]$report.Add('■ 次のステップ')
[void]$report.Add('')
if ($systemCompromised -or $countCompromised -gt 0) {
    [void]$report.Add('  → 侵害が確認されました。Stage 7（修復スクリプト）を実行してください:')
    [void]$report.Add("     powershell -ExecutionPolicy Bypass -File .\axios_audit_stage7_remediate.ps1 -OutputDir `"$OutputDir`"")
    [void]$report.Add('')
} elseif ($countNeedsReview -gt 0) {
    [void]$report.Add('  → 要確認プロジェクトがあります。上記の推奨アクションを実施後、')
    [void]$report.Add('    Stage 6 を再実行してください。')
    [void]$report.Add('')
} else {
    [void]$report.Add('  → 今回の axios 侵害による被害は検出されませんでした。')
    if (-not $wslExists) {
        [void]$report.Add('  → WSL を使用している場合は Stage 5 を実行してください。')
    }
    [void]$report.Add('')
}

# ============================================================
# 全体防御策の案内（侵害の有無にかかわらず必ず表示）
# ============================================================
[void]$report.Add('========================================')
[void]$report.Add('■ 今後の npm サプライチェーン攻撃への防御策')
[void]$report.Add('========================================')
[void]$report.Add('')
[void]$report.Add('  今回は axios が狙われましたが、同じ手口はどのパッケージにも起こり得ます。')
[void]$report.Add('  axios だけをピン止めしても、他の依存パッケージが攻撃されれば同じことです。')
[void]$report.Add('  以下の設定はパッケージ名に関係なく、npm 全体に効きます。')
[void]$report.Add('')

# npm バージョンを取得して min-release-age の対応可否を判定
$npmVersionStr = $null
try { Set-StrictMode -Off; $npmVersionStr = (& npm --version 2>$null) } catch {} finally { Set-StrictMode -Version Latest }
$npmSupportsAge = $false
if ($npmVersionStr -match '^(\d+)\.(\d+)') {
    $npmMajor = [int]$Matches[1]; $npmMinor = [int]$Matches[2]
    $npmSupportsAge = ($npmMajor -gt 11 -or ($npmMajor -eq 11 -and $npmMinor -ge 10))
}

# npm の現在の設定を確認
$currentIgnoreScripts = $null
$currentMinReleaseAge = $null
try {
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Set-StrictMode -Off
    $currentIgnoreScripts = (& npm config get ignore-scripts 2>$null)
    if ($npmSupportsAge) {
        $currentMinReleaseAge = (& npm config get min-release-age 2>$null)
    }
    Set-StrictMode -Version Latest
    $ErrorActionPreference = $savedEAP
} catch {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = $savedEAP
}

[void]$report.Add('  [防御策 A] postinstall スクリプトの実行を禁止する（最重要）')
[void]$report.Add('')
[void]$report.Add('    今回の攻撃を含め、npm サプライチェーン攻撃の大半は')
[void]$report.Add('    postinstall フック経由でマルウェアを実行します。')
[void]$report.Add('    これを全面禁止するだけで、攻撃チェーンの最終段を断ち切れます。')
[void]$report.Add('')
if ($currentIgnoreScripts -eq 'true') {
    [void]$report.Add('    現在の設定: ignore-scripts = true  ✓ 設定済み')
} else {
    [void]$report.Add('    現在の設定: ignore-scripts = ' + $(if ($currentIgnoreScripts) { $currentIgnoreScripts } else { '(未設定)' }) + '  ✗ 未設定')
    [void]$report.Add('')
    [void]$report.Add('    設定コマンド:')
    [void]$report.Add('      npm config set ignore-scripts true')
    [void]$report.Add('')
    [void]$report.Add('    postinstall が必要なパッケージ（ネイティブアドオン等）は個別に:')
    [void]$report.Add('      npm rebuild パッケージ名')
}
[void]$report.Add('')

[void]$report.Add('  [防御策 B] 新しいバージョンの即時採用を避ける（クールダウン）')
[void]$report.Add('')
[void]$report.Add('    公開から一定日数が経過していないバージョンのインストールを拒否します。')
[void]$report.Add('    今回の侵害版は約3時間で削除されたので、7日待てば絶対に踏みません。')
[void]$report.Add('')
if ($npmSupportsAge) {
    if ($currentMinReleaseAge -and $currentMinReleaseAge -ne 'undefined' -and $currentMinReleaseAge -ne '0') {
        [void]$report.Add('    現在の設定: min-release-age = ' + $currentMinReleaseAge + '  ✓ 設定済み')
    } else {
        [void]$report.Add('    現在の設定: min-release-age = ' + $(if ($currentMinReleaseAge) { $currentMinReleaseAge } else { '(未設定)' }) + '  ✗ 未設定')
        [void]$report.Add('')
        [void]$report.Add('    設定コマンド:')
        [void]$report.Add('      npm config set min-release-age 7')
        [void]$report.Add('')
        [void]$report.Add('    ※ 緊急パッチを即座に適用したい場合は都度:')
        [void]$report.Add('      npm install パッケージ名 --min-release-age=0')
    }
} else {
    [void]$report.Add('    この機能は npm v11.10 以降で利用可能です（現在 v' + $npmVersionStr + '）。')
    [void]$report.Add('    npm をアップグレード後に以下を実行してください:')
    [void]$report.Add('      npm config set min-release-age 7')
}
[void]$report.Add('')

[void]$report.Add('  [防御策 C] lockfile のコミットと npm ci の使用')
[void]$report.Add('')
[void]$report.Add('    自分が開発しているプロジェクトでは:')
[void]$report.Add('      - package-lock.json を Git にコミットする')
[void]$report.Add('      - CI/CD では npm install ではなく npm ci を使う')
[void]$report.Add('    これにより「今動いている依存の組み合わせ」を厳密に再現できます。')
[void]$report.Add('')

[void]$report.Add('  [まとめ] いますぐ実行すべきコマンド（この PC 全体に適用）:')
[void]$report.Add('')
$ignoreScriptsOk = ($currentIgnoreScripts -eq 'true')
$minReleaseAgeOk = $npmSupportsAge -and ($currentMinReleaseAge -and $currentMinReleaseAge -ne 'undefined' -and $currentMinReleaseAge -ne '0')
$alreadyDone = $ignoreScriptsOk -and ($minReleaseAgeOk -or -not $npmSupportsAge)
if ($alreadyDone) {
    [void]$report.Add('    ✓ この PC では防御設定が適用済みです。')
    if (-not $npmSupportsAge) {
        [void]$report.Add('    ※ min-release-age は npm v11.10 以降で利用可能です。npm のアップグレードを推奨します。')
    }
} else {
    if (-not $ignoreScriptsOk) {
        [void]$report.Add('    npm config set ignore-scripts true')
    }
    if ($npmSupportsAge) {
        if (-not $minReleaseAgeOk) {
            [void]$report.Add('    npm config set min-release-age 7')
        }
    } else {
        [void]$report.Add('    npm のアップグレード後: npm config set min-release-age 7  (v11.10 以降)')
    }
    [void]$report.Add('')
    [void]$report.Add('    これにより、今回の axios 攻撃を含むほとんどの')
    [void]$report.Add('    npm サプライチェーン攻撃を防げます。')
}
[void]$report.Add('')

# ファイル出力
$report | Out-File -FilePath $verdictTxt -Encoding UTF8
$verdictResults | Export-Csv -Path $verdictCsv -NoTypeInformation -Encoding UTF8

# サマリ
@(
    '=== Stage 6 Summary ===',
    "OutputDir          : $OutputDir",
    "AuditVerdict.txt   : $verdictTxt",
    "AuditVerdict.csv   : $verdictCsv",
    "TotalProjects      : $($allPaths.Count)",
    "Compromised        : $countCompromised",
    "NeedsReview        : $countNeedsReview",
    "Hardening          : $countHardening",
    "Clean              : $countClean",
    "SystemIOCs         : $($highIocs.Count)"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

# コンソール表示
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  監査判定レポート' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  侵害確定: $countCompromised 件" -ForegroundColor $(if ($countCompromised -gt 0) { 'Red' } else { 'Green' })
Write-Host "  要確認:   $countNeedsReview 件" -ForegroundColor $(if ($countNeedsReview -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  要強化:   $countHardening 件" -ForegroundColor $(if ($countHardening -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  対策不要: $countClean 件" -ForegroundColor Green
Write-Host "  IOC:      $($highIocs.Count) 件" -ForegroundColor $(if ($highIocs.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host ''
if ($systemCompromised -or $countCompromised -gt 0) {
    Write-Host '  [!] 侵害が検出されました。Stage 7 を実行してください。' -ForegroundColor Red
} elseif ($countNeedsReview -gt 0) {
    Write-Host '  [?] 要確認プロジェクトがあります。AuditVerdict.txt を確認してください。' -ForegroundColor Yellow
} else {
    Write-Host '  [OK] 今回の axios 侵害による被害は検出されませんでした。' -ForegroundColor Green
}
Write-Host ''

# npm 全体防御策の案内（常に表示）
if (-not $alreadyDone) {
    Write-Host '  [推奨] この PC の npm を今後の攻撃に備えて強化してください:' -ForegroundColor Yellow
    Write-Host ''
    if (-not $ignoreScriptsOk) {
        Write-Host '    npm config set ignore-scripts true' -ForegroundColor White
    }
    if ($npmSupportsAge -and -not $minReleaseAgeOk) {
        Write-Host '    npm config set min-release-age 7' -ForegroundColor White
    }
    if (-not $npmSupportsAge) {
        Write-Host '    npm のアップグレード後: npm config set min-release-age 7  (v11.10 以降)' -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '    詳細は AuditVerdict.txt の「今後の防御策」セクションを参照。' -ForegroundColor DarkGray
} else {
    Write-Host '  [OK] npm の防御設定は適用済みです。' -ForegroundColor Green
    if (-not $npmSupportsAge) {
        Write-Host '  ※ min-release-age は npm v11.10 以降で利用可能です。npm のアップグレードを推奨します。' -ForegroundColor DarkGray
    }
}
Write-Host ''
Write-Host ('  詳細: ' + $verdictTxt)
Write-Host ''

Stop-Transcript | Out-Null
