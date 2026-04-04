[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoInventoryCsv,
    [string]$OutputDir = $(Split-Path -Path $RepoInventoryCsv -Parent)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$manifestCsv = Join-Path $OutputDir 'ManifestFindings.csv'
$summaryTxt = Join-Path $OutputDir 'Stage2_Summary.txt'
$transcript = Join-Path $OutputDir 'Stage2_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

$interestingFileNames = @('package.json','package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','bun.lock','bun.lockb')
$excludeNames = @('node_modules','.pnpm-store','.yarn','.next','dist','build','out','coverage','target','bin','obj')
# --- 修正: 関連パッケージ (@shadanai/openclaw, @qqbrowser/openclaw-qbot) を追加 ---
# 検索パターン
# node_modules/axios の検索で gaxios 等の部分一致を防ぐ:
#   node_modules[/\\]axios[/\\"] — axios の前がパス区切り、後もパス区切りか引用符
$manifestRegex = 'plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4|/axios@1\.14\.1|/axios@0\.30\.4|"axios"\s*:\s*"1\.14\.1"|"axios"\s*:\s*"0\.30\.4"|node_modules[/\\]axios[/\\"]|@shadanai/openclaw|@qqbrowser/openclaw-qbot'

$rows = Import-Csv $RepoInventoryCsv
$results = New-Object System.Collections.ArrayList
$pathsSeen = @{}
$stats = [ordered]@{
    RepoRowsRead = 0
    UniqueRoots = 0
    FilesInspected = 0
    Findings = 0
    PlainCryptoDirFound = 0
    AccessErrors = 0
}

function Add-Finding {
    param(
        [string]$Path,
        [string]$RepoPath,
        [string]$Pattern,
        [string]$Line,
        [int]$LineNumber,
        [string]$Severity
    )
    [void]$results.Add([pscustomobject]@{
        Path = $Path
        RepoPath = $RepoPath
        Severity = $Severity
        Pattern = $Pattern
        LineNumber = $LineNumber
        Line = $Line.Trim()
    })
    $stats.Findings++
}

$roots = New-Object System.Collections.ArrayList
foreach ($row in $rows) {
    $stats.RepoRowsRead++
    if (-not $row.Path) { continue }
    $root = [System.IO.Path]::GetFullPath([string]$row.Path)
    if ($root.Length -gt 3) { $root = $root.TrimEnd([char]'\') }
    if (-not $pathsSeen.ContainsKey($root)) {
        $pathsSeen[$root] = $true
        [void]$roots.Add($root)
    }
}
$stats.UniqueRoots = $roots.Count

$index = 0
foreach ($root in $roots) {
    $index++
    if (-not (Test-Path $root)) { continue }

    Write-Progress -Id 1 -Activity 'Manifest / lockfile 確認中' -Status "$index / $($roots.Count)" -CurrentOperation $root -PercentComplete ([int](($index / [double]$roots.Count) * 100))

    # --- 追加: node_modules/plain-crypto-js ディレクトリの直接存在確認 ---
    # マルウェアは package.json を書き戻すアンチフォレンジック機能を持つため
    # テキスト検索では見つからなくても、ディレクトリ存在だけで侵害確定
    $plainCryptoDir = Join-Path $root 'node_modules\plain-crypto-js'
    if (Test-Path $plainCryptoDir) {
        Add-Finding -Path $plainCryptoDir -RepoPath $root -Pattern 'plain-crypto-js directory exists' -Line "[CRITICAL] node_modules/plain-crypto-js ディレクトリが存在 = 侵害確定。正規 axios にこの依存は存在しません。" -LineNumber 0 -Severity 'Compromised'
        $stats.PlainCryptoDirFound++
    }

    # --- 追加: 関連パッケージのディレクトリ直接確認 ---
    foreach ($relPkg in @('node_modules\@shadanai\openclaw', 'node_modules\@qqbrowser\openclaw-qbot')) {
        $relDir = Join-Path $root $relPkg
        if (Test-Path $relDir) {
            Add-Finding -Path $relDir -RepoPath $root -Pattern "$relPkg directory exists" -Line "[HIGH] 関連する侵害パッケージのディレクトリが存在します。" -LineNumber 0 -Severity 'HighConfidence'
        }
    }

    try {
        $files = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction Stop |
            Where-Object {
                ($interestingFileNames -contains $_.Name) -and
                ($_.FullName -notmatch '[\\/]node_modules[\\/]') -and
                ($_.FullName -notmatch '[\\/]\.pnpm-store[\\/]') -and
                ($_.FullName -notmatch '[\\/]\.yarn[\\/]')
            }
    } catch {
        $stats.AccessErrors++
        continue
    }

    foreach ($file in $files) {
        $stats.FilesInspected++
        if ($file.Name -ieq 'bun.lockb') {
            Add-Finding -Path $file.FullName -RepoPath $root -Pattern 'bun.lockb (binary)' -Line '[Binary lockfile: manual review recommended]' -LineNumber 0 -Severity 'NeedsReview'
            continue
        }

        try {
            $matchResults = Select-String -Path $file.FullName -Pattern $manifestRegex -AllMatches -ErrorAction Stop
            foreach ($m in $matchResults) {
                foreach ($mm in $m.Matches) {
                    $value = $mm.Value
                    $severity = if ($value -match 'plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4|/axios@1\.14\.1|/axios@0\.30\.4|"axios"\s*:\s*"1\.14\.1"|"axios"\s*:\s*"0\.30\.4"|@shadanai/openclaw|@qqbrowser/openclaw-qbot') { 'HighConfidence' } else { 'NeedsReview' }
                    Add-Finding -Path $file.FullName -RepoPath $root -Pattern $value -Line $m.Line -LineNumber $m.LineNumber -Severity $severity
                }
            }
        } catch {
            $stats.AccessErrors++
        }

        # --- 追加: package.json 内の axios 浮動バージョン指定（^ / ~）を検出 ---
        # 侵害版でなくても、^ や ~ が付いていると将来の install で意図しない
        # バージョンが入るリスクがある。全プロジェクトに対して固定化を勧告する。
        if ($file.Name -ieq 'package.json') {
            try {
                $floatingHits = Select-String -Path $file.FullName -Pattern '"axios"\s*:\s*"[\^~]' -AllMatches -ErrorAction Stop
                foreach ($fh in $floatingHits) {
                    Add-Finding -Path $file.FullName -RepoPath $root -Pattern 'axios-floating-version' -Line $fh.Line -LineNumber $fh.LineNumber -Severity 'Hardening'
                }
            } catch {}
        }
    }
}

Write-Progress -Id 1 -Activity 'Manifest / lockfile 確認中' -Completed
$results | Sort-Object Severity, RepoPath, Path, LineNumber | Export-Csv -Path $manifestCsv -NoTypeInformation -Encoding UTF8

@(
    '=== Stage 2 Summary ===',
    "OutputDir            : $OutputDir",
    "ManifestFindings.csv : $manifestCsv",
    "RepoRowsRead         : $($stats.RepoRowsRead)",
    "UniqueRoots          : $($stats.UniqueRoots)",
    "FilesInspected       : $($stats.FilesInspected)",
    "Findings             : $($stats.Findings)",
    "PlainCryptoDirFound  : $($stats.PlainCryptoDirFound)",
    "AccessErrors         : $($stats.AccessErrors)"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host "Done. See: $OutputDir"
Stop-Transcript | Out-Null
