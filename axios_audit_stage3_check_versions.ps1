[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoInventoryCsv,
    [string]$OutputDir = $(Split-Path -Path $RepoInventoryCsv -Parent)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$versionCsv = Join-Path $OutputDir 'AxiosVersionFindings.csv'
$summaryTxt = Join-Path $OutputDir 'Stage3_Summary.txt'
$transcript = Join-Path $OutputDir 'Stage3_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

$rows = Import-Csv $RepoInventoryCsv
$rootsSeen = @{}
$roots = New-Object System.Collections.ArrayList
foreach ($row in $rows) {
    if (-not $row.Path) { continue }
    $root = [System.IO.Path]::GetFullPath([string]$row.Path)
    if ($root.Length -gt 3) { $root = $root.TrimEnd([char]'\') }
    if (-not $rootsSeen.ContainsKey($root)) {
        $rootsSeen[$root] = $true
        [void]$roots.Add($root)
    }
}

$results = New-Object System.Collections.ArrayList
$stats = [ordered]@{
    UniqueRoots = $roots.Count
    CheckedRoots = 0
    NpmUnavailable = 0
    PlainCryptoDirFound = 0
    AccessErrors = 0
    Findings = 0
}

function Add-Result {
    param(
        [string]$RepoPath,
        [string]$Status,
        [string]$AxiosVersion,
        [string]$Evidence,
        [string]$RawOutput
    )
    [void]$results.Add([pscustomobject]@{
        RepoPath = $RepoPath
        Status = $Status
        AxiosVersion = $AxiosVersion
        Evidence = $Evidence
        RawOutput = $RawOutput
    })
    $stats.Findings++
}

# nvm for Windows が管理する Node.js パスを PATH に追加
# PowerShell 5.1 から直接実行すると nvm-windows の PATH 注入が効かないため
$nvmSymlink = if ($env:NVM_SYMLINK) { $env:NVM_SYMLINK } else { '' }
$nvmHome    = if ($env:NVM_HOME)    { $env:NVM_HOME }    else { '' }
if ($nvmSymlink -and (Test-Path $nvmSymlink)) {
    $env:PATH = "$nvmSymlink;$env:PATH"
} elseif ($nvmHome) {
    $currentLink = Join-Path $nvmHome 'nodejs'
    if (Test-Path $currentLink) {
        $env:PATH = "$currentLink;$env:PATH"
    }
}

# nvm-windows の npm.ps1 ラッパーが $MyInvocation.Statement を参照するため
# StrictMode Latest だとエラーになる。npm 呼び出し時のみ緩和する。
$npmAvailable = $true
try {
    Set-StrictMode -Off
    & npm --version *> $null
} catch {
    $npmAvailable = $false
} finally {
    Set-StrictMode -Version Latest
}

$index = 0
foreach ($root in $roots) {
    $index++
    Write-Progress -Id 1 -Activity 'Axios 実バージョン確認中' -Status "$index / $($roots.Count)" -CurrentOperation $root -PercentComplete ([int](($index / [double]$roots.Count) * 100))

    if (-not (Test-Path $root)) { continue }
    if (-not (Test-Path (Join-Path $root 'package.json'))) { continue }
    $stats.CheckedRoots++

    # --- 追加: node_modules/plain-crypto-js ディレクトリの存在確認 ---
    # ディレクトリの存在だけで侵害確定（正規 axios にこの依存は存在しない）
    $plainCryptoDir = Join-Path $root 'node_modules\plain-crypto-js'
    if (Test-Path $plainCryptoDir) {
        Add-Result -RepoPath $root -Status 'CompromisedPlainCryptoJsFound' -AxiosVersion '' -Evidence "node_modules/plain-crypto-js ディレクトリが存在 = 侵害確定" -RawOutput $plainCryptoDir
        $stats.PlainCryptoDirFound++
    }

    if (-not $npmAvailable) {
        $stats.NpmUnavailable++
        Add-Result -RepoPath $root -Status 'NpmUnavailable' -AxiosVersion '' -Evidence 'npm command not found' -RawOutput ''
        continue
    }

    Push-Location $root
    try {
        # npm list は stderr に警告やエラーを出すことがある（壊れた package.json 等）。
        # $ErrorActionPreference = 'Stop' の下では stderr 出力が致命的エラーになるため、
        # 一時的に Continue に変更して npm を実行し、終了後に戻す。
        # また、npm は UTF-8 で出力するが、PowerShell 5.1 の SJIS 環境では
        # [Console]::OutputEncoding が SJIS のため日本語パスが文字化けする。
        # 一時的に UTF-8 に変更して正しく読み取る。
        $savedEAP = $ErrorActionPreference
        $savedEnc = [Console]::OutputEncoding
        $ErrorActionPreference = 'Continue'
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        Set-StrictMode -Off          # nvm-windows npm.ps1 ラッパー対策
        $raw = (& npm list axios --all 2>&1 | Out-String)
        Set-StrictMode -Version Latest
        [Console]::OutputEncoding = $savedEnc
        $ErrorActionPreference = $savedEAP

        $matchResults = [regex]::Matches($raw, 'axios@([0-9]+(?:\.[0-9]+){1,3})')
        if ($matchResults.Count -gt 0) {
            $versions = $matchResults | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
            foreach ($v in $versions) {
                $status = if ($v -in @('1.14.1','0.30.4')) { 'HighRiskVersionFound' } else { 'ObservedVersion' }
                Add-Result -RepoPath $root -Status $status -AxiosVersion $v -Evidence 'npm list axios --all' -RawOutput ($raw.Trim())
            }
        } else {
            if ($raw -match '\(empty\)') {
                Add-Result -RepoPath $root -Status 'NoAxiosResolved' -AxiosVersion '' -Evidence 'npm list returned empty' -RawOutput ($raw.Trim())
            } else {
                Add-Result -RepoPath $root -Status 'NoAxiosMatchInOutput' -AxiosVersion '' -Evidence 'No axios@x.y.z match found' -RawOutput ($raw.Trim())
            }
        }
    } catch {
        $stats.AccessErrors++
        Add-Result -RepoPath $root -Status 'ExecutionError' -AxiosVersion '' -Evidence $_.Exception.Message -RawOutput ''
    } finally {
        [Console]::OutputEncoding = $savedEnc
        $ErrorActionPreference = $savedEAP
        Pop-Location
    }
}

Write-Progress -Id 1 -Activity 'Axios 実バージョン確認中' -Completed
$results | Sort-Object Status, RepoPath, AxiosVersion | Export-Csv -Path $versionCsv -NoTypeInformation -Encoding UTF8

@(
    '=== Stage 3 Summary ===',
    "OutputDir               : $OutputDir",
    "AxiosVersionFindings.csv: $versionCsv",
    "UniqueRoots             : $($stats.UniqueRoots)",
    "CheckedRoots            : $($stats.CheckedRoots)",
    "NpmUnavailable          : $($stats.NpmUnavailable)",
    "PlainCryptoDirFound     : $($stats.PlainCryptoDirFound)",
    "AccessErrors            : $($stats.AccessErrors)",
    "Findings                : $($stats.Findings)"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host "Done. See: $OutputDir"
Stop-Transcript | Out-Null
