[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path ((Get-Location).Path) ("AxiosNpmAudit_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string[]]$ScanPaths,
    [switch]$IncludeNetworkDrives,
    [switch]$IncludeSystemLikeDirectories
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$repoCsv = Join-Path $OutputDir 'RepoInventory.csv'
$summaryTxt = Join-Path $OutputDir 'Stage1_Summary.txt'
$transcript = Join-Path $OutputDir 'Stage1_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

$interestingFileNames = @('package.json','package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','bun.lock','bun.lockb')
$excludeNames = @('$Recycle.Bin','System Volume Information','node_modules','.pnpm-store','.yarn','.next','dist','build','out','coverage','target','bin','obj')
if (-not $IncludeSystemLikeDirectories) {
    $excludeNames += @('Windows','Program Files','Program Files (x86)','ProgramData','Recovery','PerfLogs','MSOCache')
}

$results = New-Object System.Collections.ArrayList
$seen = @{}
$stats = [ordered]@{
    DrivesScanned = 0
    TopLevelRootsSeen = 0
    DirectoriesProcessed = 0
    FilesInspected = 0
    RepoCandidates = 0
    AccessErrors = 0
}

function Add-RepoCandidate {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Kind,
        [string]$Marker = ''
    )

    $normalized = [System.IO.Path]::GetFullPath($Path)
    if ($normalized.Length -gt 3) {
        $normalized = $normalized.TrimEnd([char]'\')
    }

    if (-not $seen.ContainsKey($normalized)) {
        # --- 所有者推定 (Ownership) ---
        # 完全な自動判定は不可能なので、高い確度で推定できる場合のみ
        # Mine / ThirdParty を設定し、それ以外は Unknown にしてユーザーに確認を促す。
        #
        # 判定ロジック:
        #   1. .git がない → Unknown（git リポジトリではない）
        #   2. remote が未設定（ローカルのみ） → Mine（自分で git init した可能性が高い）
        #   3. remote URL に自分の git ユーザー名が含まれる → Mine
        #   4. remote がある + 自分のコミットがない → ThirdParty
        #   5. remote がある + 自分のコミットがある → Unknown（fork かもしれないし、
        #      チームリポジトリかもしれない。判断できないのでユーザーに確認を促す）
        $ownership = 'Unknown'
        $remoteUrl = ''
        $gitDir = Join-Path $normalized '.git'
        if (Test-Path $gitDir) {
            try {
                Push-Location $normalized

                # git は UTF-8 で出力するが、SJIS 環境では文字化けするため
                # 一時的に OutputEncoding を UTF-8 に変更
                $savedEnc = [Console]::OutputEncoding
                [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

                # remote URL を取得
                $remoteUrl = (& git remote get-url origin 2>$null)
                $hasRemote = [bool]$remoteUrl

                # git の user.name / user.email を取得
                $gitUserName = (& git config user.name 2>$null)
                $gitUserEmail = (& git config user.email 2>$null)

                if (-not $hasRemote) {
                    # remote なし = ローカルで git init されたリポジトリ → Mine
                    $ownership = 'Mine'
                } else {
                    # remote URL に自分のユーザー名が含まれるか確認
                    # 例: https://github.com/myname/repo.git や git@github.com:myname/repo.git
                    $remoteHasMyName = $false
                    if ($gitUserName -and $remoteUrl -match [regex]::Escape($gitUserName)) {
                        $remoteHasMyName = $true
                    }
                    # メールのローカルパート（@ の前）でも照合
                    if (-not $remoteHasMyName -and $gitUserEmail -and $gitUserEmail -match '^([^@]+)@') {
                        $emailLocal = $Matches[1]
                        if ($emailLocal.Length -ge 3 -and $remoteUrl -match [regex]::Escape($emailLocal)) {
                            $remoteHasMyName = $true
                        }
                    }

                    if ($remoteHasMyName) {
                        $ownership = 'Mine'
                    } else {
                        # remote がある + URL に自分の名前がない
                        # → コミット履歴を確認して判断材料を増やす
                        $authorCheck = (& git log --format='%an|%ae' -n 20 2>$null)
                        $hasMyCommits = $false
                        if ($authorCheck) {
                            $myCommits = $authorCheck | Where-Object {
                                ($gitUserName -and $_ -match [regex]::Escape($gitUserName)) -or
                                ($gitUserEmail -and $_ -match [regex]::Escape($gitUserEmail))
                            }
                            $hasMyCommits = [bool]$myCommits
                        }

                        if (-not $hasMyCommits) {
                            # remote あり + 自分のコミットなし → ThirdParty
                            $ownership = 'ThirdParty'
                        } else {
                            # remote あり + 自分のコミットあり
                            # fork かもしれないしチームリポジトリかもしれない → Unknown
                            $ownership = 'Unknown'
                        }
                    }
                }

                [Console]::OutputEncoding = $savedEnc
                Pop-Location
            } catch {
                try { [Console]::OutputEncoding = $savedEnc } catch {}
                try { Pop-Location } catch {}
                # git が使えない場合は Unknown のまま
            }
        }

        $obj = [pscustomobject]@{
            Path = $normalized
            Drive = [System.IO.Path]::GetPathRoot($normalized)
            Kind = $Kind
            Marker = $Marker
            Ownership = $ownership
            RemoteUrl = $remoteUrl
        }
        $seen[$normalized] = $true
        [void]$results.Add($obj)
        $stats.RepoCandidates++
    }
}

function Should-SkipDirectory {
    param([System.IO.DirectoryInfo]$Dir)
    if ($Dir.Name -ieq '.git') { return $false }
    return $excludeNames -contains $Dir.Name
}

function Get-TargetDrives {
    $types = @(2,3)
    if ($IncludeNetworkDrives) { $types += 4 }

    try {
        return Get-CimInstance Win32_LogicalDisk |
            Where-Object { $_.DriveType -in $types -and $_.DeviceID } |
            ForEach-Object { "$($_.DeviceID)\" } |
            Select-Object -Unique
    } catch {
        return Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Root } | Select-Object -Unique
    }
}

function Scan-DirectoryTree {
    param(
        [Parameter(Mandatory)][string]$DriveRoot,
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$TopDir,
        [int]$TopIndex,
        [int]$TopCount
    )

    $stack = New-Object System.Collections.Stack
    $stack.Push($TopDir.FullName)
    $lastProgress = [datetime]::MinValue

    while ($stack.Count -gt 0) {
        $current = [string]$stack.Pop()
        $stats.DirectoriesProcessed++

        $now = Get-Date
        if (($now - $lastProgress).TotalMilliseconds -ge 500) {
            $pct = if ($TopCount -gt 0) { [int](($TopIndex / $TopCount) * 100) } else { 0 }
            Write-Progress -Id 1 -Activity 'ドライブ走査中' -Status "$DriveRoot ($TopIndex / $TopCount)" -PercentComplete $pct
            Write-Progress -Id 2 -ParentId 1 -Activity 'サブツリー走査中' -Status "処理済みディレクトリ: $($stats.DirectoriesProcessed) / Repo候補: $($stats.RepoCandidates)" -CurrentOperation $current -PercentComplete -1
            $lastProgress = $now
        }

        try {
            $children = Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop
        } catch {
            $stats.AccessErrors++
            continue
        }

        foreach ($child in $children) {
            if ($child.PSIsContainer) {
                if ($child.Name -ieq '.git') {
                    Add-RepoCandidate -Path $current -Kind 'git-repo' -Marker '.git'
                    continue
                }
                if (Should-SkipDirectory -Dir $child) { continue }
                $stack.Push($child.FullName)
            } else {
                if ($interestingFileNames -contains $child.Name) {
                    $stats.FilesInspected++
                    if ($child.Name -ieq 'package.json') {
                        Add-RepoCandidate -Path $child.DirectoryName -Kind 'package-project' -Marker 'package.json'
                    }
                }
            }
        }
    }
}

if ($ScanPaths -and $ScanPaths.Count -gt 0) {
    # --- 指定パスのみ走査 ---
    Write-Host ('  走査モード: 指定パス (' + $ScanPaths.Count + ' 件)') -ForegroundColor Cyan
    $pathIndex = 0
    foreach ($sp in $ScanPaths) {
        $pathIndex++
        $resolved = [System.IO.Path]::GetFullPath($sp)
        if (-not (Test-Path $resolved)) {
            Write-Host ('  [WARN] パスが見つかりません: ' + $resolved) -ForegroundColor Yellow
            continue
        }
        $stats.DrivesScanned++
        $topDir = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if ($topDir.PSIsContainer) {
            # 指定パス自体が .git や package.json を持つかチェック
            $gitDir = Join-Path $resolved '.git'
            if (Test-Path $gitDir) {
                Add-RepoCandidate -Path $resolved -Kind 'git-repo' -Marker '.git'
            }
            $pkgJson = Join-Path $resolved 'package.json'
            if (Test-Path $pkgJson) {
                Add-RepoCandidate -Path $resolved -Kind 'package-project' -Marker 'package.json'
            }
            # サブディレクトリも走査
            Scan-DirectoryTree -DriveRoot $resolved -TopDir $topDir -TopIndex $pathIndex -TopCount $ScanPaths.Count
        }
    }
} else {
    # --- 全ドライブ走査（従来動作） ---
    Write-Host '  走査モード: 全ローカルドライブ' -ForegroundColor Cyan

$drives = Get-TargetDrives | Where-Object { $_ -and (Test-Path $_) }
if (-not $drives) { throw '対象ドライブが見つかりません。' }

foreach ($drive in $drives) {
    $stats.DrivesScanned++
    try {
        $rootChildren = Get-ChildItem -LiteralPath $drive -Force -ErrorAction Stop
    } catch {
        $stats.AccessErrors++
        continue
    }

    $rootFiles = @($rootChildren | Where-Object { -not $_.PSIsContainer })
    $topDirs = @($rootChildren | Where-Object { $_.PSIsContainer })
    $stats.TopLevelRootsSeen += $topDirs.Count

    foreach ($f in $rootFiles) {
        if ($interestingFileNames -contains $f.Name) {
            $stats.FilesInspected++
            if ($f.Name -ieq 'package.json') {
                Add-RepoCandidate -Path $drive -Kind 'package-project' -Marker 'package.json at drive root'
            }
        }
    }

    $topCount = $topDirs.Count
    $index = 0
    foreach ($dir in $topDirs) {
        $index++
        if ($dir.Name -ieq '.git') {
            Add-RepoCandidate -Path $drive -Kind 'git-repo' -Marker '.git at drive root'
            continue
        }
        if (Should-SkipDirectory -Dir $dir) { continue }
        Scan-DirectoryTree -DriveRoot $drive -TopDir $dir -TopIndex $index -TopCount $topCount
    }

    Write-Progress -Id 2 -Activity 'サブツリー走査中' -Completed
    Write-Progress -Id 1 -Activity 'ドライブ走査中' -Status "$drive 完了" -PercentComplete 100
}

}  # end if/else ScanPaths

Write-Progress -Id 1 -Activity 'ドライブ走査中' -Completed
Write-Progress -Id 2 -Activity 'サブツリー走査中' -Completed

$results | Sort-Object Drive, Path | Export-Csv -Path $repoCsv -NoTypeInformation -Encoding UTF8

@(
    '=== Stage 1 Summary ===',
    "OutputDir            : $OutputDir",
    "RepoInventory.csv    : $repoCsv",
    "DrivesScanned        : $($stats.DrivesScanned)",
    "TopLevelRootsSeen    : $($stats.TopLevelRootsSeen)",
    "DirectoriesProcessed : $($stats.DirectoriesProcessed)",
    "FilesInspected       : $($stats.FilesInspected)",
    "RepoCandidates       : $($stats.RepoCandidates)",
    "AccessErrors         : $($stats.AccessErrors)"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host "Done. See: $OutputDir"
Stop-Transcript | Out-Null
