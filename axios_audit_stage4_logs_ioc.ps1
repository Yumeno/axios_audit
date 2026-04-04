[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path ((Get-Location).Path) ("AxiosNpmAudit_" + (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$logCsv = Join-Path $OutputDir 'NpmLogFindings.csv'
$iocCsv = Join-Path $OutputDir 'IocFindings.csv'
$globalTxt = Join-Path $OutputDir 'GlobalNpmList.txt'
$summaryTxt = Join-Path $OutputDir 'Stage4_Summary.txt'
$transcript = Join-Path $OutputDir 'Stage4_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

$SuspiciousWindowStartJst = [datetimeoffset]'2026-03-31T09:21:00+09:00'
$SuspiciousWindowEndJst   = [datetimeoffset]'2026-03-31T12:29:00+09:00'
# ログ検索パターン: axios 侵害に直接関連するものに限定
# @anthropic-ai/claude-code, @openai/codex, @google/gemini-cli は
# 今回の侵害判定としては無関係なので除外。
# npm install / npm ci 等の汎用パターンも広すぎるため除外し、
# 侵害版の具体的なパッケージ名に絞る。
$logRegexHigh = 'axios@1\.14\.1|axios@0\.30\.4|plain-crypto-js|@shadanai/openclaw|@qqbrowser/openclaw-qbot|sfrclak'
# 参考情報として install 操作も記録するが、Severity を分ける
$logRegexInfo = '\bnpm\s+install\b|\bnpm\s+i\s|\bnpm\s+ci\b|\bnpm\s+update\b'

$logResults = New-Object System.Collections.ArrayList
$iocResults = New-Object System.Collections.ArrayList
$stats = [ordered]@{
    LogFilesScanned = 0
    NpmLogHits = 0
    IocHits = 0
    AccessErrors = 0
}

function Add-NpmLogFinding {
    param(
        [string]$CachePath,
        [string]$LogPath,
        [datetime]$LastWriteTime,
        [string]$Pattern,
        [int]$LineNumber,
        [string]$Line
    )
    $dto = [datetimeoffset]::new($LastWriteTime)
    $inWindow = ($dto -ge $SuspiciousWindowStartJst -and $dto -le $SuspiciousWindowEndJst)
    [void]$logResults.Add([pscustomobject]@{
        CachePath = $CachePath
        LogPath = $LogPath
        LastWriteTime = $LastWriteTime
        LastWriteTimeInJst = $dto.ToOffset([timespan]::FromHours(9)).ToString('yyyy-MM-dd HH:mm:ss zzz')
        InSuspiciousWindowJst = $inWindow
        Pattern = $Pattern
        LineNumber = $LineNumber
        Line = $Line.Trim()
    })
    $stats.NpmLogHits++
}

function Add-IocFinding {
    param(
        [string]$Severity,
        [string]$Type,
        [string]$Indicator,
        [string]$Path,
        [string]$Detail
    )
    [void]$iocResults.Add([pscustomobject]@{
        Severity = $Severity
        Type = $Type
        Indicator = $Indicator
        Path = $Path
        Detail = $Detail
    })
    $stats.IocHits++
}

# ============================================================
# npm ログ確認
# ============================================================
$candidateCaches = New-Object System.Collections.ArrayList
try {
    $savedEnc = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $npmCache = (& npm config get cache 2>$null)
    [Console]::OutputEncoding = $savedEnc
    if ($LASTEXITCODE -eq 0 -and $npmCache) {
        $trimmed = $npmCache.ToString().Trim()
        if ($trimmed -and (Test-Path $trimmed)) { [void]$candidateCaches.Add($trimmed) }
    }
} catch {
    [Console]::OutputEncoding = $savedEnc
}

foreach ($p in @((Join-Path $env:APPDATA 'npm-cache'), (Join-Path $HOME '.npm'))) {
    if ($p -and (Test-Path $p) -and -not ($candidateCaches -contains $p)) {
        [void]$candidateCaches.Add($p)
    }
}

foreach ($cachePath in $candidateCaches) {
    $logsRoot = Join-Path $cachePath '_logs'
    if (-not (Test-Path $logsRoot)) { continue }
    try {
        $logFiles = Get-ChildItem -LiteralPath $logsRoot -File -ErrorAction Stop
    } catch {
        $stats.AccessErrors++
        continue
    }

    foreach ($log in $logFiles) {
        $stats.LogFilesScanned++

        # 注意: LastWriteTime はログファイルの更新時刻であり、
        # ログ内の操作が実行された正確な時刻とは異なる場合がある。
        # ファイルコピーやアンチウイルスのスキャンでも更新されうる。
        # 侵害ウィンドウ判定は「参考情報」として扱う。

        try {
            # 高信頼パターン（侵害版パッケージ名）
            $highMatches = Select-String -Path $log.FullName -Pattern $logRegexHigh -AllMatches -ErrorAction Stop
            foreach ($m in $highMatches) {
                foreach ($mm in $m.Matches) {
                    Add-NpmLogFinding -CachePath $cachePath -LogPath $log.FullName -LastWriteTime $log.LastWriteTime -Pattern $mm.Value -LineNumber $m.LineNumber -Line $m.Line
                }
            }
        } catch {
            $stats.AccessErrors++
        }

        # 侵害ウィンドウ内のログファイルのみ、install 操作も参考記録
        try {
            $dto = [datetimeoffset]::new($log.LastWriteTime)
            $inWindow = ($dto -ge $SuspiciousWindowStartJst -and $dto -le $SuspiciousWindowEndJst)
            if ($inWindow) {
                $infoMatches = Select-String -Path $log.FullName -Pattern $logRegexInfo -AllMatches -ErrorAction Stop
                foreach ($m in $infoMatches) {
                    foreach ($mm in $m.Matches) {
                        Add-NpmLogFinding -CachePath $cachePath -LogPath $log.FullName -LastWriteTime $log.LastWriteTime -Pattern $mm.Value -LineNumber $m.LineNumber -Line $m.Line
                    }
                }
            }
        } catch {
            $stats.AccessErrors++
        }
    }
}

try {
    $savedEAP = $ErrorActionPreference
    $savedEnc = [Console]::OutputEncoding
    $ErrorActionPreference = 'Continue'
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    (& npm ls -g --depth=8 2>&1 | Out-String) | Out-File -FilePath $globalTxt -Encoding UTF8
    [Console]::OutputEncoding = $savedEnc
    $ErrorActionPreference = $savedEAP
} catch {
    [Console]::OutputEncoding = $savedEnc
    $ErrorActionPreference = $savedEAP
    'npm ls -g could not be collected.' | Out-File -FilePath $globalTxt -Encoding UTF8
}

# ============================================================
# IOC 確認: ファイルシステム
# ============================================================

# --- 既存: %ProgramData%\wt.exe ---
$programDataWt = Join-Path $env:ProgramData 'wt.exe'
if (Test-Path $programDataWt) {
    Add-IocFinding -Severity 'High' -Type 'File' -Indicator 'Known Windows RAT payload (wt.exe)' -Path $programDataWt -Detail 'wt.exe は powershell.exe のコピー。%ProgramData% にある場合、侵害の強い指標です。'
}

# --- 追加: %ProgramData%\system.bat (永続化バッチ) ---
$programDataBat = Join-Path $env:ProgramData 'system.bat'
if (Test-Path $programDataBat) {
    Add-IocFinding -Severity 'High' -Type 'File' -Indicator 'RAT persistence batch file (system.bat)' -Path $programDataBat -Detail 'system.bat は再起動時に RAT を再確立する永続化ファイルです。wt.exe が消えていてもこちらが残る場合があります。'
}

# --- 追加: レジストリキー HKCU\...\Run\MicrosoftUpdate ---
# --- 追加: レジストリキー HKCU\...\Run\MicrosoftUpdate ---
try {
    $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $regValue = Get-ItemProperty -Path $regPath -Name 'MicrosoftUpdate' -ErrorAction SilentlyContinue
    if ($regValue -and $regValue.MicrosoftUpdate) {
        Add-IocFinding -Severity 'High' -Type 'Registry' -Indicator 'RAT persistence registry key (MicrosoftUpdate)' -Path "$regPath\MicrosoftUpdate" -Detail ('値: ' + $regValue.MicrosoftUpdate + ' — RAT が system.bat を指す永続化キーです。')
    }
} catch {
    # レジストリアクセスエラー（権限不足等）
}

# ============================================================
# IOC 確認: hosts ファイル
# ============================================================
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hostsFile) {
    try {
        # --- 修正: 142.11.206.72 を追加 ---
        $hits = Select-String -Path $hostsFile -Pattern 'sfrclak|142\.11\.206\.73|142\.11\.206\.72' -AllMatches -ErrorAction Stop
        foreach ($h in $hits) {
            Add-IocFinding -Severity 'High' -Type 'HostsFile' -Indicator 'High-confidence IOC in hosts file' -Path $hostsFile -Detail $h.Line.Trim()
        }
    } catch {
        $stats.AccessErrors++
    }
}

# ============================================================
# IOC 確認: DNS キャッシュ
# ============================================================
try {
    $dnsCache = Get-DnsClientCache -ErrorAction Stop
    $dnsHits = $dnsCache | Where-Object { $_.Entry -match 'sfrclak' }
    foreach ($d in $dnsHits) {
        Add-IocFinding -Severity 'High' -Type 'DnsCache' -Indicator 'C2 domain resolved in DNS cache' -Path 'Get-DnsClientCache' -Detail "Entry=$($d.Entry) Data=$($d.Data) Type=$($d.Type)"
    }
} catch {
    # DNS クライアントキャッシュが取得できない環境もある
}

# ============================================================
# IOC 確認: ネットワーク (netstat)
# ============================================================
try {
    $netstatLines = netstat -ano 2>$null
    foreach ($line in $netstatLines) {
        # --- 修正: 142.11.206.72 を追加 ---
        if ($line -match '142\.11\.206\.73|142\.11\.206\.72') {
            $pid = if ($line -match '\s+(\d+)\s*$') { $Matches[1] } else { '' }
            $pname = ''
            if ($pid) {
                try { $pname = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch {}
            }
            Add-IocFinding -Severity 'High' -Type 'NetworkSnapshot' -Indicator 'High-confidence C2 IP observed' -Path 'netstat' -Detail ($line.Trim() + $(if ($pname) { " | Process=$pname | PID=$pid" } else { '' }))
        } elseif ($line -match ':8000') {
            $pid = if ($line -match '\s+(\d+)\s*$') { $Matches[1] } else { '' }
            $pname = ''
            if ($pid) {
                try { $pname = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch {}
            }
            Add-IocFinding -Severity 'Low' -Type 'NetworkSnapshot' -Indicator 'Port 8000 activity (needs context)' -Path 'netstat' -Detail ($line.Trim() + $(if ($pname) { " | Process=$pname | PID=$pid" } else { '' }))
        }
    }
} catch {
    $stats.AccessErrors++
}

# ============================================================
# IOC 確認: PowerShell 履歴（参考情報）
# ============================================================
# 注意: PowerShell 履歴には個人の作業履歴が含まれます。
# レポートを共有する場合は、この情報が含まれることに注意してください。
# 検索語は今回の侵害に直接関連するものに限定しています。
$historyPath = $null
try {
    $historyPath = (Get-PSReadLineOption).HistorySavePath
    if ($historyPath -and (Test-Path $historyPath)) {
        $historyHits = Select-String -Path $historyPath -Pattern 'axios|plain-crypto-js|sfrclak' -ErrorAction Stop
        foreach ($h in $historyHits) {
            Add-IocFinding -Severity 'Info' -Type 'PowerShellHistory' -Indicator 'axios 関連の履歴' -Path $historyPath -Detail $h.Line.Trim()
        }
    }
} catch {}

# ============================================================
# 出力
# ============================================================
$logResults | Sort-Object @{Expression='InSuspiciousWindowJst';Descending=$true}, LastWriteTime | Export-Csv -Path $logCsv -NoTypeInformation -Encoding UTF8
$iocResults | Sort-Object Severity, Type, Indicator | Export-Csv -Path $iocCsv -NoTypeInformation -Encoding UTF8

@(
    '=== Stage 4 Summary ===',
    "OutputDir            : $OutputDir",
    "NpmLogFindings.csv   : $logCsv",
    "IocFindings.csv      : $iocCsv",
    "GlobalNpmList.txt    : $globalTxt",
    "LogFilesScanned      : $($stats.LogFilesScanned)",
    "NpmLogHits           : $($stats.NpmLogHits)",
    "IocHits              : $($stats.IocHits)",
    "AccessErrors         : $($stats.AccessErrors)"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host "Done. See: $OutputDir"
Stop-Transcript | Out-Null
