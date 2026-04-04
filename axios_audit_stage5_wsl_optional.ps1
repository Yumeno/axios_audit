[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path ((Get-Location).Path) ("AxiosNpmAudit_" + (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$outFile = Join-Path $OutputDir 'WSL_Findings.txt'
$summaryTxt = Join-Path $OutputDir 'Stage5_Summary.txt'
$transcript = Join-Path $OutputDir 'Stage5_Transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null

$lines = New-Object System.Collections.ArrayList
[void]$lines.Add('=== WSL audit ===')

try {
    $savedEnc = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $distros = & wsl.exe -l -q 2>$null
    if (-not $distros) {
        [void]$lines.Add('No WSL distro found.')
    } else {
        foreach ($d in $distros) {
            $name = [string]$d
            $name = $name.Trim()
            if (-not $name) { continue }
            [void]$lines.Add('')
            [void]$lines.Add("--- Distro: $name ---")

$bashCmd = @'
set -e
printf "--- repo candidates ---\n"
find /home /root /opt /srv -type d \( -name .git -o -name node_modules \) 2>/dev/null | sed 's#/\.git$##' | sed 's#/node_modules$##' | sort -u | head -n 2000
printf "--- lockfile hits ---\n"
find /home /root /opt /srv \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name bun.lock -o -name package.json \) -type f 2>/dev/null | while read -r f; do
  grep -nE 'plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4|/axios@1\.14\.1|/axios@0\.30\.4|"axios"[[:space:]]*:[[:space:]]*"1\.14\.1"|"axios"[[:space:]]*:[[:space:]]*"0\.30\.4"|node_modules/axios' "$f" 2>/dev/null && printf '\n'
done
printf "--- npm logs ---\n"
if [ -d "$HOME/.npm/_logs" ]; then
  grep -R -nE 'plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4|@anthropic-ai/claude-code|@openai/codex|@google/gemini-cli|\bnpm[[:space:]]+install\b|\bnpm[[:space:]]+i\b|\bnpm[[:space:]]+ci\b|\bnpm[[:space:]]+update\b|\bnpx\b' "$HOME/.npm/_logs" 2>/dev/null || true
fi
printf "--- IOC ---\n"
ls -l /tmp/ld.py 2>/dev/null || true
'@

            $result = & wsl.exe -d $name -- bash -lc $bashCmd 2>&1
            foreach ($r in $result) {
                [void]$lines.Add(([string]$r))
            }
        }
    }
    [Console]::OutputEncoding = $savedEnc
} catch {
    [Console]::OutputEncoding = $savedEnc
    [void]$lines.Add("WSL audit error: $($_.Exception.Message)")
}

$lines | Out-File -FilePath $outFile -Encoding UTF8
@(
    '=== Stage 5 Summary ===',
    "OutputDir      : $OutputDir",
    "WSL_Findings   : $outFile"
) | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host "Done. See: $OutputDir"
Stop-Transcript | Out-Null
