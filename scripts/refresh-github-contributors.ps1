# Nudge GitHub to recompute the Contributors sidebar after history is already clean.
param(
    [switch]$Push
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

& (Join-Path $PSScriptRoot "verify-no-cursor-git.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$msg = "chore: refresh GitHub contributors graph"
$existing = git log -1 --format=%s 2>$null
if ($existing -eq $msg) {
    Write-Host "Latest commit is already a contributors refresh; skipping empty commit."
} else {
    git commit --allow-empty -m $msg
    Write-Host "Created empty commit to trigger contributor graph refresh."
}

if ($Push) {
    git push origin main
    Write-Host "Pushed. If cursoragent still appears, wait 24h or contact GitHub Support to recompute contributors."
} else {
    Write-Host "Run with -Push to publish: powershell -File scripts/refresh-github-contributors.ps1 -Push"
}
