# Enable commit-msg hook that strips Cursor co-author trailers (local repo only).
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
git config core.hooksPath .githooks
Write-Host "Git hooks enabled for this repository (core.hooksPath=.githooks)."
