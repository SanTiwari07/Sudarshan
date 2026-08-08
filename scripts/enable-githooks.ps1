# Enable hooks that strip Cursor trailers and block pushes that reintroduce cursoragent.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
git config core.hooksPath .githooks
Write-Host "Git hooks enabled for this repository (core.hooksPath=.githooks)."
