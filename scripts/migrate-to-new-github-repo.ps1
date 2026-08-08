<#
.SYNOPSIS
  Copy full main history (~72 commits) to a new GitHub repo with original dates preserved.

.DESCRIPTION
  Your current history has no cursoragent authors; a fresh repo gets a clean Contributors
  sidebar while keeping every commit timestamp and your teammates' authorship.

  Create an EMPTY repo on GitHub first (no README, .gitignore, or license).

.PARAMETER NewRepoUrl
  HTTPS or SSH URL, e.g. https://github.com/SanTiwari07/Sudarshan-Clean.git

.PARAMETER SanitizeMessages
  Run git-filter-repo to remove Cursor co-author lines from commit messages (optional).
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$NewRepoUrl,

    [string]$Branch = "main",

    [switch]$SanitizeMessages
)

$ErrorActionPreference = "Stop"
$SourceRoot = Split-Path -Parent $PSScriptRoot
$CallbackFile = Join-Path $PSScriptRoot "git-filter-repo-strip-cursor.py"

$Tmp = Join-Path $env:TEMP ("sudarshan-migrate-{0}" -f ([guid]::NewGuid().ToString("n").Substring(0, 8)))
Write-Host "Cloning $Branch from $SourceRoot -> $Tmp"
git clone --branch $Branch --single-branch -- "$SourceRoot" $Tmp
Set-Location $Tmp

$CountBefore = [int](git rev-list --count HEAD)
Write-Host "Commits to publish: $CountBefore"

if ($SanitizeMessages) {
    $mailmap = Join-Path $SourceRoot ".mailmap"
    if (Test-Path $mailmap) {
        Copy-Item $mailmap (Join-Path $Tmp ".mailmap") -Force
        git filter-repo --force --use-mailmap --commit-callback $CallbackFile
    } else {
        git filter-repo --force --commit-callback $CallbackFile
    }
    $CountAfter = [int](git rev-list --count HEAD)
    if ($CountAfter -ne $CountBefore) {
        throw "Commit count changed ($CountBefore -> $CountAfter); aborting."
    }
    Write-Host "Sanitized messages; commit count unchanged."
}

git remote remove origin 2>$null
git remote add origin $NewRepoUrl

Write-Host "Pushing to $NewRepoUrl ..."
git push -u origin $Branch

Write-Host ""
Write-Host "Done. New repo should show ~$CountBefore commits with original dates."
Write-Host "Contributors: only humans in git shortlog (no cursoragent if history was clean)."
Write-Host "You can delete the temp clone: $Tmp"
