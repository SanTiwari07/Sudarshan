# Rewrite author/committer and strip Cursor trailers from entire history, then force-push main.
# Requires: pip install git-filter-repo  (or git filter-repo on PATH)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$name = git config user.name
$email = git config user.email
if (-not $name -or -not $email) {
    throw "Set git user.name and user.email before running this script."
}

$filterRepo = Get-Command git-filter-repo -ErrorAction SilentlyContinue
if (-not $filterRepo) {
    throw "git-filter-repo not found. Install: pip install git-filter-repo"
}

Write-Host "Rewriting history: map Cursor identities -> $name <$email>"
$mailmap = @"
$name <$email> Cursor <cursoragent@cursor.com>
$name <$email> <cursoragent@cursor.com>
$name <$email> cursoragent <199161495+cursoragent@users.noreply.github.com>
"@
$mailmapPath = Join-Path $env:TEMP "sudarshan-cursor-mailmap"
Set-Content -Path $mailmapPath -Value $mailmap -Encoding utf8NoBOM

git filter-repo --force --mailmap $mailmapPath --commit-callback '
import re
msg = commit.message.decode("utf-8", errors="replace")
lines = [
    ln for ln in msg.splitlines()
    if not re.search(r"(?i)cursoragent@cursor\.com|199161495\+cursoragent@users\.noreply\.github\.com|^co-authored-by:\s*cursor|^made-with:\s*cursor", ln)
]
commit.message = ("\n".join(lines) + "\n").encode("utf-8")
'

Remove-Item $mailmapPath -Force -ErrorAction SilentlyContinue

Write-Host "Verify: powershell -File scripts/verify-no-cursor-git.ps1"
Write-Host "Then: git push --force origin main"
Write-Host "Refresh GitHub sidebar: powershell -File scripts/refresh-github-contributors.ps1 -Push"
