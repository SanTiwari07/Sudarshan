# Scan all refs for Cursor Agent author/committer/trailers (exit 1 if any found).
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$pattern = '(?i)cursoragent@cursor\.com|199161495\+cursoragent@users\.noreply\.github\.com|^co-authored-by:\s*cursor|^made-with:\s*cursor'

$hits = @()
git for-each-ref --format="%(refname)" refs/heads refs/remotes | ForEach-Object {
    $ref = $_
    git log $ref --format="%H" 2>$null | ForEach-Object {
        $hash = $_
        $body = git log -1 --format="%an`n%ae`n%cn`n%ce`n%B" $hash
        if ($body -match $pattern) {
            $hits += [pscustomobject]@{ Ref = $ref; Commit = $hash }
        }
    }
}

if ($hits.Count -eq 0) {
    Write-Host "OK: no Cursor Agent attribution in any branch."
    exit 0
}

Write-Host "Found Cursor Agent traces in $($hits.Count) commit(s):" -ForegroundColor Red
$hits | Select-Object -First 20 | Format-Table -AutoSize
Write-Host "Rewrite history: powershell -File scripts/strip-cursor-from-git-history.ps1"
exit 1
