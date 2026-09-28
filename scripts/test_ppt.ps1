param (
    [string]$FilePath = ".\SUDARSHAN_15_SLIDE_COMPLETE_SIH_PRESENTATION.pptx"
)

$resolved = (Resolve-Path $FilePath).Path
Write-Host "Resolved: $resolved"

$ppt = New-Object -ComObject PowerPoint.Application
try {
    $deck = $ppt.Presentations.Open($resolved)
    Write-Host "SUCCESS: Slides count = $($deck.Slides.Count)"
    $deck.Close()
} catch {
    Write-Host "FAILED: $($_.Exception.Message)"
} finally {
    $ppt.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ppt) | Out-Null
}
