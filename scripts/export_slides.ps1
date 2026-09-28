param(
    [string]$PptxPath = "SUDARSHAN_15_SLIDE_COMPLETE_SIH_PRESENTATION.pptx",
    [string]$OutDir = "docs/slides"
)

$resolvedPptx = (Resolve-Path $PptxPath).Path
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}
$resolvedOut = (Resolve-Path $OutDir).Path

$ppApp = New-Object -ComObject PowerPoint.Application
$pres = $ppApp.Presentations.Open($resolvedPptx, [Microsoft.Office.Core.MsoTriState]::msoTrue, [Microsoft.Office.Core.MsoTriState]::msoFalse, [Microsoft.Office.Core.MsoTriState]::msoFalse)

# Export slide by slide to have exact names
$i = 1
foreach ($slide in $pres.Slides) {
    $slidePath = Join-Path $resolvedOut ("Slide_{0:D2}.png" -f $i)
    $slide.Export($slidePath, "PNG", 1920, 1080)
    $i++
}

$pres.Close()
$ppApp.Quit()
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($pres) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($ppApp) | Out-Null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

Write-Output "SUCCESS: Exported $($i - 1) slides to $resolvedOut"
