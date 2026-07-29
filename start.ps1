# -----------------------------------------------------------------------------
#  Sudarshan Enterprise -- One-Command Startup Script
#  Usage: .\start.ps1
# -----------------------------------------------------------------------------

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "|        SUDARSHAN ENTERPRISE -- STARTUP SCRIPT        |" -ForegroundColor Cyan
Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""

# -- Locate adb ----------------------------------------------------------------
# adb is often not on PATH even when Android Studio is installed, so fall back
# to the standard SDK locations before giving up.
$adb = (Get-Command adb -ErrorAction SilentlyContinue).Source
if (-not $adb) {
    $candidates = @(
        "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
        "$env:ANDROID_HOME\platform-tools\adb.exe",
        "$env:ANDROID_SDK_ROOT\platform-tools\adb.exe",
        "$env:ProgramFiles\Android\android-sdk\platform-tools\adb.exe"
    )
    $adb = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

# -- Step 1: Restart ADB server ------------------------------------------------
Write-Host "[1/6] Restarting ADB server..." -ForegroundColor Yellow
if ($adb) {
    & $adb kill-server | Out-Null
    Start-Sleep -Seconds 1
    & $adb start-server | Out-Null
    Write-Host "      OK ADB server started" -ForegroundColor Green
} else {
    Write-Host "      !  adb executable not found -- dynamic analysis requires platform-tools." -ForegroundColor DarkYellow
}

# Check if an emulator/device is connected
$hasDevice = $false
if ($adb) {
    $devices = & $adb devices 2>&1 | Select-String "device$" | Where-Object { $_ -notmatch "unauthorized|offline" }
    if ($devices) {
        $hasDevice = $true
    }
}

# -- Step 2: Switch emulator to TCP mode --------------------------------------
Write-Host "[2/6] Enabling ADB over TCP (port 5555)..." -ForegroundColor Yellow
if ($hasDevice) {
    $tcpResult = & $adb tcpip 5555 2>&1
    if ($tcpResult -match "error|failed") {
        Write-Host "      !  Could not enable TCP mode (skip if emulator is already in TCP mode)" -ForegroundColor DarkYellow
    } else {
        Write-Host "      OK ADB TCP mode enabled" -ForegroundColor Green
    }
    Start-Sleep -Seconds 1
} else {
    Write-Host "      !  No active Android emulator/device connected via ADB (skipping TCP mode)" -ForegroundColor DarkYellow
}

# -- Step 3: Restart ADB as root -----------------------------------------------
Write-Host "[3/6] Restarting adbd as root..." -ForegroundColor Yellow
if ($hasDevice) {
    & $adb root | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "      OK adbd running as root" -ForegroundColor Green
} else {
    Write-Host "      !  No active emulator connected (skipping adb root)" -ForegroundColor DarkYellow
}

# -- Step 4: Start frida-server on emulator -----------------------------------
Write-Host "[4/6] Starting frida-server on emulator..." -ForegroundColor Yellow
if ($hasDevice) {
    $fridaBinName = if ($env:SUDARSHAN_FRIDA_BIN) { $env:SUDARSHAN_FRIDA_BIN } else { "sudarshan_agent_srv" }
    $fridaPort = if ($env:SUDARSHAN_FRIDA_PORT) { $env:SUDARSHAN_FRIDA_PORT } else { "27055" }
    $fridaRemotePath = "/data/local/tmp/$fridaBinName"

    # Kill any stale instance first
    & $adb shell "pkill -f frida-server" 2>$null | Out-Null
    & $adb shell "pkill -f $fridaBinName" 2>$null | Out-Null
    Start-Sleep -Seconds 1

    # Push if default frida-server exists but randomized binary does not
    & $adb shell "if [ -f /data/local/tmp/frida-server ] && [ ! -f $fridaRemotePath ]; then cp /data/local/tmp/frida-server $fridaRemotePath && chmod 755 $fridaRemotePath; fi" 2>$null | Out-Null

    # Launch fresh in background on non-default port
    & $adb shell "nohup $fridaRemotePath -l 0.0.0.0:$fridaPort > /dev/null 2>&1 &" | Out-Null
    Start-Sleep -Seconds 2

    # Verify
    $fridaCheck = & $adb shell "ps -A" 2>&1 | Select-String -Pattern "$fridaBinName|frida-server"
    if ($fridaCheck) {
        Write-Host "      OK Frida agent server ($fridaBinName) is RUNNING on port $fridaPort" -ForegroundColor Green
    } else {
        Write-Host "      X  Frida agent server did NOT start - dynamic analysis will be skipped" -ForegroundColor Red
        Write-Host "         Make sure the binary exists at $fridaRemotePath on the emulator." -ForegroundColor DarkYellow
    }
} else {
    Write-Host "      !  No active emulator connected (skipping frida-server launch)" -ForegroundColor DarkYellow
}

# -- Step 5: Check & Ensure .env configuration --------------------------------
Write-Host "[5/6] Checking environment configuration (.env)..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "      OK Created .env from .env.example" -ForegroundColor Green
    }
}
if (Test-Path ".env") {
    $envContent = Get-Content ".env" -Raw
    if ($envContent -notmatch "JWT_SECRET_KEY=\S+") {
        $secretKey = [System.Guid]::NewGuid().ToString("N") + [System.Guid]::NewGuid().ToString("N")
        Add-Content -Path ".env" -Value "`nJWT_SECRET_KEY=$secretKey"
        Write-Host "      OK Generated JWT_SECRET_KEY in .env" -ForegroundColor Green
    } else {
        Write-Host "      OK .env configuration is valid" -ForegroundColor Green
    }
}

# -- Step 6: Launch Docker Compose --------------------------------------------
Write-Host "[6/6] Starting Docker stack (Backend + Frontend + MobSF)..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Frontend Dashboard: http://localhost:5173" -ForegroundColor Cyan
Write-Host "  Backend REST API:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  MobSF Framework:    http://localhost:8008  (user: mobsf / pass: mobsf)" -ForegroundColor Cyan
Write-Host "  Analysis Engine:    http://localhost:8001  (internal)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""

docker compose up
