# ─────────────────────────────────────────────────────────────────────────────
#  Sudarshan Enterprise — One-Command Startup Script
#  Usage: .\start.ps1
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        SUDARSHAN ENTERPRISE — STARTUP SCRIPT         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Kill any stale ADB server ────────────────────────────────────────
Write-Host "[1/5] Restarting ADB server..." -ForegroundColor Yellow
adb kill-server | Out-Null
Start-Sleep -Seconds 1
adb start-server | Out-Null
Write-Host "      ✔ ADB server started" -ForegroundColor Green

# ── Step 2: Switch emulator to TCP mode ──────────────────────────────────────
Write-Host "[2/5] Enabling ADB over TCP (port 5555)..." -ForegroundColor Yellow
$tcpResult = adb tcpip 5555 2>&1
if ($tcpResult -match "error|failed") {
    Write-Host "      !  No USB device found (skip if emulator is already in TCP mode)" -ForegroundColor DarkYellow
} else {
    Write-Host "      OK ADB TCP mode enabled" -ForegroundColor Green
}
Start-Sleep -Seconds 1

# ── Step 3: Restart ADB as root ───────────────────────────────────────────────
Write-Host "[3/5] Restarting adbd as root..." -ForegroundColor Yellow
adb root | Out-Null
Start-Sleep -Seconds 2
Write-Host "      ✔ adbd running as root" -ForegroundColor Green

# ── Step 4: Start frida-server on emulator ───────────────────────────────────
Write-Host "[4/5] Starting frida-server on emulator..." -ForegroundColor Yellow

# Kill any stale instance first
adb shell "pkill -f frida-server" 2>$null | Out-Null
Start-Sleep -Seconds 1

# Launch fresh in background
adb shell "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &" | Out-Null
Start-Sleep -Seconds 2

# Verify
$fridaCheck = adb shell "ps -A" 2>&1 | Select-String "frida-server"
if ($fridaCheck) {
    Write-Host "      OK frida-server is RUNNING" -ForegroundColor Green
} else {
    Write-Host "      X frida-server did NOT start - dynamic analysis will be skipped" -ForegroundColor Red
    Write-Host "        Make sure the binary exists at /data/local/tmp/frida-server on the emulator." -ForegroundColor DarkYellow
}

# ── Step 5: Launch Docker Compose ────────────────────────────────────────────
Write-Host "[5/5] Starting Docker stack (backend + frontend + MobSF)..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Frontend:  http://localhost:5173" -ForegroundColor Cyan
Write-Host "  Backend:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  MobSF:     http://localhost:8008  (user: mobsf / pass: mobsf)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""

docker compose up
