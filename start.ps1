# -----------------------------------------------------------------------------
#  Sudarshan Enterprise -- One-Command Startup Script (emulator-agnostic)
#  Usage:  .\start.ps1
#          .\start.ps1 -SkipSandbox   # Docker only (static analysis)
#          .\start.ps1 -Detach        # docker compose up -d
# -----------------------------------------------------------------------------

[CmdletBinding()]
param(
    [switch]$SkipSandbox,
    [switch]$Detach
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Always run from the repo root (where this script lives)
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Write-Step($n, $total, $msg) {
    Write-Host "[$n/$total] $msg" -ForegroundColor Yellow
}
function Write-Ok($msg)   { Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "      !   $msg" -ForegroundColor DarkYellow }
function Write-Fail($msg) { Write-Host "      X   $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "      $msg" -ForegroundColor DarkGray }

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $eq = $line.IndexOf("=")
        if ($eq -lt 1) { return }
        $key = $line.Substring(0, $eq).Trim()
        $val = $line.Substring($eq + 1).Trim()
        if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        $existing = [Environment]::GetEnvironmentVariable($key, "Process")
        if ([string]::IsNullOrEmpty($existing)) {
            [Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
}

function Import-EnvFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or $line.IndexOf("=") -lt 1) { return }
        $eq = $line.IndexOf("=")
        $key = $line.Substring(0, $eq).Trim()
        $val = $line.Substring($eq + 1).Trim()
        [Environment]::SetEnvironmentVariable($key, $val, "Process")
        Set-Item -Path "Env:$key" -Value $val
    }
}

function Find-Python {
    foreach ($c in @("python", "py")) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

Write-Host ""
Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "|        SUDARSHAN ENTERPRISE -- STARTUP SCRIPT        |" -ForegroundColor Cyan
Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""
Write-Info "Working directory: $Root"

# -- Step 0 / 7: Ensure .env --------------------------------------------------
Write-Step 0 7 "Checking environment configuration (.env)..."

if (-not (Test-Path (Join-Path $Root ".env"))) {
    $example = Join-Path $Root ".env.example"
    if (Test-Path $example) {
        Copy-Item $example (Join-Path $Root ".env")
        Write-Ok "Created .env from .env.example"
    } else {
        Write-Fail ".env and .env.example missing -- cannot start Docker stack"
        exit 1
    }
}

Import-DotEnv -Path (Join-Path $Root ".env")

$jwt = $env:JWT_SECRET_KEY
if ([string]::IsNullOrWhiteSpace($jwt)) {
    $secretKey = -join ((1..64) | ForEach-Object { "{0:x}" -f (Get-Random -Max 16) })
    Add-Content -Path (Join-Path $Root ".env") -Value "`nJWT_SECRET_KEY=$secretKey"
    $env:JWT_SECRET_KEY = $secretKey
    Write-Ok "Generated JWT_SECRET_KEY in .env"
} else {
    Write-Ok ".env loaded (JWT_SECRET_KEY set)"
}

# Emulator-agnostic defaults (no hardcoded Genymotion IP / AVD serial)
if ([string]::IsNullOrWhiteSpace($env:SANDBOX_PROVIDER) -and [string]::IsNullOrWhiteSpace($env:ANDROID_SANDBOX_PROVIDER)) {
    $env:SANDBOX_PROVIDER = "auto"
    $env:ANDROID_SANDBOX_PROVIDER = "auto"
} elseif ([string]::IsNullOrWhiteSpace($env:SANDBOX_PROVIDER)) {
    $env:SANDBOX_PROVIDER = $env:ANDROID_SANDBOX_PROVIDER
} elseif ([string]::IsNullOrWhiteSpace($env:ANDROID_SANDBOX_PROVIDER)) {
    $env:ANDROID_SANDBOX_PROVIDER = $env:SANDBOX_PROVIDER
}
if ([string]::IsNullOrWhiteSpace($env:ADB_PORT)) { $env:ADB_PORT = "5555" }
if ([string]::IsNullOrWhiteSpace($env:AUTO_CONNECT)) { $env:AUTO_CONNECT = "true" }
if ([string]::IsNullOrWhiteSpace($env:ROOT_REQUIRED)) { $env:ROOT_REQUIRED = "true" }
if ([string]::IsNullOrWhiteSpace($env:FRIDA_PORT)) {
    if ($env:SUDARSHAN_FRIDA_PORT) { $env:FRIDA_PORT = $env:SUDARSHAN_FRIDA_PORT } else { $env:FRIDA_PORT = "27055" }
}
if ([string]::IsNullOrWhiteSpace($env:SUDARSHAN_FRIDA_BIN)) { $env:SUDARSHAN_FRIDA_BIN = "sudarshan_agent_srv" }
if ([string]::IsNullOrWhiteSpace($env:FRIDA_LISTEN_HOST)) { $env:FRIDA_LISTEN_HOST = "127.0.0.1" }
# Prefer ANDROID_DEVICE_SERIAL when DEVICE_SERIAL is empty
if ([string]::IsNullOrWhiteSpace($env:DEVICE_SERIAL) -and $env:ANDROID_DEVICE_SERIAL) {
    $env:DEVICE_SERIAL = $env:ANDROID_DEVICE_SERIAL
}
if ([string]::IsNullOrWhiteSpace($env:ANDROID_DEVICE_SERIAL) -and $env:DEVICE_SERIAL) {
    $env:ANDROID_DEVICE_SERIAL = $env:DEVICE_SERIAL
}

Write-Info "Sandbox provider mode: $($env:SANDBOX_PROVIDER)"
if ($env:ANDROID_DEVICE_SERIAL) { Write-Info "ANDROID_DEVICE_SERIAL: $($env:ANDROID_DEVICE_SERIAL)" }
elseif ($env:DEVICE_SERIAL) { Write-Info "DEVICE_SERIAL: $($env:DEVICE_SERIAL)" }

$sandboxOk = $false
$deviceSerial = $null

if ($SkipSandbox) {
    Write-Step 1 7 "ADB..."
    Write-Warn "SkipSandbox set -- skipping device / Frida setup"
    Write-Step 2 7 "Device discovery... (skipped)"
    Write-Step 3 7 "Sandbox selection... (skipped)"
    Write-Step 4 7 "Device preparation... (skipped)"
    Write-Step 5 7 "Frida... (skipped)"
} else {
    Write-Step 1 7 "ADB + sandbox bootstrap (auto-detect Genymotion / AVD / physical)..."
    $python = Find-Python
    $bootstrap = Join-Path $Root "scripts\bootstrap_sandbox.py"
    $envOut = Join-Path $Root ".sudarshan_sandbox.env"

    if (-not $python) {
        Write-Fail "Python not found -- required for sandbox bootstrap"
        Write-Warn "Docker will still start -- dynamic analysis requires Python + ADB"
    } elseif (-not (Test-Path $bootstrap)) {
        Write-Fail "Missing $bootstrap"
    } else {
        Write-Info "Python: $python"
        Write-Info "Running emulator-agnostic bootstrap (no hardcoded IP / serial / ABI)..."
        if (Test-Path $envOut) { Remove-Item $envOut -Force -ErrorAction SilentlyContinue }

        & $python $bootstrap --env-file $envOut
        $bootExit = $LASTEXITCODE

        if (Test-Path $envOut) {
            Import-EnvFile -Path $envOut
            Write-Ok "Sandbox env imported from bootstrap"
            if ($env:DEVICE_SERIAL) { $deviceSerial = $env:DEVICE_SERIAL }
            if ($env:ANDROID_DEVICE_SERIAL) { $deviceSerial = $env:ANDROID_DEVICE_SERIAL }
            Write-Info "Selected: provider=$($env:SANDBOX_PROVIDER) serial=$deviceSerial adb_host=$($env:ADB_HOST)"
        }

        if ($bootExit -eq 0) {
            $sandboxOk = $true
            Write-Ok "Sandbox ready"
        } else {
            Write-Warn "Sandbox bootstrap reported issues (exit $bootExit) -- dynamic analysis may be skipped"
            Write-Warn "Start Genymotion or an Android Studio AVD, then re-run."
        }
    }
}

# -- Step 6: Docker preflight --------------------------------------------------
Write-Step 6 7 "Checking Docker..."
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Fail "docker not found. Install Docker Desktop and re-run."
    exit 1
}

$dockerInfo = & docker info 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $dockerInfo -match "error during connect|Cannot connect|Is the docker daemon running") {
    Write-Fail "Docker daemon is not running. Start Docker Desktop, wait until it is ready, then re-run."
    exit 1
}
Write-Ok "Docker daemon is running"

$composeFile = Join-Path $Root "docker-compose.yml"
if (-not (Test-Path $composeFile)) {
    Write-Fail "docker-compose.yml not found in $Root"
    exit 1
}

# -- Step 7: Compose up --------------------------------------------------------
Write-Step 7 7 "Starting Docker stack (Backend + Frontend + MobSF)..."
Write-Host ""
Write-Host "  Frontend Dashboard: http://localhost:5173" -ForegroundColor Cyan
Write-Host "  Backend REST API:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  MobSF Framework:    http://localhost:8008  (user: mobsf / pass: mobsf)" -ForegroundColor Cyan
Write-Host "  Analysis Engine:    http://analysis-engine:8001  (internal)" -ForegroundColor Cyan
if ($deviceSerial) {
    Write-Host "  Sandbox device:     $deviceSerial  (provider=$($env:SANDBOX_PROVIDER))" -ForegroundColor Cyan
}
Write-Host ""

if ($Detach) {
    Write-Info "Mode: detached (docker compose up -d --build)"
    & docker compose up -d --build
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "docker compose failed (exit $LASTEXITCODE). Try: docker compose logs"
        exit $LASTEXITCODE
    }
    Write-Ok "Stack started in background"
    Write-Host ""
    Write-Host "Useful commands:" -ForegroundColor DarkGray
    Write-Host "  docker compose ps"
    Write-Host "  docker compose logs -f backend"
    Write-Host "  docker compose down"
    exit 0
}

Write-Host "Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""
& docker compose up --build
exit $LASTEXITCODE
