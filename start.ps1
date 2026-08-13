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
    $storeStub = [System.IO.Path]::Combine(
        $env:LOCALAPPDATA, "Microsoft", "WindowsApps")

    # 1. Project .venv (highest priority -- already has all deps installed)
    $venvPy = Join-Path $Root ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) {
        # Resolve the real interpreter the venv points to
        $realPy = & $venvPy -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $realPy -and (Test-Path $realPy.Trim())) {
            return $venvPy   # Use venv wrapper so installed packages are visible
        }
    }

    # 2. Real Python installs under %LOCALAPPDATA%\Programs\Python  (bypasses Store stub)
    $localPyRoot = Join-Path $env:LOCALAPPDATA "Programs\Python"
    if (Test-Path $localPyRoot) {
        $candidates = Get-ChildItem "$localPyRoot\Python3*\python.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending   # prefer newer version
        foreach ($c in $candidates) {
            $ver = & $c.FullName --version 2>$null
            if ($LASTEXITCODE -eq 0) { return $c.FullName }
        }
    }

    # 3. py.exe launcher (Windows Python Launcher) -- try explicit versions
    $pyLauncher = "C:\Windows\py.exe"
    if (-not (Test-Path $pyLauncher)) {
        $pyCmdObj = Get-Command py -ErrorAction SilentlyContinue
        if ($pyCmdObj) { $pyLauncher = $pyCmdObj.Source }
    }
    if ($pyLauncher -and (Test-Path $pyLauncher)) {
        foreach ($ver in @("-3.11", "-3.12", "-3.13", "-3.10", "-3")) {
            $realPy = & $pyLauncher $ver -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $realPy -and
                (Test-Path $realPy.Trim()) -and
                ($realPy.Trim() -notlike "*WindowsApps*")) {
                return $realPy.Trim()
            }
        }
    }

    # 4. PATH-based fallback -- skip the Microsoft Store stub
    foreach ($name in @("python3", "python")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -notlike "*WindowsApps*") {
            return $cmd.Source
        }
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

# analysis-engine/.env is an OPTIONAL per-service override (docker-compose marks
# it required: false). It is gitignored, so a fresh clone never has one and the
# root .env supplies every value the engine needs. Say so, because its absence
# used to abort the whole stack.
if (Test-Path (Join-Path $Root "analysis-engine\.env")) {
    Write-Info "analysis-engine/.env present -- layered over the root .env"
}

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

# Config-only preflight (no ADB / Frida probes -- the sandbox bootstrap below
# covers those on the host). Catches the silent degraders early: a missing
# GEMINI_API_KEY downgrades the agentic explorer to the fallback planner, and
# SUDARSHAN_DISABLE_SCREENSHOTS empties the evidence gallery. Advisory only.
$preflight = Join-Path $Root "scripts\preflight.py"
if (Test-Path $preflight) {
    $pyCfg = Find-Python
    if ($pyCfg) {
        & $pyCfg $preflight --no-device
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Preflight reported blocking issues (see above)"
        }
    }
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

    # The check that actually matters: `adb devices` resolves differently inside
    # the engine than on the host. The host ADB server binds 127.0.0.1, so
    # ADB_SERVER_SOCKET=tcp:host.docker.internal:5037 only reaches it when the
    # host server was started listening on all interfaces. Without this the run
    # completes with zero devices and an empty screenshot gallery.
    Write-Host ""
    Write-Info "Waiting for analysis-engine before running the in-container preflight..."
    $engineUp = $false
    foreach ($attempt in 1..30) {
        $state = & docker compose ps --status running --services 2>$null
        if ($state -and ($state -split "\r?\n") -contains "analysis-engine") {
            $engineUp = $true
            break
        }
        Start-Sleep -Seconds 3
    }

    if (-not $engineUp) {
        Write-Warn "analysis-engine did not reach running state -- skipping in-container preflight"
        Write-Info "Run it later with: docker compose exec analysis-engine python -m sudarshan_core.preflight"
    } else {
        & docker compose exec -T analysis-engine python -m sudarshan_core.preflight
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "In-container preflight found blocking issues -- dynamic analysis will not produce runtime evidence until they are fixed"
        } else {
            Write-Ok "In-container preflight passed"
        }
    }

    Write-Host ""
    Write-Host "Useful commands:" -ForegroundColor DarkGray
    Write-Host "  docker compose ps"
    Write-Host "  docker compose logs -f backend"
    Write-Host "  docker compose down"
    Write-Host "  python scripts/preflight.py --container   # re-run all preflight checks"
    exit 0
}

Write-Host "Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""
& docker compose up --build
exit $LASTEXITCODE
