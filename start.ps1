# -----------------------------------------------------------------------------
#  Sudarshan Enterprise -- One-Command Startup Script
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
        # Strip surrounding quotes
        if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        # Do not overwrite vars already set in the current shell
        $existing = [Environment]::GetEnvironmentVariable($key, "Process")
        if ([string]::IsNullOrEmpty($existing)) {
            [Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
}

function Find-Adb {
    $fromPath = (Get-Command adb -ErrorAction SilentlyContinue).Source
    if ($fromPath) { return $fromPath }

    $candidates = @(
        $env:GENYMOTION_ADB,
        "$env:ProgramFiles\Genymobile\Genymotion\tools\adb.exe",
        "${env:ProgramFiles(x86)}\Genymobile\Genymotion\tools\adb.exe",
        "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
        "$env:ANDROID_HOME\platform-tools\adb.exe",
        "$env:ANDROID_SDK_ROOT\platform-tools\adb.exe",
        "$env:ProgramFiles\Android\android-sdk\platform-tools\adb.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Invoke-Adb {
    param(
        [Parameter(Mandatory)][string]$AdbPath,
        [string[]]$AdbArguments,
        [int]$TimeoutSec = 30
    )
    # Capture stdout+stderr without PowerShell treating adb stderr as a terminating error
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $AdbPath
    $psi.Arguments = ($AdbArguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        return @{ Ok = $false; Out = "adb timed out"; Code = -1 }
    }
    $out = ($p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()).Trim()
    return @{ Ok = ($p.ExitCode -eq 0); Out = $out; Code = $p.ExitCode }
}

function Get-OnlineDevices {
    param([string]$AdbPath)
    $r = Invoke-Adb -AdbPath $AdbPath -AdbArguments @("devices")
    $serials = @()
    foreach ($line in ($r.Out -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t -or $t -match "List of devices") { continue }
        if ($t -match "^(\S+)\s+device$") {
            $serials += $Matches[1]
        }
    }
    return $serials
}

function Find-FridaHostBinary {
    $dir = Join-Path $Root "frida-server-17.16.4-android-x86_64"
    $candidates = @(
        (Join-Path $dir "frida-server-17.16.4-android-x86_64"),
        (Join-Path $dir "frida-server"),
        (Join-Path $Root "frida-server-17.16.4-android-x86_64.xz"),
        (Join-Path $Root "frida-server")
    )
    # Also pick any executable-looking file inside the folder
    if (Test-Path $dir) {
        Get-ChildItem $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $candidates += $_.FullName
        }
    }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c) -and -not $c.EndsWith(".xz") -and -not $c.EndsWith(".md")) {
            $item = Get-Item $c
            if ($item.Length -gt 100000) { return $item.FullName }
        }
    }
    return $null
}

function Get-FridaListenHost {
    $listen = $env:FRIDA_LISTEN_HOST
    if ([string]::IsNullOrWhiteSpace($listen)) { $listen = "127.0.0.1" }
    if ($listen -ne "127.0.0.1" -and $listen -ne "::1") {
        Write-Warn "FRIDA_LISTEN_HOST=$listen is not loopback; using 127.0.0.1 for guest bind"
        $listen = "127.0.0.1"
    }
    return $listen
}

function Test-FridaRunningOnDevice {
    param(
        [string]$AdbPath,
        [string]$Serial,
        [string]$FridaBinName
    )
    # pgrep is more reliable than scanning full `ps -A` (huge output, truncated names).
    $pat = if ($FridaBinName.Length -gt 15) { $FridaBinName.Substring(0, 15) } else { $FridaBinName }
    $cmd = "pgrep -f '$pat' 2>/dev/null || pgrep -f frida-server 2>/dev/null || ps -A 2>/dev/null | grep -E '${pat}|frida-server' || true"
    $r = Invoke-Adb -AdbPath $AdbPath -AdbArguments @("-s", $Serial, "shell", $cmd) -TimeoutSec 45
    return ($r.Out -match '\d+' -or $r.Out -match $pat -or $r.Out -match 'frida-server')
}

function Start-FridaOnDevice {
    param(
        [string]$AdbPath,
        [string]$Serial,
        [string]$RemotePath,
        [string]$ListenHost,
        [string]$Port
    )
    $log = "/data/local/tmp/frida-start.log"
    $startCmd = "nohup $RemotePath -l ${ListenHost}:$Port > $log 2>&1 &"
    [void](Invoke-Adb -AdbPath $AdbPath -AdbArguments @("-s", $Serial, "shell", $startCmd) -TimeoutSec 45)
}

Write-Host ""
Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "|        SUDARSHAN ENTERPRISE -- STARTUP SCRIPT        |" -ForegroundColor Cyan
Write-Host "+------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""
Write-Info "Working directory: $Root"

# -- Step 0 / 6: Ensure .env --------------------------------------------------
Write-Step 0 6 "Checking environment configuration (.env)..."

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

# Ensure JWT_SECRET_KEY is non-empty (docker-compose requires it)
$jwt = $env:JWT_SECRET_KEY
if ([string]::IsNullOrWhiteSpace($jwt)) {
    $secretKey = -join ((1..64) | ForEach-Object { "{0:x}" -f (Get-Random -Max 16) })
    Add-Content -Path (Join-Path $Root ".env") -Value "`nJWT_SECRET_KEY=$secretKey"
    $env:JWT_SECRET_KEY = $secretKey
    Write-Ok "Generated JWT_SECRET_KEY in .env"
} else {
    Write-Ok ".env loaded (JWT_SECRET_KEY set)"
}

# Defaults for sandbox
if ([string]::IsNullOrWhiteSpace($env:SANDBOX_PROVIDER)) { $env:SANDBOX_PROVIDER = "genymotion" }
if ([string]::IsNullOrWhiteSpace($env:ADB_PORT)) { $env:ADB_PORT = "5555" }
if ([string]::IsNullOrWhiteSpace($env:ADB_HOST)) { $env:ADB_HOST = "host.docker.internal" }
if ([string]::IsNullOrWhiteSpace($env:AUTO_CONNECT)) { $env:AUTO_CONNECT = "true" }
if ([string]::IsNullOrWhiteSpace($env:ROOT_REQUIRED)) { $env:ROOT_REQUIRED = "true" }
if ([string]::IsNullOrWhiteSpace($env:FRIDA_PORT)) {
    if ($env:SUDARSHAN_FRIDA_PORT) { $env:FRIDA_PORT = $env:SUDARSHAN_FRIDA_PORT } else { $env:FRIDA_PORT = "27055" }
}
if ([string]::IsNullOrWhiteSpace($env:SUDARSHAN_FRIDA_BIN)) { $env:SUDARSHAN_FRIDA_BIN = "sudarshan_agent_srv" }

Write-Info "Sandbox provider: $($env:SANDBOX_PROVIDER)"
if ($env:DEVICE_SERIAL) { Write-Info "DEVICE_SERIAL: $($env:DEVICE_SERIAL)" }

# -- Step 1: Locate ADB + restart server --------------------------------------
Write-Step 1 6 "Restarting ADB server..."
$adb = Find-Adb
$hasDevice = $false
$deviceSerial = $env:DEVICE_SERIAL

if ($SkipSandbox) {
    Write-Warn "SkipSandbox set -- skipping device / Frida setup"
} elseif ($adb) {
    Write-Info "ADB: $adb"
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("kill-server"))
    Start-Sleep -Seconds 1
    $start = Invoke-Adb -AdbPath $adb -AdbArguments @("start-server")
    if ($start.Ok -or $start.Out -match "daemon") {
        Write-Ok "ADB server started"
    } else {
        Write-Warn "ADB start-server: $($start.Out)"
    }

    # If DEVICE_SERIAL is configured, attempt connection first
    if ($deviceSerial) {
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", $deviceSerial))
    }
    # If ADB_HOST is set and no local device yet, try connect (Genymotion TCP)
    if ($env:ADB_HOST -and $env:ADB_HOST -ne "host.docker.internal") {
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", "$($env:ADB_HOST):$($env:ADB_PORT)"))
    }
    # Also try common Genymotion host-only interface & localhost TCP
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", "192.168.56.101:$($env:ADB_PORT)"))
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", "127.0.0.1:$($env:ADB_PORT)"))

    $devices = @(Get-OnlineDevices -AdbPath $adb)
    if ($deviceSerial) {
        if ($devices -contains $deviceSerial) {
            $hasDevice = $true
        } else {
            Write-Warn "Configured DEVICE_SERIAL=$deviceSerial not online. Online: $($devices -join ', ')"
        }
    } elseif ($devices.Count -gt 0) {
        $hasDevice = $true
        $deviceSerial = $devices[0]
        $env:DEVICE_SERIAL = $deviceSerial
        if ($deviceSerial -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):') {
            $env:ADB_HOST = $Matches[1]
            Write-Info "Detected network device IP: $($env:ADB_HOST)"
        }
        if ($devices.Count -gt 1) {
            Write-Warn "Multiple devices online ($($devices -join ', ')) -- using $deviceSerial (set DEVICE_SERIAL to pin)"
        }
    }

    if ($hasDevice) {
        if ($deviceSerial -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):') {
            $env:ADB_HOST = $Matches[1]
        }
        Write-Ok "Sandbox device: $deviceSerial (ADB_HOST=$($env:ADB_HOST))"
    } else {
        Write-Warn "No sandbox device connected. Start Genymotion (or AVD), then re-run."
        Write-Warn "Docker will still start -- static analysis works; dynamic will be skipped."
    }
} else {
    Write-Warn "adb not found -- install platform-tools or Genymotion tools"
    Write-Warn "Docker will still start -- dynamic analysis requires ADB"
}

$adbPort = $env:ADB_PORT
$fridaBinName = $env:SUDARSHAN_FRIDA_BIN
$fridaPort = $env:FRIDA_PORT

# -- Step 2: ADB TCP -----------------------------------------------------------
Write-Step 2 6 "Enabling ADB over TCP (port $adbPort)..."
if ($hasDevice -and $adb) {
    $r = Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "tcpip", $adbPort)
    if ($r.Out -match "error|failed|unable") {
        Write-Warn "TCP mode: $($r.Out) (ok if already TCP)"
    } else {
        Write-Ok "ADB TCP mode enabled on port $adbPort"
    }
    Start-Sleep -Seconds 1
    # Reconnect after tcpip (serial may become IP:port)
    if ($deviceSerial) {
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", $deviceSerial))
    }
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", "127.0.0.1:$adbPort"))
    $devices = @(Get-OnlineDevices -AdbPath $adb)
    if ($devices.Count -gt 0 -and ($devices -notcontains $deviceSerial)) {
        # Prefer matching IP or keep configured serial if still present
        if ($env:DEVICE_SERIAL -and ($devices -contains $env:DEVICE_SERIAL)) {
            $deviceSerial = $env:DEVICE_SERIAL
        } else {
            $deviceSerial = $devices[0]
            $env:DEVICE_SERIAL = $deviceSerial
        }
        Write-Info "Device serial after tcpip: $deviceSerial"
    }
} else {
    Write-Warn "Skipped (no device)"
}

# -- Step 3: Root --------------------------------------------------------------
Write-Step 3 6 "Restarting adbd as root..."
if ($hasDevice -and $adb) {
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "root"))
    Start-Sleep -Seconds 2
    # Root often drops the connection -- reconnect
    if ($deviceSerial) {
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", $deviceSerial))
    }
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", "127.0.0.1:$adbPort"))
    if ($deviceSerial -match "^\d+\.\d+\.\d+\.\d+:") {
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("connect", $deviceSerial))
    }
    $devices = @(Get-OnlineDevices -AdbPath $adb)
    if ($devices.Count -gt 0 -and ($devices -notcontains $deviceSerial)) {
        if ($env:DEVICE_SERIAL -and ($devices -contains $env:DEVICE_SERIAL)) {
            $deviceSerial = $env:DEVICE_SERIAL
        } else {
            $deviceSerial = $devices[0]
            $env:DEVICE_SERIAL = $deviceSerial
        }
    }

    $who = Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "whoami")
    if ($who.Out -match "root") {
        Write-Ok "adbd running as root (whoami=root)"
    } else {
        Write-Warn "whoami=$($who.Out) -- use a rooted Genymotion image (ROOT_REQUIRED=true)"
    }

    # SELinux permissive for Frida attach
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "setenforce", "0"))
} else {
    Write-Warn "Skipped (no device)"
}

# -- Step 4: Frida -------------------------------------------------------------
Write-Step 4 6 "Starting frida-server on sandbox..."
if ($hasDevice -and $adb) {
    $fridaRemotePath = "/data/local/tmp/$fridaBinName"
    $legacyRemote = "/data/local/tmp/frida-server"
    $hostFrida = Find-FridaHostBinary

    # Kill stale
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "pkill -f frida-server || true"))
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "pkill -f $fridaBinName || true"))
    Start-Sleep -Seconds 1

    # Push from host if we have the binary
    if ($hostFrida) {
        Write-Info "Pushing Frida from host: $hostFrida"
        $push1 = Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "push", $hostFrida, $fridaRemotePath) -TimeoutSec 120
        if ($push1.Ok -or $push1.Out -match "pushed|file pushed") {
            Write-Ok "Pushed -> $fridaRemotePath"
        } else {
            Write-Warn "Push to $fridaRemotePath failed: $($push1.Out)"
        }
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "chmod 755 $fridaRemotePath"))
        # Keep legacy path too (DAE auto-start looks for frida-server)
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "cp $fridaRemotePath $legacyRemote && chmod 755 $legacyRemote"))
    } else {
        Write-Warn "No local frida-server binary found under frida-server-17.16.4-android-x86_64\"
        Write-Warn "Download: https://github.com/frida/frida/releases/tag/17.16.4"
        Write-Warn "Extract frida-server-17.16.4-android-x86_64 into that folder, then re-run."
        # Try copy on-device if legacy already exists
        [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "if [ -f $legacyRemote ] && [ ! -f $fridaRemotePath ]; then cp $legacyRemote $fridaRemotePath && chmod 755 $fridaRemotePath; fi"))
    }

    $fridaListen = Get-FridaListenHost
    Start-FridaOnDevice -AdbPath $adb -Serial $deviceSerial -RemotePath $fridaRemotePath -ListenHost $fridaListen -Port $fridaPort
    Start-Sleep -Seconds 3

    $fridaUp = Test-FridaRunningOnDevice -AdbPath $adb -Serial $deviceSerial -FridaBinName $fridaBinName
    if (-not $fridaUp) {
        Start-FridaOnDevice -AdbPath $adb -Serial $deviceSerial -RemotePath $legacyRemote -ListenHost $fridaListen -Port $fridaPort
        Start-Sleep -Seconds 3
        $fridaUp = Test-FridaRunningOnDevice -AdbPath $adb -Serial $deviceSerial -FridaBinName $fridaBinName
    }

    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "forward", "tcp:27055", "tcp:$fridaPort"))
    [void](Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "forward", "tcp:27042", "tcp:$fridaPort"))

    if ($fridaUp) {
        Write-Ok "Frida agent running on ${fridaListen}:$fridaPort (forwarded 27055/27042)"
    } else {
        Write-Fail "Frida did NOT start -- dynamic analysis will be skipped"
        $logTail = Invoke-Adb -AdbPath $adb -AdbArguments @("-s", $deviceSerial, "shell", "tail -n 20 /data/local/tmp/frida-start.log 2>/dev/null || echo '(no frida-start.log)'")
        if ($logTail.Out) { Write-Warn "Frida log: $($logTail.Out)" }
        Write-Warn "Manual start: adb -s $deviceSerial shell `"nohup $fridaRemotePath -l ${fridaListen}:$fridaPort &`""
        Write-Warn "Or run: python scripts/setup_dynamic_analysis.py"
        if (-not $hostFrida) {
            Write-Warn "Place frida-server 17.16.4 x86_64 in frida-server-17.16.4-android-x86_64\ and re-run"
        }
    }
} else {
    Write-Warn "Skipped (no device)"
}

# -- Step 5: Docker preflight --------------------------------------------------
Write-Step 5 6 "Checking Docker..."
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

# -- Step 6: Compose up --------------------------------------------------------
Write-Step 6 6 "Starting Docker stack (Backend + Frontend + MobSF)..."
Write-Host ""
Write-Host "  Frontend Dashboard: http://localhost:5173" -ForegroundColor Cyan
Write-Host "  Backend REST API:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  MobSF Framework:    http://localhost:8008  (user: mobsf / pass: mobsf)" -ForegroundColor Cyan
Write-Host "  Analysis Engine:    http://analysis-engine:8001  (internal)" -ForegroundColor Cyan
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
