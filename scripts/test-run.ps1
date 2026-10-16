<#
.SYNOPSIS
    Brings up everything needed to try Bond, and opens two windows.

.DESCRIPTION
    One command for the whole local stack: Docker, PostgreSQL, Redis, database
    migrations, the relay server, and two independent client installations side
    by side so there is someone to talk to.

    Each client runs under its own PROFILE. A profile is a genuinely separate
    installation - its own encrypted database, its own DPAPI-protected key, its
    own cryptographic device identity - not a second window onto one account.
    That is what makes the two windows a real test of the protocol rather than
    a demo of the interface.

    It is safe to re-run. Nothing is deleted unless you pass -Fresh.

.PARAMETER Fresh
    Wipe the server database AND both local installations first, so the run
    starts from nobody having an account. DESTRUCTIVE: any account you
    registered is destroyed, along with its message history.

.PARAMETER Second
    Name of the second installation's profile. Default: 'guest'.

.PARAMETER NoLaunch
    Bring the stack up but do not open any windows.

.EXAMPLE
    .\scripts\test-run.ps1

.EXAMPLE
    .\scripts\test-run.ps1 -Fresh
#>

[CmdletBinding()]
param(
    [switch]$Fresh,
    [string]$Second = 'guest',
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell wraps every stderr LINE from a native executable in an
# ErrorRecord, and with ErrorActionPreference='Stop' that makes ordinary
# progress output fatal - docker compose prints "Container ... Running" to
# stderr and the script would die on a successful call. So native commands run
# with the preference relaxed and are judged on their EXIT CODE, which is the
# only thing that actually reports failure.
function Invoke-Native {
    param(
        [Parameter(Mandatory)][scriptblock]$Block,
        [string]$What = 'command',
        [switch]$Quiet,
        [switch]$IgnoreExitCode
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Quiet) { & $Block 2>&1 | Out-Null } else { & $Block 2>&1 | Out-Host }
        if (-not $IgnoreExitCode -and $LASTEXITCODE -ne 0) {
            throw "$What failed (exit $LASTEXITCODE)."
        }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}

# Same relaxation, but returns the command's stdout instead of showing it.
function Get-Native {
    param([Parameter(Mandatory)][scriptblock]$Block)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { return (& $Block 2>$null) } finally { $ErrorActionPreference = $previous }
}

$repoRoot  = Split-Path -Parent $PSScriptRoot
$serverDir = Join-Path $repoRoot 'server'
$composeFile = Join-Path $repoRoot 'infra\docker-compose.yml'
$composeEnv  = Join-Path $repoRoot 'infra\.env'
$exePath   = Join-Path $env:LOCALAPPDATA 'Bond\bond.exe'
$profileRoot = Join-Path $env:APPDATA 'dev.privateconv\Bond\profiles'
$tsx = Join-Path $serverDir 'node_modules\.bin\tsx'

function Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Note($text) { Write-Host "    $text" -ForegroundColor DarkGray }
function Good($text) { Write-Host "    $text" -ForegroundColor Green }

if ($Second -notmatch '^[A-Za-z0-9_-]{1,32}$') {
    throw "Profile '$Second' is not valid. Letters, digits, underscore or hyphen, 1-32 characters."
}

# ---------------------------------------------------------------------------
# 1. Docker
# ---------------------------------------------------------------------------
Step 'Docker'
$dockerUp = $false
$code = Invoke-Native { docker version --format '{{.Server.Version}}' } -Quiet -IgnoreExitCode
$dockerUp = ($code -eq 0)

if (-not $dockerUp) {
    Note 'daemon not responding; starting Docker Desktop'
    $dd = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
    if (Test-Path $dd) { Start-Process $dd } else { throw 'Docker Desktop is not installed at the default path.' }

    $deadline = (Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 4
        $code = Invoke-Native { docker version --format '{{.Server.Version}}' } -Quiet -IgnoreExitCode
        if ($code -eq 0) { $dockerUp = $true; break }
    }
    if (-not $dockerUp) { throw 'Docker did not become ready within 3 minutes.' }
}
Good 'daemon ready'

# ---------------------------------------------------------------------------
# 2. PostgreSQL + Redis
# ---------------------------------------------------------------------------
Step 'PostgreSQL and Redis'
Invoke-Native { docker compose --env-file $composeEnv -f $composeFile up -d } -What 'docker compose up' -Quiet | Out-Null
Good 'containers running'

# ---------------------------------------------------------------------------
# 3. Schema
# ---------------------------------------------------------------------------
Step 'Database schema'
Push-Location $serverDir
try {
    Invoke-Native { & $tsx --env-file=.env src/database/migrate.ts } -What 'migrations' | Out-Null

    if ($Fresh) {
        Step 'Resetting (destroys all accounts and messages)'
        Invoke-Native { & $tsx --env-file=.env scripts/reset-dev.ts } -What 'reset' | Out-Null
    }
} finally {
    Pop-Location
}

if ($Fresh) {
    foreach ($p in @('default', $Second)) {
        $dir = Join-Path $profileRoot $p
        if (Test-Path $dir) {
            # Close anything holding the database open first.
            Get-Process -Name bond -ErrorAction SilentlyContinue | Stop-Process -Force
            Start-Sleep -Milliseconds 900
            Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
            Note "cleared local installation '$p'"
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Relay server
#
# ALLOW_BOOTSTRAP_ACCOUNT is the env-gated path that creates user #1. Nobody
# can invite the first account, so without it a fresh database can never get
# started. It is a privileged account-creation path and the config refuses to
# boot with it in production.
# ---------------------------------------------------------------------------
Step 'Relay server'
$healthy = $false
try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:3000/health' -UseBasicParsing -TimeoutSec 3
    $healthy = ($r.StatusCode -eq 200)
} catch { $healthy = $false }

if ($healthy) {
    Good 'already running on :3000'
} else {
    Note 'starting on :3000 with the bootstrap account enabled'
    $cmd = "set ALLOW_BOOTSTRAP_ACCOUNT=true&& set LOG_LEVEL=warn&& `"$tsx`" --env-file=.env src/server.ts"
    Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd -WorkingDirectory $serverDir -WindowStyle Minimized

    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 700
        try {
            $r = Invoke-WebRequest -Uri 'http://127.0.0.1:3000/health' -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { $healthy = $true; break }
        } catch {}
    }
    if (-not $healthy) { throw 'The server did not become healthy. Check the minimised console window.' }
    Good 'healthy'
}

# ---------------------------------------------------------------------------
# 5. Who already exists
# ---------------------------------------------------------------------------
$accounts = @()
$raw = Get-Native {
    docker exec privatemessenger-postgres-1 psql -U messenger -d privatemessenger `
        -t -A -c 'SELECT username FROM users ORDER BY created_at;'
}
if ($raw) { $accounts = @($raw | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }

Step 'Accounts on the server'
if ($accounts.Count -eq 0) {
    Good 'none - the first registration will use the bootstrap path'
} else {
    foreach ($a in $accounts) { Note $a }
}

# ---------------------------------------------------------------------------
# 6. Clients
# ---------------------------------------------------------------------------
if ($NoLaunch) {
    Write-Host ''
    Write-Host 'Stack is up. Not launching clients (-NoLaunch).' -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $exePath)) {
    throw "Bond is not installed at $exePath. Run: .\scripts\install-desktop.ps1 -Build"
}

Step 'Clients'
Get-Process -Name bond -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 900

foreach ($p in @('default', $Second)) {
    $env:BOND_PROFILE = $p
    Start-Process -FilePath $exePath
    Note "opened '$p'"
    Start-Sleep -Seconds 2
}
$env:BOND_PROFILE = $null

Start-Sleep -Seconds 5
$running = @(Get-Process -Name bond -ErrorAction SilentlyContinue)
Good "$($running.Count) window(s) open"

# ---------------------------------------------------------------------------
# What to do next
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'WHAT TO TRY' -ForegroundColor Cyan
Write-Host ''
if ($accounts.Count -eq 0) {
    Write-Host '  1. In "Bond" (the default window): Register. Leave the invitation'
    Write-Host '     field EMPTY - this is the first account, so it uses bootstrap.'
    Write-Host '     Then "Generate and register this device".'
} else {
    Write-Host "  1. In ""Bond"" (the default window): Sign in as one of: $($accounts -join ', ')"
}
Write-Host '  2. Invite (top right) -> Create an invitation -> Copy. It is shown'
Write-Host '     ONCE; the server stores only an HMAC of it.'
Write-Host "  3. In ""Bond - $Second"": Register with a different username and PASTE"
Write-Host '     that token. Then register its device.'
Write-Host '  4. Pick the contact in either window and send a message. Watch the'
Write-Host '     other window receive it live, and the state under your own'
Write-Host '     message go sending -> sent -> delivered -> read.'
Write-Host ''
Write-Host '  Worth doing once: the shield icon -> compare the 60 digits in both'
Write-Host '  windows. They match. That comparison is the only thing in the system'
Write-Host '  that proves the keys belong to the people - everything else just'
Write-Host '  protects traffic between two keys.'
Write-Host ''
Write-Host '  Offline delivery: close one window, send to it from the other, then'
Write-Host '  reopen it. The message is waiting, and it decrypts after a restart.'
Write-Host ''
Write-Host 'NOTE' -ForegroundColor Yellow
Write-Host '  The server is running with ALLOW_BOOTSTRAP_ACCOUNT=true, which must'
Write-Host '  be off outside local development.'
Write-Host ''
