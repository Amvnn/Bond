<#
.SYNOPSIS
    Installs Bond for everyday use and puts a shortcut on the Desktop.

.DESCRIPTION
    Copies the release build to a stable location and creates (or refreshes) a
    Desktop shortcut pointing at it.

    Why it copies instead of shortcutting the build output directly: the build
    directory is disposable. `flutter clean` deletes it, and every rebuild
    replaces the exe while it may be running, which Windows refuses. A shortcut
    into build/ therefore breaks the first time the project is cleaned, and the
    user is left with an icon that does nothing. Installing to
    %LOCALAPPDATA%\Bond keeps the two concerns apart: developing and running.

    No elevation is needed. Everything lands under the current user's profile,
    nothing is written to the registry, and nothing is added to Windows startup
    - an app that launches itself at login is the user's decision to make, not
    the installer's. See -AddToStartup below.

.PARAMETER Build
    Run `flutter build windows --release` first. Without this the script uses
    whatever is already in build/, and refuses if there is nothing there.

.PARAMETER Profile
    Which installation profile the shortcut launches. Separate profiles get
    separate encrypted databases and separate OS-protected keys, so this is how
    a second, independent installation gets its own icon. Default: none, which
    means the app's own default profile.

.PARAMETER Server
    Override the server origin for this shortcut, e.g. https://bond.example.com.
    Default: the app's built-in default (local development).

.PARAMETER AddToStartup
    Also place a shortcut in the user's Startup folder so Bond opens at login.
    Off by default and never implied.

.EXAMPLE
    .\scripts\install-desktop.ps1 -Build

.EXAMPLE
    # A second icon for a separate installation, for testing two clients.
    .\scripts\install-desktop.ps1 -Profile two
#>

[CmdletBinding()]
param(
    [switch]$Build,
    [string]$Profile = '',
    [string]$Server = '',
    [switch]$AddToStartup
)

$ErrorActionPreference = 'Stop'

$repoRoot   = Split-Path -Parent $PSScriptRoot
$clientDir  = Join-Path $repoRoot 'client'
$releaseDir = Join-Path $clientDir 'build\windows\x64\runner\Release'
$brandIcon  = Join-Path $repoRoot 'brand\favicon.ico'

if ($Profile -ne '' -and $Profile -notmatch '^[A-Za-z0-9_-]{1,32}$') {
    throw "Profile '$Profile' is not valid. Use 1-32 characters of letters, digits, underscore or hyphen - it becomes a directory name."
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if ($Build) {
    Write-Host 'Building release...' -ForegroundColor Cyan

    # A running copy holds libsignal_frb.dll open and the build fails part-way
    # with a file-access error that does not name the cause. Close it first.
    $running = Get-Process -Name bond -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "  closing $($running.Count) running instance(s)" -ForegroundColor DarkGray
        $running | Stop-Process -Force
        Start-Sleep -Milliseconds 1200
    }

    Push-Location $clientDir
    try {
        & flutter build windows --release
        if ($LASTEXITCODE -ne 0) { throw "flutter build windows failed with exit code $LASTEXITCODE." }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path (Join-Path $releaseDir 'bond.exe'))) {
    throw "No release build at $releaseDir. Re-run with -Build."
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
$installDir = Join-Path $env:LOCALAPPDATA 'Bond'
Write-Host "Installing to $installDir" -ForegroundColor Cyan

# Stop anything running from the install directory, or the copy will fail.
Get-Process -Name bond -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($installDir, [StringComparison]::OrdinalIgnoreCase) } |
    ForEach-Object { $_ | Stop-Process -Force }
Start-Sleep -Milliseconds 400

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Mirror rather than merge: a stale DLL left behind by an older build is the
# kind of failure that takes an afternoon to find.
Get-ChildItem -Path $installDir -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $releaseDir '*') -Destination $installDir -Recurse -Force

$exePath = Join-Path $installDir 'bond.exe'
if (-not (Test-Path $exePath)) { throw "Copy completed but $exePath is missing." }

# The icon is kept beside the exe so the shortcut does not depend on the
# repository still being present, or still being at this path.
$iconPath = Join-Path $installDir 'bond.ico'
if (Test-Path $brandIcon) {
    Copy-Item -Path $brandIcon -Destination $iconPath -Force
} else {
    Write-Warning "brand\favicon.ico not found; the shortcut will use the icon compiled into the exe."
    $iconPath = $exePath
}

# ---------------------------------------------------------------------------
# Launcher
# ---------------------------------------------------------------------------
# A shortcut cannot set environment variables, and BOND_PROFILE / BOND_SERVER
# are read from the environment. When either is requested, the shortcut points
# at a tiny .cmd that sets them and then starts the exe detached.
$target    = $exePath
$arguments = ''

if ($Profile -ne '' -or $Server -ne '') {
    $launcher = Join-Path $installDir ("launch-" + ($(if ($Profile -ne '') { $Profile } else { 'default' })) + ".cmd")
    $lines = @('@echo off')
    if ($Profile -ne '') { $lines += "set BOND_PROFILE=$Profile" }
    if ($Server  -ne '') { $lines += "set BOND_SERVER=$Server" }
    # `start ""` returns immediately so no console window lingers.
    $lines += 'start "" "%~dp0bond.exe"'
    Set-Content -Path $launcher -Value $lines -Encoding ASCII
    $target = $launcher
}

# ---------------------------------------------------------------------------
# Shortcuts
# ---------------------------------------------------------------------------
$shortcutName = if ($Profile -ne '') { "Bond ($Profile).lnk" } else { 'Bond.lnk' }
$shell = New-Object -ComObject WScript.Shell

function New-BondShortcut([string]$path) {
    $link = $shell.CreateShortcut($path)
    $link.TargetPath       = $target
    $link.Arguments        = $arguments
    $link.WorkingDirectory = $installDir
    $link.IconLocation     = "$iconPath,0"
    $link.Description      = 'Bond - invite-only, end-to-end encrypted messenger'
    # Minimised console for the .cmd launcher; normal for a direct exe target.
    $link.WindowStyle      = if ($target -eq $exePath) { 1 } else { 7 }
    $link.Save()
}

$desktop  = [Environment]::GetFolderPath('Desktop')
$shortcut = Join-Path $desktop $shortcutName
New-BondShortcut $shortcut
Write-Host "Desktop shortcut: $shortcut" -ForegroundColor Green

# Start menu too: it is where people actually search for an app, and it costs
# one more file.
$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
if (Test-Path $startMenu) {
    New-BondShortcut (Join-Path $startMenu $shortcutName)
    Write-Host "Start menu entry: $(Join-Path $startMenu $shortcutName)" -ForegroundColor Green
}

if ($AddToStartup) {
    $startup = [Environment]::GetFolderPath('Startup')
    New-BondShortcut (Join-Path $startup $shortcutName)
    Write-Host "Will open at login: $(Join-Path $startup $shortcutName)" -ForegroundColor Green
} else {
    Write-Host 'Not added to startup. Pass -AddToStartup if you want it to open at login.' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host "  Installed:  $installDir"
if ($Profile -ne '') { Write-Host "  Profile:    $Profile" }
if ($Server  -ne '') { Write-Host "  Server:     $Server" }
Write-Host '  Re-run this script after a rebuild to update the installed copy.'
