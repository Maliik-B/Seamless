# clean-uninstall.ps1
# ---------------------------------------------------------------------------
# Companion to dist/joiner/uninstall.cmd. This is the host-side / own-build
# version: same behaviour, but PowerShell so it can use the same
# elevated-refusal + PS7-only pattern as our other host scripts. Closes
# ticket H-24 in the DS2 Seamless hardening backlog.
#
# What this script does:
#   1. Refuses to run elevated (consistent with our other install scripts).
#   2. Refuses to run on PowerShell 5.1 (we standardise on 7+).
#   3. Refuses to run while DarkSoulsII.exe is in the process list.
#   4. Locates the DS2 Game directory (auto-detects, or pass -GameDir).
#   5. Asks the user to confirm before deleting (skip with -Force).
#   6. Removes dinput8.dll, ds2_seamless_coop.ini, ds2_server_public.key
#      from the Game folder. Leaves DarkSoulsII.exe and everything else
#      untouched.
#   7. Leaves workspace backups in $BackupRoot untouched and prints the
#      path so the user can restore manually if needed.
#
# Out of scope until H-01 lands:
#   AppData save-folder restore. H-01 (save segregation) hasn't shipped
#   yet, so today the mod doesn't swap saves and there is nothing for
#   uninstall to restore. Stubbed below as a TODO.
#
# Usage:
#   pwsh -File .\tools\clean-uninstall.ps1
#   pwsh -File .\tools\clean-uninstall.ps1 -GameDir 'D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game'
#   pwsh -File .\tools\clean-uninstall.ps1 -Force   # skip the y/N prompt
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [string]$GameDir = '',
    [string]$BackupRoot = 'D:\Applications\DS2\backups',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Preconditions ---------------------------------------------------------
if (Test-Admin) {
    Write-Host 'REFUSING to run as Administrator. Open a non-elevated PowerShell.' -ForegroundColor Red
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host 'Requires PowerShell 7+.' -ForegroundColor Red
    Write-Host "Re-run with:  pwsh -File `"$PSCommandPath`""
    exit 1
}

# Deleting dinput8.dll while the game has it mapped would leave Steam's
# Verify Integrity reporting missing files on the next launch.
$running = Get-Process -Name 'DarkSoulsII' -ErrorAction SilentlyContinue
if ($running) {
    Write-Host 'DarkSoulsII.exe is running. Close the game first.' -ForegroundColor Red
    exit 1
}

# --- Locate Game folder ----------------------------------------------------
if (-not $GameDir) {
    $candidates = @(
        'C:\Program Files (x86)\Steam\steamapps\common\Dark Souls II Scholar of the First Sin\Game',
        'C:\Program Files\Steam\steamapps\common\Dark Souls II Scholar of the First Sin\Game',
        'D:\Steam\steamapps\common\Dark Souls II Scholar of the First Sin\Game',
        'D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game',
        'E:\Steam\steamapps\common\Dark Souls II Scholar of the First Sin\Game',
        'E:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game',
        'F:\Steam\steamapps\common\Dark Souls II Scholar of the First Sin\Game',
        'F:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game'
    )
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c 'DarkSoulsII.exe')) { $GameDir = $c; break }
    }
}

if (-not $GameDir -or -not (Test-Path (Join-Path $GameDir 'DarkSoulsII.exe'))) {
    Write-Host 'Could not auto-detect DS2 SOTFS Game folder.' -ForegroundColor Red
    Write-Host 'In Steam: right-click DS2 SOTFS -> Manage -> Browse Local Files.'
    Write-Host 'Then re-run with:  pwsh -File .\tools\clean-uninstall.ps1 -GameDir "<that path>\Game"'
    exit 1
}

Write-Host ("DS2 Game folder: $GameDir")

$installedFiles = @('dinput8.dll', 'ds2_seamless_coop.ini', 'ds2_server_public.key')

Write-Host ''
Write-Host 'The following files will be removed if present:'
foreach ($f in $installedFiles) { Write-Host "  $f" }
Write-Host ''
Write-Host 'Your DS2 saves and DarkSoulsII.exe will NOT be touched.'
Write-Host ''

if (-not $Force) {
    $confirm = Read-Host 'Proceed? [y/N]'
    if ($confirm -notmatch '^[Yy]') {
        Write-Host 'Aborted. No files modified.' -ForegroundColor Yellow
        exit 0
    }
    Write-Host ''
}

# --- Remove ----------------------------------------------------------------
$removed = 0
$skipped = 0
foreach ($f in $installedFiles) {
    $target = Join-Path $GameDir $f
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Force
        if (Test-Path -LiteralPath $target) {
            Write-Host "  ${f}: FAILED to remove. Check file permissions." -ForegroundColor Red
            exit 1
        }
        Write-Host "  ${f}: removed."
        $removed++
    } else {
        Write-Host "  ${f}: not present."
        $skipped++
    }
}

# TODO when H-01 lands: restore swapped AppData\Roaming\DarkSoulsII save
# folder from the bind-mount or rename performed at install time.

Write-Host ''
Write-Host "Uninstall complete. Removed $removed file(s); skipped $skipped not-present file(s)."
if (Test-Path -LiteralPath $BackupRoot) {
    Write-Host ''
    Write-Host 'Workspace backups remain in:'
    Write-Host "  $BackupRoot"
    Write-Host 'These are NOT touched. Restore manually if needed.'
}
Write-Host ''
Write-Host 'In Steam: right-click DS2 -> Properties -> Local Files -> Verify integrity'
Write-Host 'of game files. It should now report no missing files.'
