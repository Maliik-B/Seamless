# regenerate-webui-credentials.ps1
# ---------------------------------------------------------------------------
# Generates fresh credentials for the ds3os Web UI admin panel. Closes the
# script-side half of ticket H-29 (WebUI authentication) in the DS2 Seamless
# hardening backlog.
#
# Context: v1.2.0 ships with both WebUIServerPassword="" and
# WebUIServerUsername="" in Server\Saved\default\config.json. The ds3os WebUI
# listens on port 50005. With empty credentials, anyone reachable on the
# host's VPN can admin the seamless server (bans, view player list, view
# blood-message DB, etc.). See phase-0-forensics.md F-4 and ticket H-29.
#
# What this script does:
#   1. Refuses to run elevated (consistent with our other install scripts).
#   2. Refuses to run on PowerShell 5.1 (needs RandomNumberGenerator.GetBytes
#      static method, PS 7+).
#   3. Locates the server data directory (auto-detects, or use -ServerDataDir).
#   4. Detects whether both credential fields are empty (the v1.2.0 default).
#      If so, ALWAYS regenerates. If not, requires -Force.
#   5. Backs up config.json to .bak-<timestamp>.
#   6. Generates a username 'host-<8 random alphanumeric>' and a 32-char
#      alphanumeric password from a CSPRNG.
#   7. Edits config.json in place via targeted regex replacement, preserving
#      indentation, key order, CRLF line endings, and UTF-8-no-BOM encoding.
#   8. Verifies the edit by re-reading the file and checking both fields.
#   9. Prints the credentials ONCE to stdout for the host to save.
#
# What this script does NOT do:
#   - It does NOT bind the WebUI to loopback-only. The ds3os config schema
#     has no WebUI-specific bind-address field; that change belongs in the
#     server source (separate H-29 sub-ticket, mirrors how joiner-side
#     fingerprint pinning split off from H-30).
#   - It does NOT change WebUIServerPort (50005 is fine; the auth fix is the
#     critical part).
#
# Usage:
#   pwsh -File .\tools\regenerate-webui-credentials.ps1
#   pwsh -File .\tools\regenerate-webui-credentials.ps1 -ServerDataDir 'C:\path\to\Server\Saved\default'
#   pwsh -File .\tools\regenerate-webui-credentials.ps1 -Force   # overwrite even non-default creds
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [string]$ServerDataDir = '',
    [int]$PasswordLength = 32,
    [int]$UsernameSuffixLength = 8,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RandomAlphanumeric {
    param([int]$Length)
    # Cryptographically secure: rejection-sampled bytes mapped onto a
    # 62-char alphabet. We over-sample to keep the loop tight in the
    # common case (62/256 ~= 0.24 acceptance per byte).
    $alphabet = [char[]]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $out = [System.Text.StringBuilder]::new($Length)
    $buf = New-Object byte[] 4096
    while ($out.Length -lt $Length) {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
        foreach ($b in $buf) {
            if ($b -lt 248) {
                # 248 = 4 * 62; values 248..255 are rejected to avoid modulo bias.
                [void]$out.Append($alphabet[$b % 62])
                if ($out.Length -ge $Length) { break }
            }
        }
    }
    return $out.ToString()
}

# --- Preconditions ---------------------------------------------------------
if (Test-Admin) {
    Write-Host 'REFUSING to run as Administrator. Open a non-elevated PowerShell.' -ForegroundColor Red
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host 'Requires PowerShell 7+ for RandomNumberGenerator.Fill.' -ForegroundColor Red
    Write-Host "Re-run with:  pwsh -File `"$PSCommandPath`""
    exit 1
}

# --- Locate the server data dir --------------------------------------------
if (-not $ServerDataDir) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates = @(
        # If this script is shipped inside the host bundle:
        (Join-Path (Split-Path -Parent $here) 'Server\Saved\default'),
        # If this script is run from the fork's tools dir against a sibling staging:
        'D:\Applications\DS2\staging\host\Server\Saved\default',
        # Or against the DS2 Game folder's server install:
        'C:\Program Files (x86)\Steam\steamapps\common\Dark Souls II Scholar of the First Sin\Game\Server\Saved\default',
        'D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\Server\Saved\default'
    )
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c 'config.json')) { $ServerDataDir = $c; break }
    }
}

if (-not $ServerDataDir -or -not (Test-Path $ServerDataDir)) {
    Write-Host 'Could not locate Server\Saved\default. Pass -ServerDataDir explicitly.' -ForegroundColor Red
    exit 1
}

$configPath = Join-Path $ServerDataDir 'config.json'
if (-not (Test-Path $configPath)) {
    Write-Host "config.json not found at: $configPath" -ForegroundColor Red
    exit 1
}

Write-Host ("Server data dir: $ServerDataDir")

# --- Read the config (preserve raw bytes/line endings/encoding) ------------
$raw = [System.IO.File]::ReadAllText($configPath, [System.Text.UTF8Encoding]::new($false))

# Pull out the current values via the same regex we'll use to edit, so the
# detection and the edit can't disagree on what counts as the field.
$userRx = '"WebUIServerUsername"\s*:\s*"((?:[^"\\]|\\.)*)"'
$passRx = '"WebUIServerPassword"\s*:\s*"((?:[^"\\]|\\.)*)"'

$mUser = [regex]::Match($raw, $userRx)
$mPass = [regex]::Match($raw, $passRx)

if (-not $mUser.Success) {
    Write-Host 'WebUIServerUsername field not found in config.json. Aborting.' -ForegroundColor Red
    exit 1
}
if (-not $mPass.Success) {
    Write-Host 'WebUIServerPassword field not found in config.json. Aborting.' -ForegroundColor Red
    exit 1
}

$curUser = $mUser.Groups[1].Value
$curPass = $mPass.Groups[1].Value
$isDefault = ($curUser -eq '' -and $curPass -eq '')

if ($isDefault) {
    Write-Host 'Both WebUI credentials are empty (the v1.2.0 default). Regenerating.' -ForegroundColor Yellow
} else {
    $userPreview = if ($curUser) { $curUser } else { '(empty)' }
    $passPreview = if ($curPass) { '(set, ' + $curPass.Length + ' chars)' } else { '(empty)' }
    Write-Host ("Current WebUIServerUsername: $userPreview")
    Write-Host ("Current WebUIServerPassword: $passPreview")
    if (-not $Force) {
        Write-Host ''
        Write-Host 'At least one credential is non-empty. Pass -Force to overwrite anyway.'
        Write-Host 'Skipping regeneration.'
        exit 0
    }
    Write-Host '-Force set: overwriting existing credentials.' -ForegroundColor Yellow
}

# --- Backup ---------------------------------------------------------------
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$bak = "$configPath.bak-$stamp"
Copy-Item -LiteralPath $configPath -Destination $bak -Force
Write-Host ("Backed up: config.json -> $(Split-Path -Leaf $bak)")

# --- Generate credentials --------------------------------------------------
$suffix   = New-RandomAlphanumeric -Length $UsernameSuffixLength
$username = "host-$suffix"
$password = New-RandomAlphanumeric -Length $PasswordLength

# Alphanumeric only, so no JSON escaping required. Assert to make the
# property explicit instead of implicit:
if ($username -match '[^A-Za-z0-9\-]') { throw "Generated username contains unexpected chars: $username" }
if ($password -match '[^A-Za-z0-9]')   { throw "Generated password contains unexpected chars." }

# --- Edit config.json (preserve indentation, key order, CRLF, no BOM) ------
# We use a single-shot regex replacement on each field. The replacement
# strings are emitted as their own JSON-string form, manually, since we
# constrained the inputs to alphanumeric-only above.
$newRaw = [regex]::Replace($raw, $userRx, ('"WebUIServerUsername": "' + $username + '"'))
$newRaw = [regex]::Replace($newRaw, $passRx, ('"WebUIServerPassword": "' + $password + '"'))

if ($newRaw -eq $raw) {
    throw 'Edit produced no change. The regex did not match anything to replace.'
}

[System.IO.File]::WriteAllText($configPath, $newRaw, [System.Text.UTF8Encoding]::new($false))

# --- Verify by re-reading --------------------------------------------------
$verifyRaw = [System.IO.File]::ReadAllText($configPath, [System.Text.UTF8Encoding]::new($false))
$vUser = [regex]::Match($verifyRaw, $userRx)
$vPass = [regex]::Match($verifyRaw, $passRx)
if (-not $vUser.Success -or $vUser.Groups[1].Value -ne $username) {
    throw "Verification failed: username field not as expected after write."
}
if (-not $vPass.Success -or $vPass.Groups[1].Value -ne $password) {
    throw "Verification failed: password field not as expected after write."
}

# Sanity: structure should still parse as JSON.
try {
    $null = $verifyRaw | ConvertFrom-Json -Depth 100
} catch {
    throw "Verification failed: config.json no longer parses as JSON after edit. ($_)"
}

Write-Host ("Wrote: $configPath")
Write-Host 'Verify (re-read + JSON parse): OK'

# --- Print credentials once ------------------------------------------------
Write-Host ''
Write-Host '=========================================================='
Write-Host 'NEW WEBUI CREDENTIALS (save these now — printed only once):'
Write-Host "  Username: $username"
Write-Host "  Password: $password"
Write-Host '=========================================================='
Write-Host ''
Write-Host "WebUI listens on port $((($verifyRaw | ConvertFrom-Json).WebUIServerPort))."
Write-Host 'Reach it from this host at http://127.0.0.1:50005/ and log in with the above.'
Write-Host ''
Write-Host 'NOTE: This script only fixes the empty-credentials half of H-29. The'
Write-Host 'ds3os config schema has no WebUI-specific bind-address field, so'
Write-Host 'binding the WebUI to loopback-only is a server-source change tracked'
Write-Host 'as a follow-up to H-29. Until that lands, do not advertise the server'
Write-Host 'to a hostile network without firewalling port 50005.'
