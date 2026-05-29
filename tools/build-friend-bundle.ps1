# Build the friend-bundle zip from the current H26Repro build + the
# deployed RSA public key + the current ds2_seamless_coop.ini (the host's
# version, with its server_ip).
#
# Run after each rebuild of the mod or after you change the host's
# Tailscale / LAN IP. Hand the emitted zip to friends along with your
# ds3os password (which is NOT in the bundle for privacy -- communicate
# it separately via a private channel).
#
# ASCII only per repo convention.
#
# Usage:
#   .\tools\build-friend-bundle.ps1
# Or to override paths:
#   .\tools\build-friend-bundle.ps1 -OutDir 'D:\path\to\out' -DllPath '...'

[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),

    [string]$DllPath = $null,    # default: $RepoRoot\build\H26Repro\bin\RelWithDebInfo\dinput8.dll

    [string]$KeyPath = (Join-Path 'D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game' 'ds2_server_public.key'),

    [string]$IniPath = (Join-Path 'D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game' 'ds2_seamless_coop.ini'),

    [string]$OutDir = 'D:\Applications\DS2\friend-bundle'
)

$ErrorActionPreference = 'Stop'

if (-not $DllPath) {
    $DllPath = Join-Path $RepoRoot 'build\H26Repro\bin\RelWithDebInfo\dinput8.dll'
}

Write-Host "RepoRoot:   $RepoRoot"
Write-Host "DllPath:    $DllPath"
Write-Host "KeyPath:    $KeyPath"
Write-Host "IniPath:    $IniPath"
Write-Host "OutDir:     $OutDir"
Write-Host ""

# Sanity checks.
foreach ($p in @($DllPath, $KeyPath, $IniPath)) {
    if (-not (Test-Path $p)) {
        Write-Error "Required file not found: $p"
        exit 1
    }
}

# Stage in a clean subfolder.
$staging = Join-Path $OutDir 'staging'
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Force $staging | Out-Null
New-Item -ItemType Directory -Force $OutDir  | Out-Null

Copy-Item $DllPath (Join-Path $staging 'dinput8.dll')
Copy-Item $KeyPath (Join-Path $staging 'ds2_server_public.key')
Copy-Item $IniPath (Join-Path $staging 'ds2_seamless_coop.ini')

# README is generated fresh each time so it picks up the current
# server_ip from the ini.
$ini = Get-Content $IniPath -Raw
$serverIpMatch = [regex]::Match($ini, '(?m)^\s*server_ip\s*=\s*([^\s#;]+)')
$serverIp = if ($serverIpMatch.Success) { $serverIpMatch.Groups[1].Value.Trim() } else { '<host-IP>' }

# Detect VPN type from IP range so the README's prereqs section says
# the right thing.
#   100.x.x.x in 100.64.0.0/10 -> Tailscale (CGNAT)
#   25.x.x.x                   -> Hamachi
#   192.168.x.x / 10.x.x.x     -> LAN-direct
#   anything else              -> generic
$vpnPrereqs = switch -Regex ($serverIp) {
    '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.' {
@"
2. You install Tailscale (https://tailscale.com/download) and accept
   the share-link your friend sends you. Verify in the Tailscale admin
   console that you can see their machine.
"@
        break
    }
    '^25\.' {
@"
2. You install Hamachi (https://vpn.net), create a free LogMeIn account,
   then Network -> Join an existing network with the network ID and
   password your friend gives you. Verify in the Hamachi window that
   their machine shows up with a green dot (online).
"@
        break
    }
    '^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)' {
@"
2. You are on the same LAN as your friend's machine. Confirm you can
   reach their LAN IP (ask them to verify it pings from your machine).
"@
        break
    }
    default {
@"
2. You have network reachability to your friend's machine at the IP
   above. Confirm whatever VPN / network setup they told you about is
   working.
"@
    }
}

$readme = @"
DS2 Seamless Co-op -- friend setup
===================================

You're getting this from a friend who wants to play DS2 co-op with you
through an unofficial server. Here is what you are running and what to do
with it.

WHAT IS THIS
------------

Four files including this README:

  dinput8.dll              - Mod DLL. Built by your friend from
                             https://github.com/Maliik-B/Seamless. You can
                             check out the repo if you want to verify the
                             source; the build is reproducible from there.

  ds2_server_public.key    - The RSA public key for the custom server your
                             friend is running (a self-built ds3os
                             instance, https://github.com/TLeonardUK/ds3os).
                             Public-key material; safe to share over any
                             channel.

  ds2_seamless_coop.ini    - Mod config, already pointed at your friend's
                             server IP ($serverIp).

KNOWN UNKNOWNS / RISKS
----------------------

- Custom servers for DS2 are a grey area in FROM/Bandai's ToS. ds3os
  isolates its saves so retail saves aren't touched, but no written
  guarantee against account action.

- ds3os flags DS2 specifically as "Experimental, high probability of
  things not behaving correctly." First session expect occasional
  disconnect popups; the mod's auto-reconnect handles them.

- If something goes badly mid-session, hit Ctrl+Shift+End and the mod
  reverts itself to vanilla without alt-F4.

PREREQS
-------

1. You own DS2: Scholar of the First Sin on Steam.
$vpnPrereqs

INSTALL
-------

1. Find your DS2 install directory (it has DarkSoulsII.exe in it).
   Default Steam path:
   C:\Program Files (x86)\Steam\steamapps\common\Dark Souls II Scholar of the First Sin\Game\

2. Copy ALL FOUR files (dinput8.dll, ds2_server_public.key,
   ds2_seamless_coop.ini, README.txt) into that Game folder.

3. Confirm:
   - You see dinput8.dll next to DarkSoulsII.exe.
   - Your friend has told you their ds3os server is running.
   - Your VPN / network path to their machine is up.

LAUNCH
------

Run DS2 normally through Steam. The mod loads automatically. A brief
"DSOS - Welcome" popup at the title screen means you connected to the
custom server.

LOGS
----

The mod writes ds2_seamless_coop.log next to DarkSoulsII.exe. If
something is not working, that file has the diagnostic lines starting
with [NET], [REDIRECT], [SEAMLESS]. Send it to your friend if you need
help debugging.

UNINSTALL
---------

Delete dinput8.dll from the Game folder. DS2 returns to vanilla
behavior immediately. The other three files do nothing without
dinput8.dll; can be left or deleted.

ds3os PASSWORD
--------------

Your friend may have set a password on their ds3os server. Ask them
for it through your private channel.
"@

Set-Content -Path (Join-Path $staging 'README.txt') -Value $readme -Encoding ASCII

# Build the zip.
$zip = Join-Path $OutDir 'ds2-coop-friend-pack.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip
$info = Get-Item $zip
$sha = (Get-FileHash $zip -Algorithm SHA256).Hash

Write-Host ""
Write-Host "Bundle: $zip"
Write-Host "Size:   $($info.Length) bytes"
Write-Host "SHA256: $sha"
Write-Host ""
Write-Host "Contents:"
Get-ChildItem $staging | ForEach-Object {
    Write-Host ("  {0,-30} {1,10} bytes" -f $_.Name, $_.Length)
}
