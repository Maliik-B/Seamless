# DS2 Seamless Co-op -- Layer 2 defense-in-depth
#
# Blocks all outbound traffic from DarkSoulsII.exe to the public Internet
# (anything not on the local subnet, and not loopback). Loopback and LAN
# remain allowed so the mod localhost P2P server and any future LAN-based
# joiner testing keep working.
#
# Pair this with layer 3 (mod-internal ConnectHook off-allowlist refusal)
# and layer 4 (Resource Monitor / Wireshark observing during the test) to
# get defense-in-depth coverage for the H-26 online-flag-accessor patch,
# which expanded the engine "online" state to all 34 callers and may
# unlock outbound traffic the existing mod hooks were never designed to
# cover (HTTPS to FROM / Bandai-Namco auth servers, port-80 status probes,
# etc.).
#
# RUN AS ADMINISTRATOR (modifying Windows Firewall requires elevation).
#
# To verify after add:
#   Get-NetFirewallRule -DisplayName "DS2 Seamless - Block outbound to Internet"
#
# To remove:
#   See "REMOVE" section at the bottom of this file.

$ErrorActionPreference = "Stop"

$ruleName = "DS2 Seamless - Block outbound to Internet"
$exePath  = "D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\DarkSoulsII.exe"

# Sanity-check the exe path before adding the rule.
if (-not (Test-Path $exePath)) {
    Write-Error "DarkSoulsII.exe not found at: $exePath"
    Write-Error "Edit `$exePath in this script to match your install location."
    exit 1
}

# Refuse to add a duplicate. If the rule already exists, surface that.
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Rule already exists:" -ForegroundColor Yellow
    $existing | Format-List DisplayName, Action, Direction, Enabled, Profile
    Write-Host "To replace, run the REMOVE block at the bottom of this file first." -ForegroundColor Yellow
    exit 0
}

Write-Host "Adding firewall rule: $ruleName" -ForegroundColor Cyan
Write-Host "  Program:        $exePath"
Write-Host "  Direction:      Outbound"
Write-Host "  Action:         Block"
Write-Host "  Remote address: Internet (excludes loopback + local subnet)"
Write-Host ""

$rule = New-NetFirewallRule `
    -DisplayName   $ruleName `
    -Direction     Outbound `
    -Action        Block `
    -Program       $exePath `
    -RemoteAddress Internet `
    -Profile       Any `
    -Enabled       True

Write-Host "Rule added." -ForegroundColor Green
$rule | Format-List DisplayName, Action, Direction, Enabled, Profile

Write-Host ""
Write-Host "What this catches:" -ForegroundColor Cyan
Write-Host "  - HTTPS to FROM / Bandai-Namco auth servers (port 443)"
Write-Host "  - Port-80 HTTP probes to Cloudflare-fronted status servers"
Write-Host "  - WSAConnect / ConnectEx / UDP sendto / WinHTTP -- anything"
Write-Host "    DS2 might use that the mod connect() hook does not see"
Write-Host ""
Write-Host "What still works:" -ForegroundColor Cyan
Write-Host "  - 127.0.0.0/8 (mod localhost P2P server)"
Write-Host "  - Local LAN (future joiner testing)"
Write-Host "  - Steam itself (this rule is per-process on DarkSoulsII.exe)"
Write-Host ""
Write-Host "To REMOVE this rule later, run this in an elevated PowerShell:"
Write-Host "  Remove-NetFirewallRule -DisplayName `"$ruleName`""

# ============================================================================
# REMOVE block -- paste into an elevated PowerShell to delete the rule.
# Leaving here as a comment block so the path / name are co-located with add.
#
# Remove-NetFirewallRule -DisplayName "DS2 Seamless - Block outbound to Internet"
# ============================================================================
