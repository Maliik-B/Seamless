# regenerate-server-keys.ps1
# ---------------------------------------------------------------------------
# Replaces the bundled ds3os default RSA keypair with a fresh per-install
# one. Closes ticket H-30 in the DS2 Seamless hardening backlog: in v1.2.0
# the SAME RSA private key ships with every download. Anyone with the bundle
# can impersonate any v1.2.0 host. This script regenerates a unique 2048-bit
# RSA keypair on the host machine and writes it in the PKCS#1 PEM format the
# ds3os server expects.
#
# What this script does:
#   1. Refuses to run elevated (consistent with our other install scripts).
#   2. Refuses to run on PowerShell 5.1 (needs .NET 5+'s ExportRSAPublicKeyPem).
#   3. Locates the server data directory (auto-detects, or use -ServerDataDir).
#   4. Detects whether the current keys are the well-known v1.2.0 defaults
#      by SHA-256 hash. If so, ALWAYS regenerates. If not, requires -Force.
#   5. Backs up current keys to .bak-<timestamp> sibling files.
#   6. Generates a fresh RSA-2048 keypair.
#   7. Writes the new private + public keys in PKCS#1 PEM (BEGIN RSA PUBLIC KEY).
#   8. Verifies the new keypair by signing and verifying a test buffer.
#   9. Prints the new public-key fingerprint (SHA-256 of the DER bytes). The
#      host shares this fingerprint with joiners out of band so joiners can
#      pin it (TOFU; the joiner-side pinning is a follow-on H-30 task).
#
# Why this matters:
#   The ds3os server uses RSA to authenticate the matchmaking-style traffic.
#   With v1.2.0 every host runs with the same private key, so any v1.2.0 user
#   can impersonate any other v1.2.0 host. After this script runs, the host's
#   private key is unique to this machine. The bundled public key file that
#   ships with the joiner bundle becomes obsolete; joiners need the host's
#   new public-key fingerprint to verify the server's identity.
#
# Usage:
#   pwsh -File .\tools\regenerate-server-keys.ps1
#   pwsh -File .\tools\regenerate-server-keys.ps1 -ServerDataDir 'C:\path\to\Server\Saved\default'
#   pwsh -File .\tools\regenerate-server-keys.ps1 -Force   # overwrite even non-default keys
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [string]$ServerDataDir = '',
    [int]$KeySize = 2048,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# v1.2.0 well-known defaults — SHA-256 of the bundled key files.
# Matching either of these means the install is using the shared key and
# should be regenerated unconditionally.
$WellKnownHashes = @{
    'private.key' = 'B2BA7CA5C5DD86EAB855B0D282F6D63B9C4F01B62EF6071C49DECA6429F0EFF9'
    'public.key'  = '888DC2A0EE20A14A341381AF4D881BA55644896663AB3AE1BBD56486E567A3C8'
}

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
    Write-Host 'Requires PowerShell 7+ for the PEM export APIs.' -ForegroundColor Red
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
        if (Test-Path (Join-Path $c 'private.key')) { $ServerDataDir = $c; break }
    }
}

if (-not $ServerDataDir -or -not (Test-Path $ServerDataDir)) {
    Write-Host 'Could not locate Server\Saved\default. Pass -ServerDataDir explicitly.' -ForegroundColor Red
    exit 1
}

$privPath = Join-Path $ServerDataDir 'private.key'
$pubPath  = Join-Path $ServerDataDir 'public.key'

Write-Host ("Server data dir: $ServerDataDir")

# --- Detect well-known defaults --------------------------------------------
$isDefault = $false
if (Test-Path $privPath) {
    $h = (Get-FileHash -Path $privPath -Algorithm SHA256).Hash
    if ($h -eq $WellKnownHashes['private.key']) {
        $isDefault = $true
        Write-Host 'Current private.key matches the well-known v1.2.0 default. Regenerating.' -ForegroundColor Yellow
    } else {
        Write-Host ("Current private.key hash: $h (not the v1.2.0 default)")
    }
}

if (-not $isDefault -and -not $Force) {
    Write-Host ''
    Write-Host 'Existing keys are NOT the v1.2.0 default. Pass -Force to overwrite anyway.'
    Write-Host 'Skipping regeneration.'
    exit 0
}

# --- Backup existing keys --------------------------------------------------
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
foreach ($p in @($privPath, $pubPath)) {
    if (Test-Path $p) {
        $bak = "$p.bak-$stamp"
        Move-Item -LiteralPath $p -Destination $bak -Force
        Write-Host ("Backed up: $(Split-Path -Leaf $p) -> $(Split-Path -Leaf $bak)")
    }
}

# --- Generate fresh RSA keypair --------------------------------------------
Write-Host ("Generating fresh RSA-$KeySize keypair...")
$rsa = [System.Security.Cryptography.RSA]::Create($KeySize)
try {
    $privPem = $rsa.ExportRSAPrivateKeyPem()
    $pubPem  = $rsa.ExportRSAPublicKeyPem()

    # Sanity: the headers MUST be the PKCS#1 variants ds3os expects.
    if ($privPem -notmatch '-----BEGIN RSA PRIVATE KEY-----') {
        throw "Unexpected private-key PEM header (got something other than PKCS#1)."
    }
    if ($pubPem -notmatch '-----BEGIN RSA PUBLIC KEY-----') {
        throw "Unexpected public-key PEM header (got something other than PKCS#1)."
    }

    # Write with LF line endings + no BOM, matching the upstream bundled file.
    [System.IO.File]::WriteAllText($privPath, $privPem, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($pubPath,  $pubPem,  [System.Text.UTF8Encoding]::new($false))

    Write-Host "Wrote: $privPath"
    Write-Host "Wrote: $pubPath"

    # --- Verify the new keys round-trip via sign/verify ----------------------
    $testBytes = [Text.Encoding]::UTF8.GetBytes('regen-self-test-' + $stamp)
    $sig = $rsa.SignData(
        $testBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $ok = $rsa.VerifyData(
        $testBytes,
        $sig,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    if (-not $ok) { throw "Self-test sign/verify failed on the new keypair." }
    Write-Host 'Self-test sign/verify: OK'

    # --- Fingerprint: SHA-256 of the public key's DER bytes ------------------
    $pubDer = $rsa.ExportRSAPublicKey()
    $fpBytes = [Security.Cryptography.SHA256]::HashData($pubDer)
    $fpHex   = ($fpBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ''
    # Standard fingerprint colon-separated form (for friendlier sharing)
    $fpPretty = ($fpBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ':'

    Write-Host ''
    Write-Host '=========================================================='
    Write-Host 'NEW HOST PUBLIC-KEY FINGERPRINT (SHA-256 of public-key DER):'
    Write-Host "  $fpHex"
    Write-Host ''
    Write-Host 'Pretty form to share with joiners (out of band, e.g. Discord DM):'
    Write-Host "  $fpPretty"
    Write-Host '=========================================================='
    Write-Host ''
    Write-Host 'Joiners need this fingerprint to verify they are connecting to YOUR'
    Write-Host 'server. Once joiner-side pinning lands (follow-up H-30 task), the'
    Write-Host 'joiner client will check this on first connect and refuse mismatches.'

    # --- Also update the bundle-root ds2_server_public.key if it lives next to
    #     the server data dir. That file is the joiner's trust anchor — it must
    #     match the server's newly-regenerated public.key, otherwise the joiner
    #     would still be trusting the v1.2.0 default key.
    # Path inferred: <bundleRoot>/Server/Saved/default/  ->  <bundleRoot>/ds2_server_public.key
    $bundleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $ServerDataDir))
    $bundlePub  = Join-Path $bundleRoot 'ds2_server_public.key'
    if (Test-Path $bundlePub) {
        $oldHash = (Get-FileHash $bundlePub -Algorithm SHA256).Hash
        $bak = "$bundlePub.bak-$stamp"
        Copy-Item -LiteralPath $bundlePub -Destination $bak -Force
        [System.IO.File]::WriteAllText($bundlePub, $pubPem, [System.Text.UTF8Encoding]::new($false))
        Write-Host ''
        Write-Host "Also updated bundle-root joiner trust anchor: $bundlePub"
        Write-Host "  Old hash (backed up to .bak-$stamp): $oldHash"
        Write-Host '  New hash matches the newly generated public.key.'
    }
}
finally {
    $rsa.Dispose()
}
