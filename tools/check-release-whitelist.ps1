# check-release-whitelist.ps1
# ---------------------------------------------------------------------------
# H-08: assert that the joiner and host release bundles contain only files
# enumerated in tools/release-whitelist.txt. Exits non-zero if a bundle
# contains an extra file (anything outside the whitelist), so author-
# specific batch scripts or stray developer artifacts cannot sneak into a
# release.
#
# Designed for two callers:
#   - Local: run with no args; it scans dist/joiner and dist/host.
#   - Packaging / CI: pass -JoinerDir and/or -HostDir pointing at the
#     assembled-but-not-yet-zipped bundle, or at a directory containing
#     the unzipped bundle. With -Strict, also fails on whitelisted entries
#     that are absent (useful as a post-build gate before zipping).
#
# Whitelist semantics:
#   - Sections [joiner] and [host] each carry their own path list.
#   - Paths are bundle-relative, forward-slashed, case-insensitive.
#   - "(built)" annotation marks entries produced by the C++ build /
#     server build. These are absent from the source dist/ checkout and
#     so are not reported as "missing" in default mode. -Strict requires
#     them to be present (a real bundle must include the binaries).
#
# Exit codes:
#   0  no extras (default) / no extras and no missing (-Strict).
#   1  one or more extras found, or (-Strict) one or more missing.
#   2  usage / configuration error (whitelist unreadable, bad section).
#
# Run from the repo root:
#   pwsh -NoProfile -File tools\check-release-whitelist.ps1
#   pwsh -NoProfile -File tools\check-release-whitelist.ps1 -Strict
#   pwsh -NoProfile -File tools\check-release-whitelist.ps1 `
#        -JoinerDir D:\stage\joiner -HostDir D:\stage\host -Strict
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [string]$WhitelistPath = '',
    [string]$JoinerDir     = '',
    [string]$HostDir       = '',
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    # tools/ lives at repo root; this script's parent's parent is the root.
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir '..')).Path
}

function Read-Whitelist {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "Whitelist not found: $Path" -ForegroundColor Red
        exit 2
    }

    $sections = @{ 'joiner' = @(); 'host' = @() }
    $builtFlags = @{ 'joiner' = @{}; 'host' = @{} }
    $current = $null

    foreach ($raw in Get-Content -LiteralPath $Path) {
        $line = $raw.Trim()
        if (-not $line)            { continue }
        if ($line.StartsWith('#')) { continue }

        if ($line -match '^\[([a-zA-Z0-9_-]+)\]$') {
            $current = $Matches[1].ToLower()
            if (-not $sections.ContainsKey($current)) {
                Write-Host "Unknown section in whitelist: [$current]" -ForegroundColor Red
                exit 2
            }
            continue
        }

        if (-not $current) {
            Write-Host "Whitelist entry outside any section: $line" -ForegroundColor Red
            exit 2
        }

        # Strip an optional "(built)" annotation. Trailing comments are not
        # supported deliberately — keep the format trivially parseable.
        $isBuilt = $false
        if ($line -match '^(.+?)\s*\(built\)\s*$') {
            $entry = $Matches[1].Trim()
            $isBuilt = $true
        } else {
            $entry = $line
        }
        # Normalise to forward slashes and lowercase for case-insensitive
        # comparison on Windows.
        $entry = $entry -replace '\\', '/'
        $key = $entry.ToLower()

        $sections[$current] += $key
        $builtFlags[$current][$key] = $isBuilt
    }

    return @{ Paths = $sections; Built = $builtFlags }
}

function Get-BundleFiles {
    param([string]$Root)

    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $rootFull = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\','/')
    $files = Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($rootFull.Length).TrimStart('\','/')
        $rel = ($rel -replace '\\', '/').ToLower()
        $null = $out.Add($rel)
    }
    return ,$out.ToArray()
}

function Compare-Bundle {
    param(
        [string]   $Label,
        [string]   $Dir,
        [string[]] $Whitelist,
        [hashtable]$BuiltFlags,
        [bool]     $StrictMode
    )

    if (-not $Dir) { return @{ Extras = @(); Missing = @() } }
    if (-not (Test-Path -LiteralPath $Dir)) {
        Write-Host "[$Label] bundle directory not found: $Dir" -ForegroundColor Yellow
        return @{ Extras = @(); Missing = @() }
    }

    $present = Get-BundleFiles -Root $Dir
    $whiteSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($w in $Whitelist) { $null = $whiteSet.Add($w) }

    $presentSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $present) { $null = $presentSet.Add($p) }

    $extras  = @($present | Where-Object { -not $whiteSet.Contains($_) })
    $missing = @()
    foreach ($w in $Whitelist) {
        if ($presentSet.Contains($w)) { continue }
        # In default mode, suppress "missing" for build artifacts — they
        # legitimately aren't there until a build/packaging step has run.
        if ((-not $StrictMode) -and $BuiltFlags[$w]) { continue }
        $missing += $w
    }

    Write-Host ("== [$Label] $Dir") -ForegroundColor Cyan
    Write-Host ("   files on disk : {0}" -f $present.Count)
    Write-Host ("   whitelisted   : {0}" -f $Whitelist.Count)

    if ($extras.Count -gt 0) {
        Write-Host ("   EXTRAS ({0}):" -f $extras.Count) -ForegroundColor Red
        foreach ($e in $extras) { Write-Host "     + $e" -ForegroundColor Red }
    }
    if ($missing.Count -gt 0) {
        $color = if ($StrictMode) { 'Red' } else { 'Yellow' }
        Write-Host ("   MISSING ({0}):" -f $missing.Count) -ForegroundColor $color
        foreach ($m in $missing) {
            $tag = if ($BuiltFlags[$m]) { ' (built)' } else { '' }
            Write-Host ("     - {0}{1}" -f $m, $tag) -ForegroundColor $color
        }
    }
    if ($extras.Count -eq 0 -and $missing.Count -eq 0) {
        Write-Host "   OK — bundle matches whitelist exactly." -ForegroundColor Green
    }

    return @{ Extras = $extras; Missing = $missing }
}

# --- main -------------------------------------------------------------------

$repoRoot = Resolve-RepoRoot
if (-not $WhitelistPath) { $WhitelistPath = Join-Path $repoRoot 'tools\release-whitelist.txt' }
if (-not $JoinerDir)     { $JoinerDir     = Join-Path $repoRoot 'dist\joiner' }
if (-not $HostDir)       { $HostDir       = Join-Path $repoRoot 'dist\host' }

Write-Host "DS2 Seamless Co-op — release whitelist check (H-08)"
Write-Host "  whitelist : $WhitelistPath"
Write-Host "  mode      : $(if ($Strict) { 'STRICT (extras + missing fail)' } else { 'default (extras fail; built-artifact missing tolerated)' })"
Write-Host ''

$wl = Read-Whitelist -Path $WhitelistPath

$joinerResult = Compare-Bundle -Label 'joiner' -Dir $JoinerDir `
                               -Whitelist $wl.Paths['joiner'] `
                               -BuiltFlags $wl.Built['joiner'] `
                               -StrictMode $Strict.IsPresent
$hostResult   = Compare-Bundle -Label 'host'   -Dir $HostDir `
                               -Whitelist $wl.Paths['host'] `
                               -BuiltFlags $wl.Built['host'] `
                               -StrictMode $Strict.IsPresent

$totalExtras  = $joinerResult.Extras.Count  + $hostResult.Extras.Count
$totalMissing = $joinerResult.Missing.Count + $hostResult.Missing.Count

Write-Host ''
Write-Host ("Summary: extras = {0}, missing = {1}" -f $totalExtras, $totalMissing)

$fail = $false
if ($totalExtras  -gt 0)              { $fail = $true }
if ($Strict -and $totalMissing -gt 0) { $fail = $true }

if ($fail) {
    Write-Host 'FAIL — release bundle does not match whitelist.' -ForegroundColor Red
    exit 1
}

Write-Host 'PASS' -ForegroundColor Green
exit 0
