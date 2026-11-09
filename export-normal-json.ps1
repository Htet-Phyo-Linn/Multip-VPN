<#
.SYNOPSIS
    Sing-box Complex Config to Normal Clean JSON Converter
    Extracts only the pure proxy outbounds from any complex sing-box configuration 
    (stripping out TUN, DNS, routing rules, internal selectors, etc.) into a clean 
    import-style JSON file: { "outbounds": [ ... ] }.

.DESCRIPTION
    1. Reads any sing-box JSON configuration file (e.g. _singbox_cluster_run.json, full TUN configs).
    2. Filters out non-proxy types (tun, selector, urltest, direct, block, dns, etc.).
    3. Excludes dummy/example endpoints (e.g. example.com).
    4. Deduplicates identical nodes.
    5. Saves a clean, import-ready JSON file with only { "outbounds": [ ... ] }.
    6. Validates syntax with sing-box.exe check.

.PARAMETER InputFile
    Input JSON file to extract from. Defaults to '_singbox_cluster_run.json' (if active) 
    or '_singbox_dynamic_run.json', or 'config.json'.

.PARAMETER OutputFile
    Target output file path. Defaults to 'normal_config.json'.

.PARAMETER OverwriteMaster
    If specified, saves directly into 'config.json' (with a safety backup).
#>

param(
    [string]$InputFile,
    [string]$OutputFile,
    [switch]$OverwriteMaster
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir   = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = "d:\CODE\Multip VPN" }
$SingBoxBin  = Join-Path $ScriptDir "sing-box.exe"
$utf8NoBom   = New-Object System.Text.UTF8Encoding $false

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Sing-box Config -> Normal Clean JSON Converter" -ForegroundColor White
Write-Host "   Extracts Pure Proxy Outbounds (Stripping TUN, DNS & Route Bloat)" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Determine input file
$resolvedInput = $null

if ($InputFile) {
    $testInput = if ([System.IO.Path]::IsPathRooted($InputFile)) { $InputFile } else { Join-Path $ScriptDir $InputFile }
    if (Test-Path $testInput) {
        $resolvedInput = $testInput
    } else {
        Write-Host ("[-] ERROR: Input file '{0}' not found." -f $InputFile) -ForegroundColor Red
        exit 1
    }
} else {
    # Auto-detect best candidate
    $candidates = @(
        (Join-Path $ScriptDir "_singbox_cluster_run.json"),
        (Join-Path $ScriptDir "_singbox_dynamic_run.json"),
        (Join-Path $ScriptDir "config.json")
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            $resolvedInput = $cand
            break
        }
    }
}

if (-not $resolvedInput -or -not (Test-Path $resolvedInput)) {
    Write-Host "[-] ERROR: No valid sing-box JSON configuration file found to convert." -ForegroundColor Red
    exit 1
}

Write-Host ("[+] Reading configuration from: {0}" -f (Split-Path -Leaf $resolvedInput)) -ForegroundColor Green
Write-Host ("    Full Path: {0}" -f $resolvedInput) -ForegroundColor Gray

# 2. Parse input JSON
$rawContent = Get-Content -Path $resolvedInput -Raw -Encoding UTF8
$jsonObj = $null
try {
    $jsonObj = $rawContent | ConvertFrom-Json
} catch {
    Write-Host ("[-] ERROR: Failed to parse JSON from {0}: {1}" -f $resolvedInput, $_.Exception.Message) -ForegroundColor Red
    exit 1
}

if (-not $jsonObj.outbounds) {
    Write-Host "[-] ERROR: No 'outbounds' array found in the specified configuration." -ForegroundColor Red
    exit 1
}

# 3. Filter real proxy nodes
$controlTypes = @("selector", "urltest", "direct", "block", "dns")
$proxyTypes   = @("vless", "vmess", "shadowsocks", "trojan", "hysteria2", "hy2", "tuic", "socks", "http", "wireguard")

function Get-NodeSignature($node) {
    $type = if ($node.type) { $node.type } else { "" }
    $srv  = if ($node.server) { $node.server } else { "" }
    $prt  = if ($node.server_port) { $node.server_port } else { "" }
    $uuid = if ($node.uuid) { $node.uuid } else { "" }
    $pwd  = if ($node.password) { $node.password } else { "" }
    $path = if ($node.transport -and $node.transport.path) { $node.transport.path } else { "" }
    return "$type|$srv|$prt|$uuid|$pwd|$path".ToLowerInvariant()
}

$extractedNodes = @()
$seenSignatures = @{}
$droppedCount   = 0

foreach ($node in $jsonObj.outbounds) {
    $nodeType = [string]$node.type

    # Skip non-proxy control blocks
    if ($nodeType -in $controlTypes) {
        $droppedCount++
        continue
    }

    # Skip dummy example nodes
    if ($node.server -eq "example.com" -or $node.server -like "*00000000*") {
        $droppedCount++
        continue
    }

    # Deduplicate
    $sig = Get-NodeSignature $node
    if ($seenSignatures.ContainsKey($sig)) {
        continue
    }
    $seenSignatures[$sig] = $true

    $extractedNodes += $node
}

Write-Host ("`n[*] Extracted {0} pure proxy node(s) (dropped {1} TUN/routing/control blocks):" -f $extractedNodes.Count, $droppedCount) -ForegroundColor Cyan

$i = 0
foreach ($n in $extractedNodes) {
    $i++
    Write-Host ("  [{0,2}] {1,-12} '{2}' ({3}:{4})" -f $i, $n.type, $n.tag, $n.server, $n.server_port) -ForegroundColor Green
}

if ($extractedNodes.Count -eq 0) {
    Write-Host "[-] ERROR: Zero valid proxy nodes found in file." -ForegroundColor Red
    exit 1
}

# 4. Determine output target path
$targetOutput = $null

if ($OverwriteMaster) {
    $targetOutput = Join-Path $ScriptDir "config.json"
    # Backup original before overwrite
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = Join-Path $ScriptDir "backups\backup_$timestamp"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Copy-Item -Path $targetOutput -Destination $backupDir -Force -ErrorAction SilentlyContinue
    Write-Host ("`n[+] Created safety backup of config.json in: {0}" -f $backupDir) -ForegroundColor Yellow
} elseif ($OutputFile) {
    $targetOutput = if ([System.IO.Path]::IsPathRooted($OutputFile)) { $OutputFile } else { Join-Path $ScriptDir $OutputFile }
} else {
    $targetOutput = Join-Path $ScriptDir "normal_config.json"
}

# 5. Build clean "normal JSON" object: { "outbounds": [ ... ] }
$normalConfig = [ordered]@{
    outbounds = $extractedNodes
}

$finalJson = $normalConfig | ConvertTo-Json -Depth 15
[System.IO.File]::WriteAllText($targetOutput, $finalJson, $utf8NoBom)

Write-Host ("`n[+] SUCCESS: Saved {0} node(s) to clean JSON: {1}" -f $extractedNodes.Count, (Split-Path -Leaf $targetOutput)) -ForegroundColor Green
Write-Host ("    Output Path: {0}" -f $targetOutput) -ForegroundColor Gray

# 6. Validate with sing-box check
if (Test-Path $SingBoxBin) {
    $valProc = & $SingBoxBin check -c $targetOutput 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] sing-box validation PASSED (Valid schema for import)!" -ForegroundColor Green
    } else {
        Write-Host ("[-] sing-box check warning: {0}" -f ($valProc -join ' ')) -ForegroundColor Yellow
    }
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "   EXPORT COMPLETE!" -ForegroundColor White
Write-Host ("   Clean File: {0}" -f (Split-Path -Leaf $targetOutput)) -ForegroundColor Green
Write-Host "   Format    : Standard import format ({ `"outbounds`": [...] })" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
