<#
.SYNOPSIS
    Universal Multip VPN Config Cleaner, Health Pruner & Consolidator
    Filters out Antigravity-blocked countries, purges dead keys, and combines all working nodes into config.json.

.DESCRIPTION
    1. Automatically backs up all config*.json files to a timestamped backup folder.
    2. Resolves and checks geolocation against Antigravity / Google AI blocked countries (HK, CN, RU, IR, etc.).
    3. Performs an end-to-end sing-box proxy handshake & internet fetch test on every node.
    4. Purges dead, expired (404), and blocked nodes, leaving only clean, ultra-low ping, supported keys.
    5. Deduplicates identical nodes across multiple files.
    6. Combines ALL surviving, verified nodes into ONE clean 'config.json'.
    7. Deletes other secondary config files (config01.json, config02.json, etc.) after backup.

.PARAMETER DryRun
    Tests all nodes and prints report without modifying or deleting files on disk.

.PARAMETER TargetFile
    Optional specific config file to clean (e.g. config.json). When specified, only that file is cleaned.

.PARAMETER KeepSplit
    Disables auto-combining: cleans each file in place rather than merging into config.json.

.PARAMETER PurgeGcp
    Purges all Google Cloud Platform (GCP) datacenter IPs (AS396982, AS15169, 34.64.0.0/10, 35.184.0.0/13, etc.)
    Aliases: -gcp, -gpc, -ExcludeGcp, -NoGcp.
    Essential for protecting Antigravity / Gemini AI Studio which blocks datacenter ASNs.
#>

param(
    [switch]$DryRun,
    [Parameter(Position=0)]
    [string]$TargetFile,
    [switch]$KeepSplit,
    [int]$Threads = 16,
    [int]$TimeoutMs = 9000,
    [Alias("gcp", "gpc", "ExcludeGcp", "NoGcp")]
    [switch]$PurgeGcp
)

# Set UTF-8 Console
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir    = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = "d:\CODE\Multip VPN" }
$SingBoxBin   = Join-Path $ScriptDir "sing-box.exe"
$GeoCacheFile = Join-Path $ScriptDir "_geo_cache.json"
$IpInfoToken  = "a1e1161ecc1b38"
$MasterConfig = Join-Path $ScriptDir "config.json"

# Countries blocked by Google AI Studio / Gemini / Antigravity
$BLOCKED_COUNTRIES = @('HK', 'CN', 'RU', 'IR', 'KP', 'SY', 'CU', 'BY', 'MM', 'VE')

$utf8NoBom = New-Object System.Text.UTF8Encoding $false

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Multip VPN Config Cleaner & Auto-Consolidator" -ForegroundColor White
Write-Host "   Policy & Health Check -> Combines All Working Nodes to config.json" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "[!] DRY-RUN MODE: No files will be modified or deleted on disk." -ForegroundColor Yellow
}
if ($PurgeGcp) {
    Write-Host "[+] PURGE GCP MODE: All Google Cloud Platform datacenter IPs will be filtered out to protect Antigravity." -ForegroundColor Yellow
}
Write-Host ""

# Verify sing-box binary
if (-not (Test-Path $SingBoxBin)) {
    Write-Host "[-] ERROR: sing-box.exe not found at '$SingBoxBin'." -ForegroundColor Red
    exit 1
}

# Load / initialize geo cache
$GeoCache = @{}
if (Test-Path $GeoCacheFile) {
    try {
        $rawCache = Get-Content -Path $GeoCacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($prop in $rawCache.PSObject.Properties) {
            $GeoCache[$prop.Name] = @{
                country = $prop.Value.country
                city    = $prop.Value.city
                isp     = $prop.Value.isp
                org     = $prop.Value.org
                as      = $prop.Value.as
            }
        }
    } catch {}
}

function Save-GeoCache {
    try {
        $cacheJson = $GeoCache | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($GeoCacheFile, $cacheJson, $utf8NoBom)
    } catch {}
}

function Get-NodeGeoInfo([string]$IpAddress) {
    $existing = if ($GeoCache.ContainsKey($IpAddress)) { $GeoCache[$IpAddress] } else { $null }
    if ($existing -and ($existing.isp -or $existing.org)) {
        return $existing
    }

    $geo = @{ country = "UNKNOWN"; city = "Unknown"; isp = ""; org = ""; as = "" }
    if ($existing) {
        if ($existing.country) { $geo.country = $existing.country }
        if ($existing.city)    { $geo.city    = $existing.city }
    }

    # Primary fast lookup: ip-api.com line format via curl (including ISP, Org, and ASN)
    try {
        $respRaw = & curl.exe -s -m 3 "http://ip-api.com/line/${IpAddress}?fields=countryCode,city,isp,org,as"
        if ($respRaw) {
            $lines = @($respRaw -split "`r?`n" | Where-Object { $_.Trim() -ne "" })
            if ($lines.Count -ge 1) {
                $geo.country = $lines[0].Trim().ToUpper()
                $geo.city    = if ($lines.Count -ge 2) { $lines[1].Trim() } else { "Unknown" }
                $geo.isp     = if ($lines.Count -ge 3) { $lines[2].Trim() } else { "" }
                $geo.org     = if ($lines.Count -ge 4) { $lines[3].Trim() } else { "" }
                $geo.as      = if ($lines.Count -ge 5) { $lines[4].Trim() } else { "" }
                $GeoCache[$IpAddress] = $geo
                Save-GeoCache
                return $geo
            }
        }
    } catch {}

    # Secondary lookup: ipinfo.io via curl
    try {
        $url = if ($IpInfoToken) { "https://ipinfo.io/$IpAddress/json?token=$IpInfoToken" } else { "https://ipinfo.io/$IpAddress/json" }
        $respRaw = & curl.exe -s -m 3 $url
        if ($respRaw) {
            $d = $respRaw | ConvertFrom-Json
            if ($d.country) {
                $geo.country = $d.country.ToString().Trim().ToUpper()
                $geo.city    = if ($d.city) { $d.city.ToString() } else { "Unknown" }
                $geo.org     = if ($d.org) { $d.org.ToString() } else { "" }
                $geo.isp     = if ($d.org) { $d.org.ToString() } else { "" }
                $geo.as      = if ($d.org) { $d.org.ToString() } else { "" }
                $GeoCache[$IpAddress] = $geo
                Save-GeoCache
                return $geo
            }
        }
    } catch {}

    if ($existing) {
        return $existing
    }
    return $geo
}

function Test-IsGcpNode {
    param(
        [string]$ResolvedIp,
        $GeoInfo,
        [string]$Server,
        [string]$Tag
    )

    # 1. Check IP against known GCP CIDR allocations
    if ($ResolvedIp) {
        # 34.64.0.0 - 34.191.255.255 (GCP massive allocation covering europe-west6, us, asia)
        if ($ResolvedIp -match '^34\.(6[4-9]|[7-9]\d|1[0-8]\d|19[01])\.') { return $true }
        # 35.184.0.0 - 35.247.255.255 (GCP massive allocation)
        if ($ResolvedIp -match '^35\.(18[4-9]|19\d|2[0-3]\d|24[0-7])\.') { return $true }
        # Other well-known GCP prefixes
        if ($ResolvedIp -match '^104\.(15[45]|19[6-9])\.') { return $true }
        if ($ResolvedIp -match '^130\.211\.') { return $true }
        if ($ResolvedIp -match '^146\.148\.') { return $true }
    }

    # 2. Check GeoInfo ISP / Org / AS
    if ($GeoInfo) {
        $combinedGeo = ("{0} {1} {2}" -f $GeoInfo.isp, $GeoInfo.org, $GeoInfo.as).ToLowerInvariant()
        if ($combinedGeo -match "google cloud" -or 
            $combinedGeo -match "google llc" -or 
            $combinedGeo -match "as396982" -or 
            $combinedGeo -match "as15169" -or 
            $combinedGeo -match "googleusercontent") {
            return $true
        }
    }

    # 3. Check Server hostname
    if ($Server) {
        $srvLower = $Server.ToLowerInvariant()
        if ($srvLower -like "*.bc.googleusercontent.com" -or 
            $srvLower -like "*gcp*" -or 
            $srvLower -like "*googlecloud*") {
            return $true
        }
    }

    # 4. Check Tag
    if ($Tag) {
        $tagLower = $Tag.ToLowerInvariant()
        if ($tagLower -match '\bgcp\b' -or $tagLower -match 'google cloud') {
            return $true
        }
    }

    return $false
}

function Get-NodeSignature($node) {
    $type = if ($node.type) { $node.type } else { "" }
    $srv  = if ($node.server) { $node.server } else { "" }
    $prt  = if ($node.server_port) { $node.server_port } else { "" }
    $uuid = if ($node.uuid) { $node.uuid } else { "" }
    $pwd  = if ($node.password) { $node.password } else { "" }
    $sni  = if ($node.tls -and $node.tls.server_name) { $node.tls.server_name } else { "" }
    $hostHeader = if ($node.transport -and $node.transport.headers -and $node.transport.headers.Host) { 
        $node.transport.headers.Host 
    } elseif ($node.transport -and $node.transport.host) {
        $node.transport.host
    } else { "" }
    $path = if ($node.transport -and $node.transport.path) { $node.transport.path } else { "" }
    return "$type|$srv|$prt|$uuid|$pwd|$sni|$hostHeader|$path".ToLowerInvariant()
}

function Test-SingBoxNodeConnectivity($nodeObj) {
    $probeTmpPath = Join-Path $env:TEMP ("singbox_probe_" + [Guid]::NewGuid().ToString("N") + ".json")
    
    # Clone node object and normalize tag
    $cloneJson = $nodeObj | ConvertTo-Json -Depth 10
    $nodeClone = $cloneJson | ConvertFrom-Json
    $nodeClone.tag = "probe-target"

    $probeConfig = @{
        log = @{ level = "error" }
        outbounds = @($nodeClone)
    }

    $jsonStr = $probeConfig | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($probeTmpPath, $jsonStr, $utf8NoBom)

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $SingBoxBin
    $pinfo.Arguments = "tools fetch https://www.gstatic.com/generate_204 -c `"$probeTmpPath`" -o probe-target"
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($pinfo)
    $finished = $proc.WaitForExit(3200)
    $sw.Stop()

    $isAlive = $false
    $errText = ""
    if (-not $finished) {
        try { $proc.Kill() } catch {}
        $errText = "Timeout (>3.2s)"
    } else {
        if ($proc.ExitCode -eq 0) {
            $isAlive = $true
        } else {
            $err = $proc.StandardError.ReadToEnd()
            $errText = ($err -split "`n")[0].Trim()

            # Auto-recovery for expired or self-signed TLS certificates
            if (($errText -match "certificate has expired" -or $errText -match "failed to verify certificate" -or $errText -match "cannot validate certificate") -and $nodeClone.tls -and (-not $nodeClone.tls.insecure)) {
                $nodeClone.tls | Add-Member -NotePropertyName "insecure" -NotePropertyValue $true -Force
                $reprobeJson = @{ log = @{ level = "error" }; outbounds = @($nodeClone) } | ConvertTo-Json -Depth 10
                [System.IO.File]::WriteAllText($probeTmpPath, $reprobeJson, $utf8NoBom)
                $reProc = & $SingBoxBin tools fetch https://www.gstatic.com/generate_204 -c $probeTmpPath -o probe-target 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $isAlive = $true
                    $errText = ""
                    if ($nodeObj.tls -is [System.Collections.IDictionary]) {
                        $nodeObj.tls["insecure"] = $true
                    } else {
                        $nodeObj.tls | Add-Member -NotePropertyName "insecure" -NotePropertyValue $true -Force
                    }
                }
            }

            if (-not $isAlive) {
                if ($errText -match "status code: (\d+)") {
                    $errText = "Auth error (HTTP $($Matches[1]))"
                } elseif ($errText -match "EOF") {
                    $errText = "Server dropped connection (EOF)"
                } elseif ($errText -match "refused") {
                    $errText = "Connection refused"
                } elseif ($errText -match "cannot validate certificate") {
                    $errText = "TLS certificate mismatch"
                } elseif ($errText -match "certificate has expired") {
                    $errText = "TLS certificate expired"
                }
            }
        }
    }

    Remove-Item $probeTmpPath -Force -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        Alive     = $isAlive
        LatencyMs = $sw.ElapsedMilliseconds
        Error     = $errText
    }
}

# Locate config files
$configFiles = @()
if ($TargetFile -and $TargetFile -ne "configs" -and $TargetFile -ne "all") {
    $fullTarget = if ([System.IO.Path]::IsPathRooted($TargetFile)) { $TargetFile } else { Join-Path $ScriptDir $TargetFile }
    if (-not (Test-Path $fullTarget) -and (Test-Path "$fullTarget.json")) {
        $fullTarget = "$fullTarget.json"
    }
    if (Test-Path $fullTarget) {
        $configFiles = @(Get-Item $fullTarget)
    } else {
        Write-Host "[-] Target file '$TargetFile' not found." -ForegroundColor Red
        exit 1
    }
} else {
    $configFiles = Get-ChildItem -Path $ScriptDir -Filter "config*.json" | 
        Where-Object { 
            $_.Name -notmatch '^_singbox' -and 
            $_.Name -notmatch '\.example\.json$' -and 
            $_.Name -notmatch '^normal_config' 
        } |
        Sort-Object Name
}

if ($configFiles.Count -eq 0) {
    Write-Host "[!] No config*.json files found to clean." -ForegroundColor Yellow
    exit 0
}

# Backup directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $ScriptDir "backups\backup_$timestamp"

if (-not $DryRun) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Write-Host "[+] Creating safety backup in: $backupDir" -ForegroundColor Yellow
    foreach ($f in $configFiles) {
        Copy-Item -Path $f.FullName -Destination $backupDir -Force
    }
    Write-Host "[+] Backup complete.`n" -ForegroundColor Green
}

# Global Statistics & Collector for Consolidation
$totalOriginalNodes  = 0
$totalDeadPurged     = 0
$totalBlockedPurged  = 0
$totalGcpPurged      = 0
$totalDuplicateNodes = 0
$allSurvivingNodes   = @()
$seenSignatures      = @{}
$seenIpPorts         = @{}

# Inspect and test each file
foreach ($file in $configFiles) {
    Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ("[*] Inspecting File: {0}" -f $file.Name) -ForegroundColor White

    $rawContent = Get-Content -Path $file.FullName -Raw -Encoding UTF8
    $jsonObj = $null
    try {
        $jsonObj = $rawContent | ConvertFrom-Json
    } catch {
        Write-Host ("[-] Failed to parse JSON in {0}: {1}" -f $file.Name, $_.Exception.Message) -ForegroundColor Red
        continue
    }

    if (-not $jsonObj.outbounds) {
        Write-Host "[-] No outbounds array found. Skipping." -ForegroundColor Yellow
        continue
    }

    # Separate non-proxy outbounds (selector, urltest, direct, block, dns)
    $controlTypes = @("selector", "urltest", "direct", "block", "dns")
    $controlOutbounds = @($jsonObj.outbounds | Where-Object { $_.type -in $controlTypes })
    $proxyNodes       = @($jsonObj.outbounds | Where-Object { $_.type -notin $controlTypes })

    $nodeCount = $proxyNodes.Count
    $totalOriginalNodes += $nodeCount
    Write-Host ("    Found {0} proxy outbound node(s) to evaluate." -f $nodeCount) -ForegroundColor Gray

    if ($nodeCount -eq 0) {
        continue
    }

    $fileSurvivingNodes = @()
    $fileDeadCount      = 0
    $fileBlockedCount   = 0
    $fileGcpCount       = 0
    $fileDupCount       = 0

    # Step 1: Fast Filter (Duplicates, DNS & Geo-Policy)
    $candidateList = [System.Collections.Generic.List[PSObject]]::new()
    $nodeIdx = 0

    foreach ($node in $proxyNodes) {
        $nodeIdx++
        $type   = $node.type
        $server = $node.server
        $port   = $node.server_port
        $tag    = $node.tag

        if ($server -eq "example.com" -or $server -like "*00000000*") { continue }

        # Auto-normalize Shadowsocks cipher for sing-box compatibility
        if ($type -eq "shadowsocks" -and $node.method) {
            switch ($node.method.ToString().Trim().ToLowerInvariant()) {
                "chacha20-poly1305"      { $node.method = "chacha20-ietf-poly1305" }
                "chacha20-ietf"          { $node.method = "chacha20-ietf-poly1305" }
                "aead_chacha20_poly1305" { $node.method = "chacha20-ietf-poly1305" }
                "aead_aes_128_gcm"       { $node.method = "aes-128-gcm" }
                "aead_aes_256_gcm"       { $node.method = "aes-256-gcm" }
            }
        }

        # Check for duplicate node
        $sig = Get-NodeSignature $node
        if ($seenSignatures.ContainsKey($sig)) {
            Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} -> DUPLICATE (Already tested in {5})" -f $nodeIdx, $nodeCount, $type, $server, $port, $seenSignatures[$sig]) -ForegroundColor DarkGray
            $fileDupCount++
            $totalDuplicateNodes++
            continue
        }

        # 1. Resolve IP
        $resolvedIp = $null
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($server)
            $resolvedIp = ($ips | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
        } catch {}

        if (-not $resolvedIp) {
            Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} -> DNS RESOLVE FAILED" -f $nodeIdx, $nodeCount, $type, $server, $port) -ForegroundColor Red
            $fileDeadCount++
            $totalDeadPurged++
            continue
        }

        # Deduplicate strictly by Type + resolved IP + Port combination
        # (Prevents dropping Hysteria2 UDP vs VLESS TCP on the same port 443)
        $typeIpPortKey = "$($type)://$resolvedIp`:$port".ToLowerInvariant()
        if ($seenIpPorts.ContainsKey($typeIpPortKey)) {
            Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} ({5}) -> DUPLICATE PROTOCOL+IP:PORT (Already in {6})" -f $nodeIdx, $nodeCount, $type, $server, $port, $resolvedIp, $seenIpPorts[$typeIpPortKey]) -ForegroundColor DarkGray
            $fileDupCount++
            $totalDuplicateNodes++
            continue
        }
        $seenIpPorts[$typeIpPortKey] = $file.Name

        # 2. Geo Location check
        $geo = Get-NodeGeoInfo $resolvedIp
        $country = $geo.country
        $city    = $geo.city

        # 2a. Antigravity Policy: Purge GCP Datacenter IPs if requested (-gcp / -gpc)
        if ($PurgeGcp -and (Test-IsGcpNode -ResolvedIp $resolvedIp -GeoInfo $geo -Server $server -Tag $tag)) {
            Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} -> DROPPED (GCP Datacenter IP purged: {5} - {6})" -f $nodeIdx, $nodeCount, $type, $server, $port, $country, $city) -ForegroundColor Yellow
            $fileGcpCount++
            $totalGcpPurged++
            continue
        }

        if ($country -in $BLOCKED_COUNTRIES) {
            Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} -> DROPPED (Blocked: {5} - {6})" -f $nodeIdx, $nodeCount, $type, $server, $port, $country, $city) -ForegroundColor Yellow
            $fileBlockedCount++
            $totalBlockedPurged++
            continue
        }

        # Passes pre-filter -> queue for multi-threaded live probe
        $candidateList.Add([PSObject]@{
            Node    = $node
            Sig     = $sig
            IpPort  = $ipPortKey
            Country = $country
            City    = $city
            ItemNum = $nodeIdx
        })
    }

    # Step 2: Multi-Threaded Connectivity Probe (16 threads, 9s delay/timeout)
    if ($candidateList.Count -gt 0) {
        if ($Threads -lt 1) { $Threads = 16 }
        if ($TimeoutMs -lt 1000) { $TimeoutMs = 9000 }
        Write-Host ("    Probing {0} candidate node(s) with {1} parallel thread(s) (Timeout: {2}ms)..." -f $candidateList.Count, $Threads, $TimeoutMs) -ForegroundColor Cyan

        $activeJobs = [System.Collections.Generic.List[PSObject]]::new()
        $candIdx = 0
        $totalCandidates = $candidateList.Count

        while ($candIdx -lt $totalCandidates -or $activeJobs.Count -gt 0) {
            # Dispatch workers up to $Threads
            while ($candIdx -lt $totalCandidates -and $activeJobs.Count -lt $Threads) {
                $cItem = $candidateList[$candIdx]
                $candIdx++

                $probeTmpPath = Join-Path $env:TEMP ("singbox_probe_" + [Guid]::NewGuid().ToString("N") + ".json")
                $cloneJson = $cItem.Node | ConvertTo-Json -Depth 10
                $nodeClone = $cloneJson | ConvertFrom-Json
                $nodeClone.tag = "probe-target"

                $probeConfig = @{
                    log = @{ level = "error" }
                    outbounds = @($nodeClone)
                }
                $jsonStr = $probeConfig | ConvertTo-Json -Depth 10
                [System.IO.File]::WriteAllText($probeTmpPath, $jsonStr, $utf8NoBom)

                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = $SingBoxBin
                $pinfo.Arguments = "tools fetch https://www.gstatic.com/generate_204 -c `"$probeTmpPath`" -o probe-target"
                $pinfo.RedirectStandardOutput = $true
                $pinfo.RedirectStandardError = $true
                $pinfo.UseShellExecute = $false
                $pinfo.CreateNoWindow = $true

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $proc = [System.Diagnostics.Process]::Start($pinfo)

                $activeJobs.Add([PSObject]@{
                    Process   = $proc
                    Stopwatch = $sw
                    TmpFile   = $probeTmpPath
                    Candidate = $cItem
                })
                Start-Sleep -Milliseconds 25
            }

            # Check running workers
            if ($activeJobs.Count -gt 0) {
                $stillRunning = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($job in $activeJobs) {
                    $p = $job.Process
                    $sw = $job.Stopwatch
                    $elapsed = $sw.ElapsedMilliseconds
                    $cItem = $job.Candidate
                    $node = $cItem.Node

                    if ($p.HasExited) {
                        $sw.Stop()
                        $exitCode = $p.ExitCode
                        $errText = ""
                        try { $errText = ($p.StandardError.ReadToEnd() -split "`n")[0].Trim() } catch {}
                        $p.Dispose()
                        Remove-Item $job.TmpFile -Force -ErrorAction SilentlyContinue

                        if ($exitCode -eq 0) {
                            Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} -> ALIVE [{5} - {6}] ({7}ms)" -f $cItem.ItemNum, $nodeCount, $node.type, $node.server, $node.server_port, $cItem.Country, $cItem.City, $elapsed) -ForegroundColor Green
                            $fileSurvivingNodes += $node
                            $allSurvivingNodes  += $node
                            $seenSignatures[$cItem.Sig] = $file.Name
                        } else {
                            $err = $errText
                            if ($err -match "status code: (\d+)") {
                                $err = "Auth error (HTTP $($Matches[1]))"
                            } elseif ($err -match "EOF") {
                                $err = "Server dropped connection (EOF)"
                            } elseif ($err -match "refused") {
                                $err = "Connection refused"
                            } elseif ($err -match "reality verification failed") {
                                $err = "Reality handshake failed"
                            } elseif ($err -match "cannot validate certificate") {
                                $err = "TLS certificate mismatch"
                            }
                            if (-not $err) { $err = "Failed" }
                            Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} -> DEAD ({5})" -f $cItem.ItemNum, $nodeCount, $node.type, $node.server, $node.server_port, $err) -ForegroundColor Red
                            $fileDeadCount++
                            $totalDeadPurged++
                        }
                    } elseif ($elapsed -gt $TimeoutMs) {
                        $sw.Stop()
                        try { $p.Kill(); $p.Dispose() } catch {}
                        Remove-Item $job.TmpFile -Force -ErrorAction SilentlyContinue

                        Write-Host ("  [{0}/{1}] {2,-10} {3}:{4} -> DEAD (Timeout >$($TimeoutMs)ms)" -f $cItem.ItemNum, $nodeCount, $node.type, $node.server, $node.server_port) -ForegroundColor Red
                        $fileDeadCount++
                        $totalDeadPurged++
                    } else {
                        $stillRunning.Add($job)
                    }
                }
                $activeJobs = $stillRunning
                Start-Sleep -Milliseconds 25
            }
        }
    }

    Write-Host ("    Result for {0}: {1} Kept (Alive & Supported) | {2} Dead Purged | {3} Blocked Geo Purged | {4} Duplicates Skipped" -f $file.Name, $fileSurvivingNodes.Count, $fileDeadCount, $fileBlockedCount, $fileDupCount) -ForegroundColor Cyan

    # If TargetFile or KeepSplit mode, update the file in place
    if ($TargetFile -or $KeepSplit) {
        if (-not $DryRun) {
            if ($fileSurvivingNodes.Count -gt 0) {
                $survivingTags = @($fileSurvivingNodes | ForEach-Object { $_.tag })
                foreach ($ctl in $controlOutbounds) {
                    if ($ctl.type -in @("selector", "urltest") -and $ctl.outbounds) {
                        $newOutbounds = @($ctl.outbounds | Where-Object { $_ -in $survivingTags })
                        if ($ctl.type -eq "selector") {
                            $urlTestTags = @($controlOutbounds | Where-Object { $_.type -eq "urltest" } | ForEach-Object { $_.tag })
                            $specialTags = @($ctl.outbounds | Where-Object { $_ -in $urlTestTags })
                            $newOutbounds = @($specialTags + $newOutbounds) | Select-Object -Unique
                        }
                        $ctl.outbounds = $newOutbounds
                    }
                }
                $finalOutbounds = @($controlOutbounds + $fileSurvivingNodes)
                $jsonObj.outbounds = $finalOutbounds
                $newJson = $jsonObj | ConvertTo-Json -Depth 15
                [System.IO.File]::WriteAllText($file.FullName, $newJson, $utf8NoBom)
                Write-Host ("[+] UPDATED {0}: Saved with {1} clean working node(s)." -f $file.Name, $fileSurvivingNodes.Count) -ForegroundColor Green
            } else {
                Write-Host ("[!] SKIPPED OVERWRITE for {0}: All nodes are dead/blocked." -f $file.Name) -ForegroundColor Yellow
            }
        }
    }
}

# ================================================================
# Consolidation Mode (Default): Combine all surviving nodes into config.json & delete others
# ================================================================
if (-not $TargetFile -and -not $KeepSplit) {
    Write-Host "`n----------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[*] CONSOLIDATION: Merging all surviving nodes into 1 master config.json..." -ForegroundColor Cyan

    if ($allSurvivingNodes.Count -gt 0) {
        # Ensure unique tags across all combined nodes
        $uniqueTagCounts = @{}
        foreach ($node in $allSurvivingNodes) {
            $baseTag = $node.tag
            if ($uniqueTagCounts.ContainsKey($baseTag)) {
                $uniqueTagCounts[$baseTag]++
                $node.tag = ("{0} ({1})" -f $baseTag, $uniqueTagCounts[$baseTag])
            } else {
                $uniqueTagCounts[$baseTag] = 1
            }
        }

        # Build master config.json
        $masterObj = [ordered]@{
            outbounds = $allSurvivingNodes
        }

        if (-not $DryRun) {
            $masterJson = $masterObj | ConvertTo-Json -Depth 15
            [System.IO.File]::WriteAllText($MasterConfig, $masterJson, $utf8NoBom)
            Write-Host ("[+] SUCCESS: Combined {0} working node(s) into: {1}" -f $allSurvivingNodes.Count, (Split-Path -Leaf $MasterConfig)) -ForegroundColor Green

            # Validate master config with sing-box
            if (Test-Path $SingBoxBin) {
                $valProc = & $SingBoxBin check -c $MasterConfig 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "[+] sing-box validation PASSED for config.json!" -ForegroundColor Green
                } else {
                    Write-Host ("[-] sing-box check warning: {0}" -f ($valProc -join ' ')) -ForegroundColor Yellow
                }
            }

            # Delete other secondary config*.json files
            $deletedFiles = @()
            foreach ($file in $configFiles) {
                if ($file.FullName -ne $MasterConfig) {
                    try {
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        $deletedFiles += $file.Name
                    } catch {
                        Write-Host ("[-] Failed to delete {0}: {1}" -f $file.Name, $_.Exception.Message) -ForegroundColor Yellow
                    }
                }
            }

            if ($deletedFiles.Count -gt 0) {
                Write-Host ("[+] CLEANED UP: Deleted {0} secondary file(s):" -f $deletedFiles.Count) -ForegroundColor Green
                foreach ($df in $deletedFiles) {
                    Write-Host ("     - {0} (safe copy in backups/)" -f $df) -ForegroundColor Gray
                }
            }
        } else {
            Write-Host ("[!] DRY-RUN: Would combine {0} working node(s) into config.json and delete {1} secondary file(s)." -f $allSurvivingNodes.Count, ($configFiles.Count - 1)) -ForegroundColor Yellow
        }
    } else {
        Write-Host "[-] WARNING: Zero nodes survived the health check! No files were deleted to prevent data loss." -ForegroundColor Red
        Write-Host "    All original files are safely backed up in: $backupDir" -ForegroundColor Yellow
    }
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "   CLEANUP & HEALTH CHECK SUMMARY" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ("Total Proxy Nodes Scanned : {0}" -f $totalOriginalNodes)
Write-Host ("Dead / Expired Keys Purged: {0}" -f $totalDeadPurged) -ForegroundColor Red
Write-Host ("Blocked Geo Nodes Purged  : {0} (HK, CN, RU, etc.)" -f $totalBlockedPurged) -ForegroundColor Yellow
if ($PurgeGcp) {
    Write-Host ("GCP Datacenter Nodes Purged: {0} (Google Cloud / AS396982)" -f $totalGcpPurged) -ForegroundColor Yellow
}
Write-Host ("Duplicate Keys Removed    : {0}" -f $totalDuplicateNodes) -ForegroundColor DarkGray
Write-Host ("Clean, Active Nodes Kept  : {0} (Singapore, US, Japan, etc.)" -f $allSurvivingNodes.Count) -ForegroundColor Green
if (-not $TargetFile -and -not $KeepSplit) {
    Write-Host ("Active Master Config      : config.json (Consolidated 1 file)" ) -ForegroundColor Green
}
if (-not $DryRun) {
    Write-Host ("Backups Preserved in      : {0}" -f $backupDir) -ForegroundColor Gray
}
Write-Host "================================================================" -ForegroundColor Cyan
