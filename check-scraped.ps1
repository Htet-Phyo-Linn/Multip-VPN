<#
.SYNOPSIS
    Multip VPN - Standalone Live Node Checker for Scraped VPN Files
    Tests connectivity and latency for nodes in scraped JSON files (e.g. vpn_file_01.json)
    without touching config.json or deleting other files.

.DESCRIPTION
    1. Loads outbounds from the specified JSON file (default: vpn_file_01.json).
    2. Probes each node in parallel (up to 16 threads) via sing-box handshake & HTTP 204 fetch.
    3. Displays live latency, protocol, country/city, and clear error reasons.
    4. Provides a full diagnostic summary at completion (Alive %, Avg Ping, Fastest Node).
    5. Safe by default: runs as a read-only diagnostic check.
    6. Optional flags:
       -OutFile <path>  : Save only verified ALIVE nodes into a new sing-box JSON file.
       -Prune           : Remove dead nodes directly from the input file (creates .bak first).
       -SortByLatency   : Orders surviving nodes from lowest ping to highest ping.
       -Connect         : Immediately connects to the verified alive nodes.

.PARAMETER File
    Path to the JSON file to check (default: vpn_file_01.json).

.PARAMETER OutFile
    Path to save only verified alive nodes (e.g. vpn_file_01_live.json).

.PARAMETER Prune
    Prunes dead nodes from the input file in place (creates backup first).

.PARAMETER Threads
    Number of concurrent worker threads (default: 16).

.PARAMETER TimeoutMs
    Timeout per node probe in milliseconds (default: 4000).

.PARAMETER TestUrl
    URL to fetch through proxy during probe (default: https://www.gstatic.com/generate_204).

.PARAMETER NoGeo
    Skip GeoIP lookup to maximize check speed.

.PARAMETER SortByLatency
    Sort alive nodes by lowest ping when saving to -OutFile or -Prune.

.PARAMETER Connect
    Launch connection cluster with surviving nodes after live check.

.EXAMPLE
    .\check-scraped.ps1
    Tests all nodes in vpn_file_01.json (read-only diagnostic).

.EXAMPLE
    .\check-scraped.ps1 -OutFile vpn_file_live.json
    Tests all nodes and exports only working nodes to vpn_file_live.json.

.EXAMPLE
    .\check-scraped.ps1 -Prune -SortByLatency
    Filters vpn_file_01.json in place, keeping only alive nodes ordered by lowest ping.

.EXAMPLE
    .\check-scraped.ps1 vpn_file_02.json -Threads 20 -TimeoutMs 3000
    Tests vpn_file_02.json with 20 parallel threads and 3s timeout.
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$File = "vpn_file_01.json",

    [string]$OutFile,

    [switch]$Prune,

    [int]$Threads = 16,

    [int]$TimeoutMs = 6000,

    [string]$TestUrl = "https://www.gstatic.com/generate_204",

    [switch]$NoGeo,

    [switch]$SortByLatency,

    [switch]$Connect
)

# Set UTF-8 Console
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = "d:\CODE\Multip VPN" }
$SingBoxBin = Join-Path $ScriptDir "sing-box.exe"
$GeoCacheFile = Join-Path $ScriptDir "_geo_cache.json"

# ── Color Output Helpers ──────────────────────────────────────────────────────
function Write-Header { param($m) Write-Host "`n=== $m ===" -ForegroundColor Magenta }
function Write-Info   { param($m) Write-Host "[*] $m" -ForegroundColor Cyan    }
function Write-Ok     { param($m) Write-Host "[+] $m" -ForegroundColor Green   }
function Write-Warn   { param($m) Write-Host "[!] $m" -ForegroundColor Yellow  }
function Write-Err    { param($m) Write-Host "[-] $m" -ForegroundColor Red     }

# ── Verify Environment & Tools ────────────────────────────────────────────────
if (-not (Test-Path $SingBoxBin)) {
    Write-Err "sing-box.exe not found at '$SingBoxBin'."
    exit 1
}

# Resolve target file path
$targetPath = if ([System.IO.Path]::IsPathRooted($File)) { $File } else { Join-Path $ScriptDir $File }
if (-not (Test-Path $targetPath) -and (Test-Path "$targetPath.json")) {
    $targetPath = "$targetPath.json"
}

if (-not (Test-Path $targetPath)) {
    # Check if there are any other vpn_file*.json in the directory
    $alternatives = Get-ChildItem -Path $ScriptDir -Filter "vpn_file*.json" | Sort-Object LastWriteTime -Descending
    if ($alternatives.Count -gt 0) {
        $targetPath = $alternatives[0].FullName
        Write-Warn "Specified file '$File' not found. Using newest file found: '$($alternatives[0].Name)'"
    } else {
        Write-Err "Target JSON file '$File' not found in '$ScriptDir'."
        exit 1
    }
}

# Load JSON Content
try {
    $rawContent = [System.IO.File]::ReadAllText($targetPath, [System.Text.Encoding]::UTF8)
    $jsonObj = $rawContent | ConvertFrom-Json
} catch {
    Write-Err "Failed to parse JSON in '$targetPath': $($_.Exception.Message)"
    exit 1
}

if (-not $jsonObj.outbounds -or $jsonObj.outbounds.Count -eq 0) {
    Write-Warn "No outbounds found in '$targetPath'."
    exit 0
}

# Filter out non-proxy control outbounds (direct, block, dns, selector, urltest)
$controlTypes = @("selector", "urltest", "direct", "block", "dns")
$proxyNodes   = @($jsonObj.outbounds | Where-Object { $_.type -notin $controlTypes })

if ($proxyNodes.Count -eq 0) {
    Write-Warn "No proxy outbounds found to test in '$targetPath'."
    exit 0
}

# ── GeoIP Cache ───────────────────────────────────────────────────────────────
$GeoCache = @{}
if (-not $NoGeo -and (Test-Path $GeoCacheFile)) {
    try {
        $rawCache = Get-Content -Path $GeoCacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($prop in $rawCache.PSObject.Properties) {
            $GeoCache[$prop.Name] = @{
                country = $prop.Value.country
                city    = $prop.Value.city
            }
        }
    } catch {}
}

function Get-QuickGeo([string]$IpAddress) {
    if ($NoGeo -or -not $IpAddress) { return "" }
    if ($GeoCache.ContainsKey($IpAddress)) {
        $c = $GeoCache[$IpAddress]
        if ($c.country) { return "$($c.country) - $($c.city)" }
    }
    try {
        $respRaw = & curl.exe -s -m 2 "http://ip-api.com/line/${IpAddress}?fields=countryCode,city"
        if ($respRaw) {
            $lines = @($respRaw -split "`r?`n" | Where-Object { $_.Trim() -ne "" })
            if ($lines.Count -ge 1) {
                $country = $lines[0].Trim().ToUpper()
                $city = if ($lines.Count -ge 2) { $lines[1].Trim() } else { "Unknown" }
                $GeoCache[$IpAddress] = @{ country = $country; city = $city }
                return "$country - $city"
            }
        }
    } catch {}
    return ""
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Multip VPN - Scraped JSON Live Node Checker" -ForegroundColor White
Write-Host "   Handshake & HTTP 204 Probe via sing-box" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ("  Target File : {0} ({1} node(s))" -f (Split-Path $targetPath -Leaf), $proxyNodes.Count) -ForegroundColor White
Write-Host ("  Concurrency : {0} thread(s) | Timeout: {1}ms" -f $Threads, $TimeoutMs) -ForegroundColor Gray
Write-Host ("  Probe URL   : {0}" -f $TestUrl) -ForegroundColor Gray
if ($OutFile) { Write-Host ("  Output File : {0}" -f $OutFile) -ForegroundColor Yellow }
if ($Prune)   { Write-Host ("  Mode        : IN-PLACE PRUNE (backup will be created)" ) -ForegroundColor Yellow }
Write-Host ""

# ── Multi-Threaded Live Testing Engine ────────────────────────────────────────
$activeJobs = [System.Collections.Generic.List[PSObject]]::new()
$aliveNodes = [System.Collections.Generic.List[PSObject]]::new()
$deadCount  = 0
$totalNodes = $proxyNodes.Count
$nodeIdx    = 0
$latencies  = [System.Collections.Generic.List[int]]::new()

while ($nodeIdx -lt $totalNodes -or $activeJobs.Count -gt 0) {
    # Dispatch worker processes up to $Threads limit
    while ($nodeIdx -lt $totalNodes -and $activeJobs.Count -lt $Threads) {
        $node = $proxyNodes[$nodeIdx]
        $nodeIdx++

        $itemNum = $nodeIdx
        $probeTmpPath = Join-Path $env:TEMP ("sb_livecheck_" + [Guid]::NewGuid().ToString("N") + ".json")

        $cloneJson = $node | ConvertTo-Json -Depth 10
        $nodeClone = $cloneJson | ConvertFrom-Json
        $nodeClone.tag = "probe-target"

        $probeConfig = @{
            log = @{ level = "error" }
            outbounds = @($nodeClone)
        }
        $jsonStr = $probeConfig | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($probeTmpPath, $jsonStr, $utf8NoBom)

        $errTmpPath = "$probeTmpPath.err"

        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $SingBoxBin
        $pinfo.Arguments = "tools fetch `"$TestUrl`" -c `"$probeTmpPath`" -o probe-target"
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
            Node      = $node
            NodeClone = $nodeClone
            ItemNum   = $itemNum
        })
        Start-Sleep -Milliseconds 15
    }

    # Inspect active worker jobs
    if ($activeJobs.Count -gt 0) {
        $stillRunning = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($job in $activeJobs) {
            $p = $job.Process
            $sw = $job.Stopwatch
            $elapsed = $sw.ElapsedMilliseconds
            $node = $job.Node
            $nodeClone = $job.NodeClone
            $itemNum = $job.ItemNum
            $tagStr = if ($node.tag) { $node.tag } else { "Node" }
            if ($tagStr.Length -gt 28) { $tagStr = $tagStr.Substring(0, 25) + "..." }

            if ($p.HasExited) {
                $sw.Stop()
                $exitCode = $p.ExitCode
                $errText = ""
                try {
                    $errText = ($p.StandardError.ReadToEnd() -split "`n")[0].Trim()
                } catch {}
                $p.Dispose()
                Remove-Item $job.TmpFile -Force -ErrorAction SilentlyContinue

                $isAlive = ($exitCode -eq 0)

                # Auto-recovery for self-signed or expired TLS certificates
                if (-not $isAlive -and ($errText -match "certificate has expired" -or $errText -match "cannot validate certificate") -and $nodeClone.tls) {
                    $nodeClone.tls | Add-Member -NotePropertyName "insecure" -NotePropertyValue $true -Force
                    $reprobePath = Join-Path $env:TEMP ("sb_livecheck_" + [Guid]::NewGuid().ToString("N") + ".json")
                    $reJson = @{ log = @{ level = "error" }; outbounds = @($nodeClone) } | ConvertTo-Json -Depth 10
                    [System.IO.File]::WriteAllText($reprobePath, $reJson, $utf8NoBom)
                    $reProc = & $SingBoxBin tools fetch "$TestUrl" -c $reprobePath -o probe-target 2>&1
                    Remove-Item $reprobePath -Force -ErrorAction SilentlyContinue
                    if ($LASTEXITCODE -eq 0) {
                        $isAlive = $true
                        if ($node.tls -is [System.Collections.IDictionary]) {
                            $node.tls["insecure"] = $true
                        } else {
                            $node.tls | Add-Member -NotePropertyName "insecure" -NotePropertyValue $true -Force
                        }
                    }
                }

                if ($isAlive) {
                    $latencies.Add([int]$elapsed)
                    # Resolve GeoIP
                    $geoStr = ""
                    if (-not $NoGeo) {
                        $resolvedIp = $node.server
                        try {
                            $ips = [System.Net.Dns]::GetHostAddresses($node.server)
                            $resolvedIp = ($ips | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
                        } catch {}
                        $geoInfo = Get-QuickGeo $resolvedIp
                        if ($geoInfo) { $geoStr = "[$geoInfo] " }
                    }

                    Write-Host ("[{0,2}/{1}] [{2,-5}] {3,-28} {4,-24} -> ALIVE {5}({6}ms)" -f `
                        $itemNum, $totalNodes, $node.type.ToUpper(), ("$($node.server):$($node.server_port)"), "'$tagStr'", $geoStr, $elapsed) -ForegroundColor Green

                    # Attach latency property for sorting if requested
                    $node | Add-Member -NotePropertyName "_ping" -NotePropertyValue ([int]$elapsed) -Force -ErrorAction SilentlyContinue
                    $aliveNodes.Add($node)
                } else {
                    $deadCount++
                    $errDesc = "Failed"
                    if ($errText -match "EOF") {
                        $errDesc = "Server dropped connection (EOF)"
                    } elseif ($errText -match "overflow reading version string") {
                        $errDesc = "Protocol/Port mismatch"
                    } elseif ($errText -match "refused") {
                        $errDesc = "Connection refused"
                    } elseif ($errText -match "lookup.*empty result|no such host") {
                        $errDesc = "DNS lookup failed"
                    } elseif ($errText -match "status code: (\d+)") {
                        $errDesc = "Auth error (HTTP $($Matches[1]))"
                    } elseif ($errText -match "context deadline exceeded") {
                        $errDesc = "Timeout (handshake stalled)"
                    } elseif ($errText -match "handshake failed") {
                        $errDesc = "Handshake failed"
                    } elseif ($errText) {
                        $errDesc = $errText
                    }

                    Write-Host ("[{0,2}/{1}] [{2,-5}] {3,-28} {4,-24} -> DEAD ({5})" -f `
                        $itemNum, $totalNodes, $node.type.ToUpper(), ("$($node.server):$($node.server_port)"), "'$tagStr'", $errDesc) -ForegroundColor Red
                }
            } elseif ($elapsed -gt $TimeoutMs) {
                # Worker timed out
                $sw.Stop()
                try { $p.Kill(); $p.Dispose() } catch {}
                Remove-Item $job.TmpFile -Force -ErrorAction SilentlyContinue

                $deadCount++
                Write-Host ("[{0,2}/{1}] [{2,-5}] {3,-28} {4,-24} -> DEAD (Timeout >{5}ms)" -f `
                    $itemNum, $totalNodes, $node.type.ToUpper(), ("$($node.server):$($node.server_port)"), "'$tagStr'", $TimeoutMs) -ForegroundColor Yellow
            } else {
                $stillRunning.Add($job)
            }
        }
        $activeJobs = $stillRunning
    }
    Start-Sleep -Milliseconds 40
}

# ── Save Geo Cache ────────────────────────────────────────────────────────────
if (-not $NoGeo -and $GeoCache.Count -gt 0) {
    try {
        $cacheJson = $GeoCache | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($GeoCacheFile, $cacheJson, $utf8NoBom)
    } catch {}
}

# ── Summary Report ────────────────────────────────────────────────────────────
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "   LIVE CHECK SUMMARY" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ("  Target File   : {0}" -f (Split-Path $targetPath -Leaf)) -ForegroundColor White
Write-Host ("  Total Tested  : {0}" -f $totalNodes) -ForegroundColor White

$aliveCount = $aliveNodes.Count
$alivePct   = if ($totalNodes -gt 0) { [math]::Round(($aliveCount / $totalNodes) * 100, 1) } else { 0 }
$deadPct    = if ($totalNodes -gt 0) { [math]::Round(($deadCount / $totalNodes) * 100, 1) } else { 0 }

Write-Host ("  Alive Nodes   : {0} ({1}%)" -f $aliveCount, $alivePct) -ForegroundColor Green
Write-Host ("  Dead Nodes    : {0} ({1}%)" -f $deadCount, $deadPct) -ForegroundColor $(if ($deadCount -gt 0) { "Red" } else { "DarkGray" })

if ($latencies.Count -gt 0) {
    $minPing = ($latencies | Measure-Object -Minimum).Minimum
    $maxPing = ($latencies | Measure-Object -Maximum).Maximum
    $avgPing = [math]::Round(($latencies | Measure-Object -Average).Average)
    Write-Host ("  Fastest Ping  : {0}ms" -f $minPing) -ForegroundColor Green
    Write-Host ("  Average Ping  : {0}ms (Max: {1}ms)" -f $avgPing, $maxPing) -ForegroundColor Cyan
}
Write-Host "================================================================`n" -ForegroundColor Cyan

# ── Exporting / Pruning Logic ─────────────────────────────────────────────────
if ($aliveCount -eq 0 -and ($OutFile -or $Prune)) {
    Write-Warn "No alive nodes found. Output file was not modified."
    exit 0
}

# Optional sorting by latency
if ($SortByLatency -and $aliveNodes.Count -gt 1) {
    $sorted = $aliveNodes | Sort-Object { if ($_.PSObject.Properties["_ping"]) { $_._ping } else { 99999 } }
    $aliveNodes = [System.Collections.Generic.List[PSObject]]::new([PSObject[]]@($sorted))
    Write-Info "Sorted surviving nodes by lowest latency."
}

# Clean internal temporary properties before saving
$cleanAliveList = @()
foreach ($n in $aliveNodes) {
    $clone = $n | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    if ($clone.PSObject.Properties["_ping"]) {
        $clone.PSObject.Properties.Remove("_ping")
    }
    $cleanAliveList += $clone
}

# Action 1: Save to separate OutFile
if ($OutFile) {
    $outPath = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path $ScriptDir $OutFile }
    $exportObj = @{ outbounds = $cleanAliveList }
    $exportJson = $exportObj | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($outPath, $exportJson, $utf8NoBom)
    Write-Ok ("Saved {0} verified ALIVE node(s) to '{1}'" -f $cleanAliveList.Count, (Split-Path $outPath -Leaf))

    # Validate output file with sing-box
    $chk = & $SingBoxBin check -c $outPath 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "sing-box check: 100% compliant standard configuration."
    } else {
        Write-Warn "sing-box check warning: $chk"
    }
}

# Action 2: In-place Prune
if ($Prune) {
    $backupPath = "$targetPath.bak"
    Copy-Item -Path $targetPath -Destination $backupPath -Force
    Write-Info ("Created safety backup: '{0}'" -f (Split-Path $backupPath -Leaf))

    $exportObj = @{ outbounds = $cleanAliveList }
    $exportJson = $exportObj | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($targetPath, $exportJson, $utf8NoBom)
    Write-Ok ("Pruned '{0}': kept {1} live nodes, removed {2} dead nodes." -f (Split-Path $targetPath -Leaf), $cleanAliveList.Count, $deadCount)

    # Validate file with sing-box
    $chk = & $SingBoxBin check -c $targetPath 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "sing-box check: 100% compliant standard configuration."
    }
}

# Action 3: Connect
if ($Connect -and $aliveCount -gt 0) {
    Write-Header "Launching Multip VPN Connection Cluster"
    $connectScript = Join-Path $ScriptDir "connect-cluster.ps1"
    if (Test-Path $connectScript) {
        & $connectScript
    } else {
        Write-Warn "connect-cluster.ps1 not found in $ScriptDir"
    }
}
