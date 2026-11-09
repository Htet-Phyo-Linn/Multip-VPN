<#
.SYNOPSIS
    Multip VPN - True Per-Connection Round-Robin Rotator (Full Randomizer)
    Every single outbound connection exits through a different proxy node across different countries!

.DESCRIPTION
    1. Scans and harvests all approved nodes from config*.json files.
    2. Enforces Antigravity Geo-Filter (drops HK, CN, RU, IR, KP, etc.).
    3. Selects a diverse multi-country pool of rotating nodes (US, Japan, Singapore, Germany, Canada, Spain, UK, etc.).
    4. Generates hardware source-port modulo routing rules inside sing-box kernel.
       Every new TCP connection receives an ephemeral source port from Windows, mapping to a different exit IP!
    5. Exposes both transparent TUN mode (system-wide) and local rotating proxy (127.0.0.1:10808).
    6. Bypasses physical Wi-Fi gateway to preserve Customer VPN / FortiClient / AnyConnect routes.
    7. Cleans up all routes and restores network upon Ctrl+C.
#>

[CmdletBinding()]
param(
    [string]$ConfigFolder = $PSScriptRoot,
    [int]$PoolSize        = 16,
    [int]$MixedPort       = 10808
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = "d:\CODE\Multip VPN" }
if (-not $ConfigFolder) { $ConfigFolder = $ScriptDir }

$SingBoxBin = Join-Path $ScriptDir "sing-box.exe"
$utf8NoBom  = New-Object System.Text.UTF8Encoding $false

# Antigravity Blocked Countries
$BlockedCountries = @("HK", "CN", "RU", "IR", "KP", "SY", "CU", "BY", "MM", "VE")

# Customer VPN subnets to preserve
$CustomerSubnets  = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[-] $msg" -ForegroundColor Red }

# Elevate to Admin if required
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Requesting Administrator privileges for route manipulation & TUN adapter..."
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   🎲 MULTIP VPN - PER-CONNECTION ROUND-ROBIN ROTATOR" -ForegroundColor White
Write-Host "   Full Randomizer * Kernel Source-Port Modulo * Tor-Style Hops" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $SingBoxBin)) {
    Write-Err "sing-box.exe not found at: $SingBoxBin"
    exit 1
}

# ── Cleanup Tracking ──────────────────────────────────────────────────────────
$CreatedRoutes         = [System.Collections.Generic.List[object]]::new()
$CreatedFirewallRules  = [System.Collections.Generic.List[string]]::new()
$SingBoxProcess        = $null
$TempConfigPath        = Join-Path $ScriptDir "_singbox_rotator_run.json"

function Invoke-Cleanup {
    Write-Host ""
    Write-Info "Stopping rotator... Restoring network..."

    if ($SingBoxProcess -ne $null -and -not $SingBoxProcess.HasExited) {
        try {
            $SingBoxProcess.Kill()
            $SingBoxProcess.WaitForExit(3000)
            Write-Ok "sing-box stopped (TUN adapter removed)."
        } catch {}
    }
    Get-Process -Name "sing-box" -ErrorAction SilentlyContinue |
        ForEach-Object { try { $_.Kill() } catch {} }

    if ($CreatedRoutes.Count -gt 0) {
        Write-Info "Removing $($CreatedRoutes.Count) rotator bypass route(s)..."
        foreach ($r in $CreatedRoutes) {
            try {
                Remove-NetRoute -DestinationPrefix $r.Prefix -NextHop $r.Gateway `
                                -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Ok "  Bypass routes cleared."
    }

    # Also perform safety bulk sweep for any lingering /32 routes pointing to gateway
    if ($gw -and $gw.Gateway) {
        try {
            Get-NetRoute -DestinationPrefix "*/32" -NextHop $gw.Gateway -RouteMetric 5 -ErrorAction SilentlyContinue |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        } catch {}
    }

    # Fast bulk removal of MultipVPN firewall rules
    try {
        Remove-NetFirewallRule -DisplayName "MultipVPN*" -ErrorAction SilentlyContinue
        Write-Ok "  Firewall rules cleared."
    } catch {}

    if ($TempConfigPath -and (Test-Path $TempConfigPath)) {
        Remove-Item $TempConfigPath -Force -ErrorAction SilentlyContinue
    }

    # Flush DNS and ensure system proxy is disabled
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
    try { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue } catch {}

    Write-Ok "Network completely restored. Customer VPN is intact."
}

$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Invoke-Cleanup }

# ── Physical Gateway Detection ────────────────────────────────────────────────
function Get-PhysicalGateway {
    $skipWords = @("vmware","virtual","tap","loopback","tunnel","pangp","anyconnect","fortinet","cisco","outline")
    $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric
    foreach ($r in $routes) {
        if ($r.NextHop -eq "0.0.0.0") { continue }
        $adapter = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter -or $adapter.Status -ne "Up") { continue }
        $desc = $adapter.InterfaceDescription.ToLower()
        $skip = $false
        foreach ($w in $skipWords) { if ($desc -like "*$w*") { $skip = $true; break } }
        if (-not $skip) {
            return @{ Gateway = $r.NextHop; IfIndex = $r.InterfaceIndex; Name = $adapter.Name }
        }
    }
    $best = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if ($best -and $best.NextHop -ne "0.0.0.0") {
        $adapter = Get-NetAdapter -InterfaceIndex $best.InterfaceIndex -ErrorAction SilentlyContinue
        return @{ Gateway = $best.NextHop; IfIndex = $best.InterfaceIndex; Name = $adapter.Name }
    }
    return $null
}

function Add-TrackedRoute {
    param($Prefix, $Gateway, $IfIndex, $Metric = 5)
    try {
        Remove-NetRoute -DestinationPrefix $Prefix -NextHop $Gateway -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $Prefix -NextHop $Gateway `
                     -InterfaceIndex $IfIndex -RouteMetric $Metric `
                     -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $CreatedRoutes.Add([pscustomobject]@{ Prefix = $Prefix; Gateway = $Gateway })
    } catch {}
}

function Add-TrackedFwRule {
    param($Name, $Direction, $Protocol)
    try {
        $p = @{ DisplayName = $Name; Direction = $Direction; Action = "Allow"; Enabled = "True"; Profile = "Any" }
        if ($Protocol) { $p.Protocol = $Protocol }
        New-NetFirewallRule @p -ErrorAction Stop | Out-Null
        $CreatedFirewallRules.Add($Name)
    } catch {}
}

# ── IP Geolocation Helper ─────────────────────────────────────────────────────
$GeoCacheFile = Join-Path $ScriptDir "_geo_cache.json"
$script:GeoCache = @{}
if (Test-Path $GeoCacheFile) {
    try {
        $loaded = Get-Content $GeoCacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($prop in $loaded.PSObject.Properties) { $script:GeoCache[$prop.Name] = $prop.Value }
    } catch {}
}

function Save-GeoCache {
    try {
        $cacheJson = $script:GeoCache | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($GeoCacheFile, $cacheJson, $utf8NoBom)
    } catch {}
}

function Resolve-GeoLocationsParallel {
    param(
        [string[]]$IPs,
        [string]$Token = "a1e1161ecc1b38"
    )

    $results = @{}
    if (-not $IPs -or $IPs.Count -eq 0) { return $results }

    # 1. Hit memory cache first
    $uncached = [System.Collections.Generic.List[string]]::new()
    foreach ($ip in $IPs) {
        if ($script:GeoCache.ContainsKey($ip)) {
            $results[$ip] = $script:GeoCache[$ip]
        } else {
            $uncached.Add($ip)
        }
    }

    if ($uncached.Count -eq 0) { return $results }

    # 2. Batch query via ip-api.com (100 IPs per call in ~150ms)
    $chunkSize = 100
    for ($i = 0; $i -lt $uncached.Count; $i += $chunkSize) {
        $chunk = @($uncached[$i..([Math]::Min($i + $chunkSize - 1, $uncached.Count - 1))])
        try {
            $jsonBody = $chunk | ConvertTo-Json -Compress
            $tempFile = [System.IO.Path]::GetTempFileName()
            [System.IO.File]::WriteAllText($tempFile, $jsonBody, $utf8NoBom)
            $respRaw = & curl.exe -s -m 4 -d "@$tempFile" -H "Content-Type: application/json" "http://ip-api.com/batch?fields=query,country,countryCode,city"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

            if ($respRaw) {
                $batchList = $respRaw | ConvertFrom-Json
                foreach ($item in $batchList) {
                    if ($item.countryCode) {
                        $entry = [pscustomobject]@{
                            country = $item.countryCode.ToString().Trim().ToUpper()
                            city    = if ($item.city) { $item.city.ToString() } else { "" }
                        }
                        $results[$item.query] = $entry
                        $script:GeoCache[$item.query] = $entry
                    }
                }
            }
        } catch {}
    }

    # 3. For any remaining missing IPs, run concurrent multi-threaded fallback (16 workers)
    $stillMissing = @($uncached | Where-Object { -not $results.ContainsKey($_) })
    if ($stillMissing.Count -gt 0) {
        $maxWorkers = [Math]::Min(16, $stillMissing.Count)
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxWorkers)
        $pool.Open()
        $jobs = [System.Collections.Generic.List[object]]::new()

        foreach ($mIp in $stillMissing) {
            $ps = [System.Management.Automation.PowerShell]::Create().AddScript({
                param($ip, $tok)
                # Primary fallback: ipinfo.io
                try {
                    $url = if ($tok) { "https://ipinfo.io/$ip/json?token=$tok" } else { "https://ipinfo.io/$ip/json" }
                    $r = & curl.exe -s -m 3 $url
                    if ($r) {
                        $d = $r | ConvertFrom-Json
                        if ($d.country) {
                            return [pscustomobject]@{
                                ip      = $ip
                                country = $d.country.ToString().Trim().ToUpper()
                                city    = if ($d.city) { $d.city.ToString() } else { "" }
                            }
                        }
                    }
                } catch {}

                # Secondary fallback: ipwho.is
                try {
                    $r = & curl.exe -s -m 3 "https://ipwho.is/$ip"
                    if ($r) {
                        $d = $r | ConvertFrom-Json
                        if ($d.country_code) {
                            return [pscustomobject]@{
                                ip      = $ip
                                country = $d.country_code.ToString().Trim().ToUpper()
                                city    = if ($d.city) { $d.city.ToString() } else { "" }
                            }
                        }
                    }
                } catch {}

                return [pscustomobject]@{ ip = $ip; country = "UNKNOWN"; city = "" }
            }).AddArgument($mIp).AddArgument($Token)

            $ps.RunspacePool = $pool
            $jobs.Add([pscustomobject]@{ Pipe = $ps; Handle = $ps.BeginInvoke() })
        }

        foreach ($job in $jobs) {
            try {
                $res = $job.Pipe.EndInvoke($job.Handle)
                if ($res -and $res.ip -and $res.country -and $res.country -ne "UNKNOWN") {
                    $entry = [pscustomobject]@{
                        country = $res.country
                        city    = $res.city
                    }
                    $results[$res.ip] = $entry
                    $script:GeoCache[$res.ip] = $entry
                }
            } catch {} finally {
                $job.Pipe.Dispose()
            }
        }
        $pool.Close()
        $pool.Dispose()
    }

    return $results
}

# ── 1. Discover & Harvest All Proxy Nodes ──────────────────────────────────────
Write-Info "Scanning for VPN configuration files in: $ConfigFolder"
$jsonFiles = Get-ChildItem -Path $ConfigFolder -Filter "*.json" |
             Where-Object { 
                 $_.Name -notlike "_singbox*" -and 
                 $_.Name -notlike "_geo*" -and 
                 $_.Name -notlike "*.example.json" -and 
                 $_.Name -notlike "normal_config*.json" 
             }

if (-not $jsonFiles -or $jsonFiles.Count -eq 0) {
    Write-Err "No JSON config files found in $ConfigFolder!"
    exit 1
}

Write-Ok "Discovered $($jsonFiles.Count) config file(s):"
foreach ($jf in $jsonFiles) { Write-Host "   • $($jf.Name)" -ForegroundColor Gray }

$rawNodes      = [System.Collections.Generic.List[object]]::new()
$seenEndpoints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$seenTags      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($jf in $jsonFiles) {
    try {
        $raw = Get-Content $jf.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $obs = if ($raw.PSObject.Properties["outbounds"]) { @($raw.outbounds) } else { @($raw) }

        foreach ($ob in $obs) {
            if ($ob.type -in @("direct", "block", "dns", "selector", "urltest")) { continue }
            if (-not $ob.server -or $ob.server -eq "example.com" -or $ob.server -like "*00000000*") { continue }

            $sni = if ($ob.tls -and $ob.tls.server_name) { $ob.tls.server_name } else { "" }
            $hostHdr = if ($ob.transport -and $ob.transport.headers -and $ob.transport.headers.Host) {
                $ob.transport.headers.Host
            } elseif ($ob.transport -and $ob.transport.host) {
                $ob.transport.host
            } else { "" }
            $path = if ($ob.transport -and $ob.transport.path) { $ob.transport.path } else { "" }
            $uuid = if ($ob.uuid) { $ob.uuid } elseif ($ob.password) { $ob.password } else { "" }

            $nodeKey = "$($ob.type)://$($ob.server):$($ob.server_port)|$sni|$hostHdr|$path|$uuid".ToLowerInvariant()
            if ($seenEndpoints.Contains($nodeKey)) { continue }
            $null = $seenEndpoints.Add($nodeKey)

            $rawNodes.Add($ob)
        }
    } catch {
        Write-Warn "Could not parse $($jf.Name): $_"
    }
}

Write-Info "Harvested $($rawNodes.Count) total unique candidate node(s)."

# ── 2. Security & Geo Filter (High-Speed Multi-Threaded Engine) ───────────────
Write-Info "Checking geolocations against Antigravity filter..."
$approvedNodes    = [System.Collections.Generic.List[object]]::new()
$allowedServerIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Extract unique servers across all raw nodes
$uniqueServers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($n in $rawNodes) {
    if ($n.server) { $null = $uniqueServers.Add($n.server.ToString().Trim()) }
}

Write-Info "Resolving DNS for $($uniqueServers.Count) server endpoint(s) in parallel..."
$dnsTasks = @{}
$resolvedServerIPs = @{}

foreach ($srv in $uniqueServers) {
    $parsedIP = $null
    if ([System.Net.IPAddress]::TryParse($srv, [ref]$parsedIP)) {
        if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $resolvedServerIPs[$srv] = $parsedIP.ToString()
        }
    } else {
        try {
            $dnsTasks[$srv] = [System.Net.Dns]::GetHostAddressesAsync($srv)
        } catch {}
    }
}

if ($dnsTasks.Count -gt 0) {
    try {
        [System.Threading.Tasks.Task]::WaitAll(@($dnsTasks.Values), 3500) | Out-Null
    } catch {}

    foreach ($kv in $dnsTasks.GetEnumerator()) {
        $srv = $kv.Key
        $task = $kv.Value
        if ($task.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and $task.Result) {
            $ipv4List = @($task.Result | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
            if ($ipv4List.Count -gt 0) {
                $resolvedServerIPs[$srv] = $ipv4List[0].ToString()
            }
        }
    }
}

# Collect target IPs and query geolocation in parallel
$targetIPs = @($resolvedServerIPs.Values | Select-Object -Unique)
Write-Info "Querying geolocations for $($targetIPs.Count) IP(s) in parallel (batch & cache)..."
$geoResults = Resolve-GeoLocationsParallel -IPs $targetIPs
Save-GeoCache

# Filter nodes and tag with country/city (Deduplicated by Type + IP + Port combination)
$seenIpPortCombo      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$duplicateServerCount = 0

foreach ($node in $rawNodes) {
    $serverStr = $node.server.ToString().Trim()
    if (-not $resolvedServerIPs.ContainsKey($serverStr)) { continue }

    $resolvedIP = $resolvedServerIPs[$serverStr]
    $typeIpPortKey = "$($node.type)://$resolvedIP`:$($node.server_port)".ToLowerInvariant()

    if ($seenIpPortCombo.Contains($typeIpPortKey)) {
        $duplicateServerCount++
        continue
    }

    $geo = if ($geoResults.ContainsKey($resolvedIP)) { $geoResults[$resolvedIP] } else { $null }
    $country = if ($geo -and $geo.country) { $geo.country } else { "UNKNOWN" }
    $city    = if ($geo -and $geo.city) { $geo.city } else { "Unknown" }

    if ($country -in $BlockedCountries) { continue }

    $null = $seenIpPortCombo.Add($typeIpPortKey)
    $null = $allowedServerIPs.Add($resolvedIP)

    # Store clean country label on node for display
    $node | Add-Member -MemberType NoteProperty -Name "_Country" -Value $country -Force
    $node | Add-Member -MemberType NoteProperty -Name "_City" -Value $city -Force
    $approvedNodes.Add($node)
}

if ($duplicateServerCount -gt 0) {
    Write-Info "Deduplication: Filtered out $duplicateServerCount duplicate node(s) sharing identical Protocol + IP:Port."
}

if ($approvedNodes.Count -eq 0) {
    Write-Err "No nodes passed the security and region filter!"
    exit 1
}

# ── 3. Select Diverse Rotating Pool ───────────────────────────────────────────
# Group by country to ensure maximum international diversity across hops
$byCountry = $approvedNodes | Group-Object { $_._Country }
$rotatingPool = [System.Collections.Generic.List[object]]::new()

$maxPerRound = [Math]::Ceiling($PoolSize / $byCountry.Count)
$added = 0

# Interleave countries in round-robin sequence
for ($r = 0; $r -lt 20; $r++) {
    foreach ($grp in $byCountry) {
        if ($r -lt $grp.Group.Count) {
            $rotatingPool.Add($grp.Group[$r])
            $added++
            if ($added -ge $PoolSize) { break }
        }
    }
    if ($added -ge $PoolSize) { break }
}

# Normalize unique tags for rotating pool
$nodeIdx = 0
foreach ($rn in $rotatingPool) {
    $nodeIdx++
    $rn.tag = ("Rotator-{0:D2} [{1}-{2}]" -f $nodeIdx, $rn._Country, $rn.type.ToUpper())
}

Write-Ok "Selected $($rotatingPool.Count) diverse node(s) for the active rotation pool:"
$idx = 0
foreach ($rn in $rotatingPool) {
    $idx++
    Write-Host ("   [{0:D2}] {1,-28} &rarr; {2}:{3} ({4}, {5})" -f $idx, $rn.tag, $rn.server, $rn.server_port, $rn._City, $rn._Country) -ForegroundColor Gray
}

# Save updated GeoCache
try {
    $cacheJson = $script:GeoCache | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($GeoCacheFile, $cacheJson, $utf8NoBom)
} catch {}

# ── 4. Detect Physical Gateway & Add Bypass Routes ────────────────────────────
Write-Info "Detecting physical gateway (bypasses FortiClient / AnyConnect)..."
$gw = Get-PhysicalGateway
if (-not $gw) {
    Write-Err "Could not identify physical gateway. Check your internet connection."
    exit 1
}
Write-Ok "Physical Gateway: $($gw.Gateway) on $($gw.Name) (idx=$($gw.IfIndex))"

Write-Info "Adding bypass routes for rotating server endpoints..."
foreach ($ip in $allowedServerIPs) {
    Add-TrackedRoute -Prefix "$ip/32" -Gateway $gw.Gateway -IfIndex $gw.IfIndex
}
Write-Ok "All cluster server traffic routed to physical gateway (Customer VPN safe)."

Add-TrackedFwRule -Name "MultipVPN-Rotator-Out" -Direction Outbound -Protocol TCP
Add-TrackedFwRule -Name "MultipVPN-Rotator-UDP" -Direction Outbound -Protocol UDP

# ── 5. Generate Kernel Source-Port Modulo Round-Robin Rules ───────────────────
# Windows allocates ephemeral ports sequentially from 49152 to 65535 on each new connection.
# Dividing the port space by modulo ($port % $PoolCount) ensures true connection-by-connection rotation!
$activeCount = $rotatingPool.Count
$rotatorRules = [System.Collections.Generic.List[object]]::new()

for ($i = 0; $i -lt $activeCount; $i++) {
    $targetNode = $rotatingPool[$i]
    $ports = [System.Collections.Generic.List[int]]::new()
    for ($p = 49152; $p -le 65535; $p++) {
        if (($p % $activeCount) -eq $i) {
            $ports.Add($p)
        }
    }
    $rotatorRules.Add([pscustomobject]@{
        source_port = @($ports)
        outbound    = $targetNode.tag
    })
}

# Outbounds assembly
$fullOutbounds = [System.Collections.Generic.List[object]]::new()
foreach ($rn in $rotatingPool) { $fullOutbounds.Add($rn) }
$fullOutbounds.Add([pscustomobject]@{ type = "direct"; tag = "direct" })
$fullOutbounds.Add([pscustomobject]@{ type = "block";  tag = "block" })

# Split-tunnel exclusions (Customer VPN + Antigravity Localhost Safe)
$standardPrivateSubnets = @(
    "127.0.0.0/8",         # Localhost loopback (Antigravity IDE, local agent IPC, language servers)
    "10.0.0.0/8",          # RFC 1918 Private / FortiClient / AnyConnect
    "172.16.0.0/12",       # RFC 1918 Private / Customer VPN
    "192.168.0.0/16",      # RFC 1918 Local LAN / Wi-Fi Gateway
    "169.254.0.0/16",      # Link-local / APIPA
    "224.0.0.0/4",         # Multicast
    "255.255.255.255/32"   # Broadcast
)

$excludeList = [System.Collections.Generic.List[string]]::new()
foreach ($p in $standardPrivateSubnets) {
    if (-not $excludeList.Contains($p)) { $excludeList.Add($p) }
}
foreach ($sub in $CustomerSubnets) {
    if (-not $excludeList.Contains($sub)) { $excludeList.Add($sub) }
}
foreach ($ip in $allowedServerIPs) {
    $cidr = "$ip/32"
    if (-not $excludeList.Contains($cidr)) { $excludeList.Add($cidr) }
}

# Transparent TUN + Local Mixed Rotating Proxy
$tunInbound = [pscustomobject]@{
    type                  = "tun"
    tag                   = "tun-in"
    address               = @("172.19.0.1/30")
    auto_route            = $true
    strict_route          = $false
    stack                 = "mixed"
    route_exclude_address = @($excludeList)
}

$mixedInbound = [pscustomobject]@{
    type        = "mixed"
    tag         = "mixed-in"
    listen      = "127.0.0.1"
    listen_port = $MixedPort
}

# Routing Table (Antigravity & Customer VPN Safe)
$allRules = [System.Collections.Generic.List[object]]::new()
$allRules.Add([pscustomobject]@{ action = "sniff" })
$allRules.Add([pscustomobject]@{ protocol = "dns"; action = "hijack-dns" })
$allRules.Add([pscustomobject]@{ ip_is_private = $true; outbound = "direct" })
$allRules.Add([pscustomobject]@{ ip_cidr = @($excludeList); outbound = "direct" })
foreach ($rr in $rotatorRules) { $allRules.Add($rr) }

$finalConfig = [pscustomobject]@{
    log = [pscustomobject]@{ level = "warn"; timestamp = $true }
    dns = [pscustomobject]@{
        servers = @(
            [pscustomobject]@{ tag = "dns-remote-tcp"; type = "tcp";   server = "8.8.8.8"; detour = $rotatingPool[0].tag },
            [pscustomobject]@{ tag = "dns-remote-doh"; type = "https"; server = "https://1.1.1.1/dns-query"; detour = $rotatingPool[0].tag },
            [pscustomobject]@{ tag = "dns-local";      type = "local" }
        )
        rules = @(
            [pscustomobject]@{ ip_is_private = $true; server = "dns-local" }
        )
        final = "dns-remote-tcp"
    }
    inbounds  = @($tunInbound, $mixedInbound)
    outbounds = @($fullOutbounds)
    route     = [pscustomobject]@{
        rules                 = @($allRules)
        auto_detect_interface = $true
        final                 = $rotatingPool[0].tag
    }
}

$json = $finalConfig | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($TempConfigPath, $json, $utf8NoBom)
Write-Ok "Rotator configuration synthesized ($($rotatingPool.Count) rotating circuits, 10808 mixed proxy)."

# ── 6. Start sing-box Engine ──────────────────────────────────────────────────
Write-Host ""
Write-Info "Starting sing-box Per-Connection Rotator Engine..."

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = $SingBoxBin
$psi.Arguments              = "run -c `"$TempConfigPath`""
$psi.UseShellExecute        = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.CreateNoWindow         = $false

$SingBoxProcess = New-Object System.Diagnostics.Process
$SingBoxProcess.StartInfo = $psi
$SingBoxProcess.EnableRaisingEvents = $true

Register-ObjectEvent $SingBoxProcess OutputDataReceived -Action {
    if ($Event.SourceEventArgs.Data) { Write-Host "[rotator] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkGray }
} | Out-Null
Register-ObjectEvent $SingBoxProcess ErrorDataReceived -Action {
    if ($Event.SourceEventArgs.Data) { Write-Host "[rotator] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkYellow }
} | Out-Null

$SingBoxProcess.Start() | Out-Null
$SingBoxProcess.BeginOutputReadLine()
$SingBoxProcess.BeginErrorReadLine()

Start-Sleep -Seconds 2

if ($SingBoxProcess.HasExited) {
    Write-Err "sing-box rotator failed to start (exit code: $($SingBoxProcess.ExitCode))"
    Invoke-Cleanup
    exit 1
}

Write-Ok "sing-box Rotator is ACTIVE (PID: $($SingBoxProcess.Id))"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  CONNECTED! PER-CONNECTION ROUND-ROBIN ROTATOR ACTIVE (🎲)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  * Rotation Pool       : $($rotatingPool.Count) active circuits across $($byCountry.Count) countries" -ForegroundColor White
Write-Host "  * Rotation Mechanism  : 🎲 True Per-Connection (Kernel Source-Port Modulo)" -ForegroundColor White
Write-Host "  * Transparent TUN     : ACTIVE (All system traffic rotates automatically)" -ForegroundColor White
Write-Host "  * Local Proxy Port    : 127.0.0.1:$MixedPort (SOCKS5 / HTTP for curl & scrapers)" -ForegroundColor Cyan
Write-Host "  * Customer VPN        : Split-tunnel intact ($($CustomerSubnets -join ', '))" -ForegroundColor Gray
Write-Host ""
Write-Host "  Test rotation anytime in another terminal:" -ForegroundColor Yellow
Write-Host "    .\Test-Rotation.bat" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Press Ctrl+C to disconnect and restore all routes." -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

# ── 7. Keep Alive ─────────────────────────────────────────────────────────────
try {
    while (-not $SingBoxProcess.HasExited) {
        Start-Sleep -Milliseconds 500
    }
    Write-Warn "sing-box rotator stopped (exit code: $($SingBoxProcess.ExitCode))"
} finally {
    Invoke-Cleanup
}
