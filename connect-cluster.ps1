#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sing-box Multi-Config Cluster & Auto Load Balancer (Tor-style multi-exit)
    - Ingests ALL config*.json files in the folder and aggregates all free keys.
    - AI / Antigravity Geo-Filter: Automatically checks IP location using IPinfo API.
    - Blocks unsupported/sanctioned countries (Hong Kong, China, Russia, Iran, etc.).
    - Real-time Lowest-Ping Auto-Balancing (urltest across all approved nodes).
    - Auto-failover: if a free key dies or throttles, traffic immediately moves to the fastest live node.
    - Protocol Pools: Hysteria2 Turbo Pool + VLESS Reality Stealth Pool + Global Cluster.
    - Split-tunneling: Coexists with Cisco AnyConnect, FortiClient, and corporate subnets.
    - Full auto-cleanup on exit (Ctrl+C).
#>

[CmdletBinding()]
param(
    [string]$ConfigFolder     = $PSScriptRoot,
    [string]$SingBoxPath      = "",
    [string[]]$CustomerSubnets = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
    [string]$IpInfoToken      = "a1e1161ecc1b38",
    [string[]]$BlockedCountries = @("HK", "CN", "RU", "IR", "KP", "SY", "CU", "BY", "MM", "VE")
)

$ErrorActionPreference = "Stop"

# ── Color Output Helpers ──────────────────────────────────────────────────────
function Write-Info    { param($m) Write-Host "[*] $m" -ForegroundColor Cyan    }
function Write-Ok      { param($m) Write-Host "[+] $m" -ForegroundColor Green   }
function Write-Warn    { param($m) Write-Host "[!] $m" -ForegroundColor Yellow  }
function Write-Err     { param($m) Write-Host "[-] $m" -ForegroundColor Red     }

# ── Auto-Elevation to Administrator ──────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal](
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warn "Cluster TUN mode requires Administrator privileges."
    Write-Info "Re-launching elevated (UAC prompt)..."
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($ConfigFolder) { $argList += " -ConfigFolder `"$ConfigFolder`"" }
    if ($SingBoxPath)  { $argList += " -SingBoxPath `"$SingBoxPath`"" }
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit 0
}

# ── State Tracking for Clean Exit ─────────────────────────────────────────────
$CreatedFirewallRules = New-Object System.Collections.Generic.List[string]
$CreatedRoutes        = New-Object System.Collections.Generic.List[object]
$SingBoxProcess       = $null
$TempConfigPath       = ""

# ── Cleanup Routine ───────────────────────────────────────────────────────────
function Invoke-Cleanup {
    Write-Host ""
    Write-Info "Stopping cluster... Restoring network..."

    # 1. Terminate sing-box (instantly tears down TUN adapter & Windows routes)
    if ($SingBoxProcess -ne $null -and -not $SingBoxProcess.HasExited) {
        try {
            $SingBoxProcess.Kill()
            $SingBoxProcess.WaitForExit(3000)
            Write-Ok "sing-box stopped (TUN adapter removed)."
        } catch {}
    }
    Get-Process -Name "sing-box" -ErrorAction SilentlyContinue |
        ForEach-Object { try { $_.Kill() } catch {} }

    # 2. Remove all bypass routes added for cluster servers
    if ($CreatedRoutes.Count -gt 0) {
        Write-Info "Removing $($CreatedRoutes.Count) cluster bypass route(s)..."
        foreach ($r in $CreatedRoutes) {
            try {
                Remove-NetRoute -DestinationPrefix $r.Prefix -NextHop $r.Gateway `
                                -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Ok "  Bypass routes cleared."
    }

    # 3. Remove firewall rules
    if ($CreatedFirewallRules.Count -gt 0) {
        Write-Info "Removing firewall rule(s)..."
        foreach ($rule in $CreatedFirewallRules) {
            try {
                Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Ok "  Firewall rules cleared."
    }

    # 4. Remove temp config file
    if ($TempConfigPath -ne "" -and (Test-Path $TempConfigPath)) {
        Remove-Item $TempConfigPath -Force -ErrorAction SilentlyContinue
    }

    Write-Ok "Network completely restored. Customer VPN is intact."
}

$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Invoke-Cleanup }

# ── Locate sing-box Binary ────────────────────────────────────────────────────
function Find-SingBox {
    $candidates = @(
        $SingBoxPath,
        "$PSScriptRoot\sing-box.exe",
        "$PSScriptRoot\sing-box\sing-box.exe",
        "C:\Program Files\sing-box\sing-box.exe",
        "$env:LOCALAPPDATA\sing-box\sing-box.exe",
        "C:\tools\sing-box.exe"
    )
    foreach ($p in $candidates) {
        if ($p -ne "" -and (Test-Path $p)) { return $p }
    }
    $found = Get-Command "sing-box" -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    return $null
}

# ── Detect Physical Wi-Fi/Ethernet Gateway (Bypasses Customer VPN) ─────────────
function Get-PhysicalGateway {
    $skipWords = @("vmware","virtual","tap","loopback","tunnel","pangp","anyconnect","fortinet","cisco","outline")
    $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
              Sort-Object RouteMetric
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
    $best = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1
    if ($best -and $best.NextHop -ne "0.0.0.0") {
        $adapter = Get-NetAdapter -InterfaceIndex $best.InterfaceIndex -ErrorAction SilentlyContinue
        return @{ Gateway = $best.NextHop; IfIndex = $best.InterfaceIndex; Name = $adapter.Name }
    }
    return $null
}

# ── Route & Firewall Helpers ──────────────────────────────────────────────────
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
    param($Name, $Direction, $Protocol, $RemoteAddress)
    try {
        $p = @{ DisplayName = $Name; Direction = $Direction; Action = "Allow"; Enabled = "True"; Profile = "Any" }
        if ($Protocol)      { $p.Protocol      = $Protocol }
        if ($RemoteAddress) { $p.RemoteAddress  = $RemoteAddress }
        New-NetFirewallRule @p -ErrorAction Stop | Out-Null
        $CreatedFirewallRules.Add($Name)
    } catch {}
}

# ── IP Geolocation & Caching Helper ───────────────────────────────────────────
$GeoCacheFile = Join-Path $PSScriptRoot "_geo_cache.json"
$script:GeoCache = @{}

if (Test-Path $GeoCacheFile) {
    try {
        $loaded = Get-Content $GeoCacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($prop in $loaded.PSObject.Properties) {
            $script:GeoCache[$prop.Name] = $prop.Value
        }
    } catch {}
}

function Get-ServerGeoLocation {
    param([string]$ip)
    if ($script:GeoCache.ContainsKey($ip)) {
        return $script:GeoCache[$ip]
    }
    try {
        $info = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json?token=$IpInfoToken" -UseBasicParsing -TimeoutSec 5
        if ($info -and $info.country) {
            $entry = [pscustomobject]@{
                country = $info.country.ToString().Trim().ToUpper()
                city    = if ($info.city) { $info.city.ToString() } else { "" }
            }
            $script:GeoCache[$ip] = $entry
            return $entry
        }
    } catch {
        # Fallback to ipwho.is if token/api hits limit
        try {
            $fb = Invoke-RestMethod -Uri "https://ipwho.is/$ip" -UseBasicParsing -TimeoutSec 5
            if ($fb -and $fb.country_code) {
                $entry = [pscustomobject]@{
                    country = $fb.country_code.ToString().Trim().ToUpper()
                    city    = if ($fb.city) { $fb.city.ToString() } else { "" }
                }
                $script:GeoCache[$ip] = $entry
                return $entry
            }
        } catch {}
    }
    return $null
}

function Save-GeoCache {
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $json = $script:GeoCache | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($GeoCacheFile, $json, $utf8NoBom)
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
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
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

# ══════════════════════════════════════════════════════════════════════════════
#  CLUSTER DISCOVERY & GEOLOCATION FILTER ENGINE
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   ⚡ MULTI-CONFIG VPN CLUSTER & AUTO LOAD-BALANCER" -ForegroundColor Cyan
Write-Host "   Antigravity Geo-Filter * Auto Lowest-Ping * Tor-Style Multipath" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Locate sing-box binary
$singBoxExe = Find-SingBox
if (-not $singBoxExe) {
    Write-Err "sing-box.exe not found! Please place sing-box.exe in project folder."
    exit 1
}
Write-Ok "sing-box engine: $singBoxExe"

# 2. Find and inspect all JSON config files in the target directory
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
foreach ($jf in $jsonFiles) {
    Write-Host "   • $($jf.Name)" -ForegroundColor Gray
}

# 3. Harvest and deduplicate all proxy nodes from all files
$rawClusterNodes  = [System.Collections.Generic.List[object]]::new()
$seenTags         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$seenEndpoints    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$uniqueServers    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

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

            $endpointKey = "$($ob.type)://$($ob.server):$($ob.server_port)|$sni|$hostHdr|$path|$uuid".ToLowerInvariant()
            if ($seenEndpoints.Contains($endpointKey)) { continue }
            $null = $seenEndpoints.Add($endpointKey)

            $tag = $ob.tag
            if (-not $tag -or $seenTags.Contains($tag)) {
                $tag = "[$($jf.BaseName)] $($ob.type.ToUpper())-$($ob.server_port)"
                $ob.tag = $tag
            }
            $null = $seenTags.Add($tag)

            $rawClusterNodes.Add($ob)
            $null = $uniqueServers.Add($ob.server.ToString().Trim())
        }
    } catch {
        Write-Warn "  Could not parse $($jf.Name): $_"
    }
}

if ($rawClusterNodes.Count -eq 0) {
    Write-Err "No valid proxy nodes could be extracted from your config files!"
    exit 1
}

Write-Host ""
Write-Info "Harvested $($rawClusterNodes.Count) total nodes across $($uniqueServers.Count) unique server endpoint(s)."
Write-Info "Checking IP geolocations against Antigravity blocked list..."
Write-Host "   Blocked regions: $($BlockedCountries -join ', ')" -ForegroundColor DarkGray
Write-Host ""

# 4. Resolve endpoints, check IP location, and apply Blocklist Filter (High-Speed Multi-Threaded Engine)
$serverStatusMap  = @{}  # Server -> Allowed (true/false)
$hostsMap         = [pscustomobject]@{}
$allowedServerIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

Write-Info "Resolving DNS for $($uniqueServers.Count) server endpoint(s) in parallel..."
$dnsTasks = @{}
$resolvedServerIPs = @{}  # Server string -> Primary IPv4 string

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
    } catch {
        # Unresolvable domains or timeouts handled below
    }

    foreach ($kv in $dnsTasks.GetEnumerator()) {
        $srv = $kv.Key
        $task = $kv.Value
        if ($task.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and $task.Result) {
            $ipv4List = @($task.Result | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
            if ($ipv4List.Count -gt 0) {
                $primary = $ipv4List[0].ToString()
                $resolvedServerIPs[$srv] = $primary
                $ipStrings = @($ipv4List | ForEach-Object { $_.ToString() })
                $hostsMap | Add-Member -MemberType NoteProperty -Name $srv -Value $ipStrings -Force
            }
        }
    }
}

# Collect all unique IPv4 targets for parallel geo lookup
$targetIPs = @($resolvedServerIPs.Values | Select-Object -Unique)
Write-Info "Querying geolocations for $($targetIPs.Count) IP(s) in parallel (batch & cache)..."
$geoResults = Resolve-GeoLocationsParallel -IPs $targetIPs -Token $IpInfoToken
Save-GeoCache

# Apply filter and display status
$approvedCount = 0
$blockedCount  = 0

foreach ($srv in $uniqueServers) {
    if (-not $resolvedServerIPs.ContainsKey($srv)) {
        Write-Host "  [-] UNRESOLVED: $srv -> Excluded (DNS resolution failed)" -ForegroundColor DarkGray
        $serverStatusMap[$srv] = $false
        continue
    }

    $targetIp = $resolvedServerIPs[$srv]
    $geo = if ($geoResults.ContainsKey($targetIp)) { $geoResults[$targetIp] } else { $null }
    $countryCode = if ($geo -and $geo.country) { $geo.country } else { "UNKNOWN" }
    $city = if ($geo -and $geo.city) { " ($($geo.city))" } else { "" }

    if ($BlockedCountries -contains $countryCode) {
        Write-Host "  [-] BLOCKED: $srv [$countryCode]$city -> Excluded (Antigravity unsupported)" -ForegroundColor Red
        $serverStatusMap[$srv] = $false
        $blockedCount++
    } else {
        Write-Host "  [+] ALLOWED: $srv [$countryCode]$city -> Approved" -ForegroundColor Green
        $serverStatusMap[$srv] = $true
        $null = $allowedServerIPs.Add($targetIp)
        $approvedCount++
    }
}

# 5. Filter nodes: Keep only nodes whose server passed the country blocklist
$approvedNodes = [System.Collections.Generic.List[object]]::new()
foreach ($node in $rawClusterNodes) {
    $srv = $node.server.ToString().Trim()
    if ($serverStatusMap.ContainsKey($srv) -and $serverStatusMap[$srv] -eq $true) {
        $approvedNodes.Add($node)
    }
}

$droppedCount = $rawClusterNodes.Count - $approvedNodes.Count
Write-Host ""
Write-Ok "Cluster Pool: $($approvedNodes.Count) nodes passed security & region filter ($droppedCount dropped)."
$protoSummary = ($approvedNodes | Group-Object type | ForEach-Object { "$($_.Name.ToUpper()): $($_.Count)" }) -join " | "
Write-Host "   Approved Protocols: $protoSummary" -ForegroundColor Yellow
Write-Host ""

if ($approvedNodes.Count -eq 0) {
    Write-Err "All nodes were filtered out! Check your config files or blocked countries list."
    exit 1
}

# 6. Detect Physical Gateway (Wi-Fi/Ethernet) to bypass Customer VPN
Write-Info "Detecting physical gateway (bypasses FortiClient / AnyConnect)..."
$gw = Get-PhysicalGateway
if (-not $gw) {
    Write-Err "Could not identify physical gateway. Check your internet connection."
    exit 1
}
Write-Ok "Physical Gateway: $($gw.Gateway) on $($gw.Name) (idx=$($gw.IfIndex))"

# 7. Add static host routes for all approved cluster server IPs
Write-Info "Adding bypass routes for all approved cluster nodes..."
foreach ($ip in $allowedServerIPs) {
    Add-TrackedRoute -Prefix "$ip/32" -Gateway $gw.Gateway -IfIndex $gw.IfIndex
}
Write-Ok "All approved cluster traffic routed directly to physical Wi-Fi (Customer VPN safe)."

# 8. Add firewall rules
Add-TrackedFwRule -Name "MultipVPN-Cluster-Out" -Direction Outbound -Protocol TCP
Add-TrackedFwRule -Name "MultipVPN-Cluster-UDP" -Direction Outbound -Protocol UDP

# 9. Build Tor-style Multi-Tier Cluster Outbounds (Approved Nodes Only)
$allNodeTags   = @($approvedNodes | ForEach-Object { $_.tag })
$hyTags        = @($approvedNodes | Where-Object { $_.type -eq "hysteria2" } | ForEach-Object { $_.tag })
$vlessTags     = @($approvedNodes | Where-Object { $_.type -eq "vless" } | ForEach-Object { $_.tag })
$vmessTrojan   = @($approvedNodes | Where-Object { $_.type -in @("vmess", "trojan", "shadowsocks") } | ForEach-Object { $_.tag })

$clusterGroups = [System.Collections.Generic.List[object]]::new()

# Group 1: Master Selector (Defaults to Lowest-Ping Cluster)
$mainSelectorList = [System.Collections.Generic.List[string]]::new()
$mainSelectorList.Add("⚡ Cluster - Auto Lowest Ping")
if ($hyTags.Count -gt 0)      { $mainSelectorList.Add("🚀 Hysteria2 Turbo Pool") }
if ($vlessTags.Count -gt 0)   { $mainSelectorList.Add("🛡️ VLESS Reality Stealth Pool") }
if ($vmessTrojan.Count -gt 0) { $mainSelectorList.Add("🌐 Standard Proxy Pool") }
$mainSelectorList.Add("⚙️ Manual Node Select")

$clusterGroups.Add([pscustomobject]@{
    type                        = "selector"
    tag                         = "proxy"
    outbounds                   = @($mainSelectorList)
    interrupt_exist_connections = $false
})

# Group 2: Global Auto Lowest Ping (Tests all approved nodes continuously)
$clusterGroups.Add([pscustomobject]@{
    type                        = "urltest"
    tag                         = "⚡ Cluster - Auto Lowest Ping"
    outbounds                   = @($allNodeTags)
    url                         = "https://www.gstatic.com/generate_204"
    interval                    = "1m"
    tolerance                   = 25
    interrupt_exist_connections = $false
})

# Group 3: Hysteria2 Turbo Pool (UDP high throughput & lowest gaming latency)
if ($hyTags.Count -gt 0) {
    $clusterGroups.Add([pscustomobject]@{
        type                        = "urltest"
        tag                         = "🚀 Hysteria2 Turbo Pool"
        outbounds                   = @($hyTags)
        url                         = "https://www.gstatic.com/generate_204"
        interval                    = "1m"
        tolerance                   = 25
        interrupt_exist_connections = $false
    })
}

# Group 4: VLESS Reality Stealth Pool (Anti-blocking Reality nodes)
if ($vlessTags.Count -gt 0) {
    $clusterGroups.Add([pscustomobject]@{
        type                        = "urltest"
        tag                         = "🛡️ VLESS Reality Stealth Pool"
        outbounds                   = @($vlessTags)
        url                         = "https://www.gstatic.com/generate_204"
        interval                    = "1m"
        tolerance                   = 25
        interrupt_exist_connections = $false
    })
}

# Group 5: Standard Proxy Pool (VMess / Trojan / Shadowsocks)
if ($vmessTrojan.Count -gt 0) {
    $clusterGroups.Add([pscustomobject]@{
        type                        = "urltest"
        tag                         = "🌐 Standard Proxy Pool"
        outbounds                   = @($vmessTrojan)
        url                         = "https://www.gstatic.com/generate_204"
        interval                    = "1m"
        tolerance                   = 25
        interrupt_exist_connections = $false
    })
}

# Group 6: Manual Node Select (fallback)
$clusterGroups.Add([pscustomobject]@{
    type      = "selector"
    tag       = "⚙️ Manual Node Select"
    outbounds = @($allNodeTags)
})

# Group 7: Direct & Block
$clusterGroups.Add([pscustomobject]@{ type = "direct"; tag = "direct" })
$clusterGroups.Add([pscustomobject]@{ type = "block";  tag = "block" })

# Assemble full outbounds array
$fullOutbounds = [System.Collections.Generic.List[object]]::new()
foreach ($grp in $clusterGroups)   { $fullOutbounds.Add($grp) }
foreach ($node in $approvedNodes)  { $fullOutbounds.Add($node) }

# 10. Split-Tunnel List: Exclude Customer Subnets + Approved Server IPs
$excludeList = [System.Collections.Generic.List[string]]::new()
foreach ($sub in $CustomerSubnets) { $excludeList.Add($sub) }
foreach ($ip in $allowedServerIPs) {
    $cidr = "$ip/32"
    if (-not $excludeList.Contains($cidr)) { $excludeList.Add($cidr) }
}

# 11. DNS Configuration with Hosts Predefined for 0ms testing
$hasHosts = ($hostsMap.PSObject.Properties | Measure-Object).Count -gt 0
$dnsServers = [System.Collections.Generic.List[object]]::new()
if ($hasHosts) {
    $dnsServers.Add([pscustomobject]@{
        tag        = "dns-hosts"
        type       = "hosts"
        predefined = $hostsMap
    })
}
$dnsServers.Add([pscustomobject]@{
    tag    = "dns-remote"
    type   = "udp"
    server = "8.8.8.8"
    detour = "proxy"
})
$dnsServers.Add([pscustomobject]@{
    tag  = "dns-local"
    type = "local"
})

$dnsRules = @()
if ($hasHosts) {
    $hostDomains = @($hostsMap.PSObject.Properties | ForEach-Object { $_.Name })
    $dnsRules = @([pscustomobject]@{ domain = $hostDomains; server = "dns-hosts" })
}

# 12. Transparent TUN Inbound
$tunInbound = [pscustomobject]@{
    type                  = "tun"
    tag                   = "tun-in"
    address               = @("172.19.0.1/30")
    auto_route            = $true
    strict_route          = $false
    stack                 = "mixed"
    route_exclude_address = @($excludeList)
}

# 13. Routing Rules
$routeBlock = [pscustomobject]@{
    default_domain_resolver = if ($hasHosts) { "dns-hosts" } else { "dns-local" }
    rules = @(
        [pscustomobject]@{ action = "sniff" },
        [pscustomobject]@{ protocol = "dns"; action = "hijack-dns" },
        [pscustomobject]@{
            ip_cidr  = @($excludeList)
            outbound = "direct"
        }
    )
    auto_detect_interface = $true
    final                 = "proxy"
}

$finalClusterConfig = [pscustomobject]@{
    log = [pscustomobject]@{ level = "warn"; timestamp = $true }
    dns = [pscustomobject]@{
        servers = @($dnsServers)
        rules   = $dnsRules
        final   = "dns-remote"
    }
    inbounds  = @($tunInbound)
    outbounds = @($fullOutbounds)
    route     = $routeBlock
}

$TempConfigPath = Join-Path $PSScriptRoot "_singbox_cluster_run.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$json = $finalClusterConfig | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($TempConfigPath, $json, $utf8NoBom)
Write-Ok "Cluster configuration synthesized ($($fullOutbounds.Count) total targets)."

# 14. Launch sing-box Cluster Engine
Write-Host ""
Write-Info "Starting sing-box Cluster Engine..."

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = $singBoxExe
$psi.Arguments              = "run -c `"$TempConfigPath`""
$psi.UseShellExecute        = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.CreateNoWindow         = $false

$SingBoxProcess = New-Object System.Diagnostics.Process
$SingBoxProcess.StartInfo = $psi
$SingBoxProcess.EnableRaisingEvents = $true

Register-ObjectEvent $SingBoxProcess OutputDataReceived -Action {
    if ($Event.SourceEventArgs.Data) { Write-Host "[cluster] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkGray }
} | Out-Null
Register-ObjectEvent $SingBoxProcess ErrorDataReceived -Action {
    if ($Event.SourceEventArgs.Data) { Write-Host "[cluster] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkYellow }
} | Out-Null

$SingBoxProcess.Start() | Out-Null
$SingBoxProcess.BeginOutputReadLine()
$SingBoxProcess.BeginErrorReadLine()

Start-Sleep -Seconds 2

if ($SingBoxProcess.HasExited) {
    Write-Err "sing-box cluster failed to start (exit code: $($SingBoxProcess.ExitCode))"
    Invoke-Cleanup
    exit 1
}

Write-Ok "sing-box Cluster is ACTIVE (PID: $($SingBoxProcess.Id))"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  CONNECTED! CLUSTER LOAD-BALANCER ACTIVE (GEO-FILTERED)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  * Approved Nodes      : $($approvedNodes.Count) active nodes in pool ($droppedCount blocked)" -ForegroundColor White
Write-Host "  * Active Mode         : ⚡ Auto Lowest-Ping (Health-checks every 1 min)" -ForegroundColor White
Write-Host "  * Auto-Failover       : Active (instant switch if a node dies or lags)" -ForegroundColor White
Write-Host "  * Antigravity Safe    : Blocked regions ($($BlockedCountries -join ', ')) filtered out" -ForegroundColor White
Write-Host "  * Customer VPN        : Split-tunnel intact ($($CustomerSubnets -join ', '))" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press Ctrl+C to disconnect and restore all routes." -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

# 15. Keep alive loop
try {
    while (-not $SingBoxProcess.HasExited) {
        Start-Sleep -Milliseconds 500
    }
    Write-Warn "sing-box cluster stopped (exit code: $($SingBoxProcess.ExitCode))"
} finally {
    Invoke-Cleanup
}
