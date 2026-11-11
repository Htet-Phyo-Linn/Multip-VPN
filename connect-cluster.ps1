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
    [string[]]$CorpDomains    = @(),
    [string]$IpInfoToken      = "a1e1161ecc1b38",
    [string[]]$BlockedCountries = @("HK", "CN", "RU", "IR", "KP", "SY", "CU", "BY", "MM", "VE"),
    [switch]$ProxyOnly,
    [switch]$SystemProxy,
    [int]$MixedPort           = 10808
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ── Color Output Helpers ──────────────────────────────────────────────────────
function Write-Info    { param($m) Write-Host "[*] $m" -ForegroundColor Cyan    }
function Write-Ok      { param($m) Write-Host "[+] $m" -ForegroundColor Green   }
function Write-Warn    { param($m) Write-Host "[!] $m" -ForegroundColor Yellow  }
function Write-Err     { param($m) Write-Host "[-] $m" -ForegroundColor Red     }

# ── Auto-Elevation to Administrator (Required for TUN Mode) ───────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal](
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $ProxyOnly -and -not $isAdmin) {
    Write-Warn "Cluster TUN mode requires Administrator privileges."
    Write-Info "Re-launching elevated (UAC prompt)..."
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($ConfigFolder)               { $argList += " -ConfigFolder `"$ConfigFolder`"" }
    if ($SingBoxPath)                { $argList += " -SingBoxPath `"$SingBoxPath`"" }
    if ($CustomerSubnets.Count -gt 0){ $argList += " -CustomerSubnets @(" + (($CustomerSubnets | ForEach-Object { "'$_'" }) -join ",") + ")" }
    if ($CorpDomains.Count -gt 0)    { $argList += " -CorpDomains @(" + (($CorpDomains | ForEach-Object { "'$_'" }) -join ",") + ")" }
    if ($SystemProxy)                { $argList += " -SystemProxy" }
    $argList += " -MixedPort $MixedPort"
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit 0
}

# ── State Tracking for Clean Exit ─────────────────────────────────────────────
$CreatedFirewallRules = New-Object System.Collections.Generic.List[string]
$CreatedRoutes        = New-Object System.Collections.Generic.List[string]
$RouteTrackFile       = Join-Path $PSScriptRoot "_cluster_routes.txt"
$TempConfigPath       = Join-Path $PSScriptRoot "_singbox_cluster_run.json"
$SingBoxProcess       = $null
$AppliedSystemProxy   = $false
$PrevProxyState       = $null
$CleanupExecuted      = $false

# ── Native route.exe Wrapper (Prevents ErrorActionPreference=Stop crashes) ─────
function Invoke-RouteNative {
    param([string[]]$RouteArgs)
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        & route.exe @RouteArgs *>$null
    } finally {
        $ErrorActionPreference = $oldEap
    }
}

# ── Fast Route Cleanup (Preserves Customer VPN Gateway Routes) ────────────────
function Clear-TrackedRoutesFast {
    param([string[]]$ExcludeCidrs = @())
    $ipsToDelete = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($ip in $CreatedRoutes) {
        if ($ip) { $null = $ipsToDelete.Add($ip) }
    }
    if (Test-Path $RouteTrackFile) {
        try {
            foreach ($line in (Get-Content $RouteTrackFile -ErrorAction SilentlyContinue)) {
                $clean = $line.Trim()
                if ($clean) { $null = $ipsToDelete.Add($clean) }
            }
        } catch {}
    }

    if ($ipsToDelete.Count -gt 0) {
        $excludeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($ex in $ExcludeCidrs) {
            if ($ex -match '^(.+?)/32$') { $null = $excludeSet.Add($matches[1]) }
        }
        $activeHostIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($rt in (Get-NetRoute -DestinationPrefix "*/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
            $null = $activeHostIPs.Add(($rt.DestinationPrefix -replace '/32$',''))
        }
        foreach ($ip in $ipsToDelete) {
            if (-not $excludeSet.Contains($ip) -and $activeHostIPs.Contains($ip)) {
                Invoke-RouteNative @("delete", $ip)
            }
        }
    }

    $CreatedRoutes.Clear()
    if (Test-Path $RouteTrackFile) {
        Remove-Item $RouteTrackFile -Force -ErrorAction SilentlyContinue
    }
}

# ── WinINet Notification Helper (Only used if -SystemProxy is active) ─────────
function Set-WindowsSystemProxyState {
    param([bool]$Enable, [string]$Server = "", [string]$Bypass = "")
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try {
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value ($(if ($Enable) { 1 } else { 0 })) -ErrorAction SilentlyContinue
        if ($Enable) {
            Set-ItemProperty -Path $regPath -Name ProxyServer -Value $Server -ErrorAction SilentlyContinue
            if ($Bypass) { Set-ItemProperty -Path $regPath -Name ProxyOverride -Value $Bypass -ErrorAction SilentlyContinue }
        }
        if (-not ("WinInetNative" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WinInetNative {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
"@ -ErrorAction SilentlyContinue
        }
        if ("WinInetNative" -as [type]) {
            [WinInetNative]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
            [WinInetNative]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
        }
    } catch {}
}

# ── Cleanup Routine ───────────────────────────────────────────────────────────
function Invoke-Cleanup {
    if ($script:CleanupExecuted) { return }
    $script:CleanupExecuted = $true

    Write-Host ""
    Write-Info "Stopping cluster... Restoring network..."

    # 1. Terminate sing-box (instantly tears down TUN adapter & Windows routes)
    if ($script:SingBoxProcess -ne $null -and -not $script:SingBoxProcess.HasExited) {
        try {
            $script:SingBoxProcess.Kill()
            $script:SingBoxProcess.WaitForExit(3000) | Out-Null
            Write-Ok "sing-box stopped (TUN adapter removed)."
        } catch {}
    }
    Get-Process -Name "sing-box" -ErrorAction SilentlyContinue |
        ForEach-Object { try { $_.Kill() } catch {} }

    # 2. Fast-scrub only our tracked cluster /32 routes (Customer VPN gateway routes untouched)
    $countBefore = $CreatedRoutes.Count
    Clear-TrackedRoutesFast
    if ($countBefore -gt 0) {
        Write-Ok "  Cleared $countBefore cluster bypass route(s)."
    }

    # 3. Remove all MultipVPN firewall rules in bulk
    if ($isAdmin) {
        try {
            Remove-NetFirewallRule -DisplayName "MultipVPN*" -ErrorAction SilentlyContinue
            Write-Ok "  Firewall rules cleared."
        } catch {}
    }

    # 4. Remove temp config file
    if ($TempConfigPath -ne "" -and (Test-Path $TempConfigPath)) {
        Remove-Item $TempConfigPath -Force -ErrorAction SilentlyContinue
    }

    # 5. Restore System Proxy only if this session modified it
    if ($script:AppliedSystemProxy) {
        if ($script:PrevProxyState -and $script:PrevProxyState.Enable -eq 1) {
            Set-WindowsSystemProxyState -Enable $true -Server $script:PrevProxyState.Server -Bypass $script:PrevProxyState.Override
        } else {
            Set-WindowsSystemProxyState -Enable $false
        }
        Write-Ok "  System proxy restored."
    }

    # 6. Flush DNS cache
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}

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

# ── Detect Physical Wi-Fi/Ethernet Gateway & DNS (Bypasses Customer VPN) ──────
function Get-PhysicalGateway {
    $skipWords = @("vmware","virtual","tap","loopback","tunnel","pangp","anyconnect","fortinet","cisco","outline","sing-tun","wintun","wireguard","nordlynx","tailscale","multip")
    $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
              Sort-Object RouteMetric
    foreach ($r in $routes) {
        if ($r.NextHop -eq "0.0.0.0") { continue }
        $adapter = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter -or $adapter.Status -ne "Up") { continue }
        $desc = "$($adapter.InterfaceDescription) $($adapter.Name)".ToLower()
        $skip = $false
        foreach ($w in $skipWords) { if ($desc -like "*$w*") { $skip = $true; break } }
        if (-not $skip) {
            $dnsList = @((Get-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
                         Where-Object { $_ -and $_ -ne "0.0.0.0" -and $_ -notlike "127.*" -and $_ -notlike "169.254.*" -and $_ -notlike "172.19.0.*" })
            return @{ Gateway = $r.NextHop; IfIndex = $r.InterfaceIndex; Name = $adapter.Name; DnsServers = $dnsList }
        }
    }
    $best = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1
    if ($best -and $best.NextHop -ne "0.0.0.0") {
        $adapter = Get-NetAdapter -InterfaceIndex $best.InterfaceIndex -ErrorAction SilentlyContinue
        $dnsList = @((Get-DnsClientServerAddress -InterfaceIndex $best.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
                     Where-Object { $_ -and $_ -ne "0.0.0.0" -and $_ -notlike "127.*" -and $_ -notlike "169.254.*" -and $_ -notlike "172.19.0.*" })
        return @{ Gateway = $best.NextHop; IfIndex = $best.InterfaceIndex; Name = $adapter.Name; DnsServers = $dnsList }
    }
    return $null
}

# ── Helper: Check if IPv4 CIDR is already covered by RFC1918 summary blocks ───
function Test-IsRfc1918Cidr {
    param([string]$Cidr)
    if ($Cidr -match '^10\.') { return $true }
    if ($Cidr -match '^192\.168\.') { return $true }
    if ($Cidr -match '^172\.(\d+)\.') {
        $oct2 = [int]$matches[1]
        if ($oct2 -ge 16 -and $oct2 -le 31) { return $true }
    }
    return $false
}

# ── Dynamic Discovery of Configured VPN Gateways (FortiClient / GlobalProtect) ─
$script:ConfiguredVpnGwCache = $null
function Get-ConfiguredVpnGateways {
    if ($null -ne $script:ConfiguredVpnGwCache) { return $script:ConfiguredVpnGwCache }

    $rawHosts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # FortiClient IPSec Tunnels (Registry stores only non-secret gateway host/IP under RemoteGw)
    try {
        Get-ChildItem "HKLM:\SOFTWARE\Fortinet\FortiClient\IPSec\Tunnels\*" -ErrorAction SilentlyContinue | ForEach-Object {
            $pRoot = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $p1    = Get-ItemProperty (Join-Path $_.PSPath "P1") -ErrorAction SilentlyContinue
            foreach ($cand in @($pRoot.RemoteGw, $p1.RemoteGw, $pRoot.Server)) {
                if ($cand) {
                    $h = ($cand.ToString().Trim() -split ':')[0]
                    if ($h -and $h -ne "0.0.0.0") { $null = $rawHosts.Add($h) }
                }
            }
        }
    } catch {}

    # FortiClient SSLVPN Tunnels (HKLM & HKCU)
    foreach ($regBase in @("HKLM:\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\*", "HKCU:\Software\Fortinet\FortiClient\Sslvpn\Tunnels\*")) {
        try {
            Get-ChildItem $regBase -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($p.Server) {
                    $h = ($p.Server.ToString().Trim() -split ':')[0]
                    if ($h -and $h -ne "0.0.0.0") { $null = $rawHosts.Add($h) }
                }
            }
        } catch {}
    }

    # Palo Alto GlobalProtect Portals (HKLM & HKCU)
    foreach ($gpBase in @("HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings\*", "HKCU:\Software\Palo Alto Networks\GlobalProtect\Settings\*")) {
        try {
            Get-ChildItem $gpBase -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                foreach ($cand in @($p.Portal, $p.LastPortal)) {
                    if ($cand) {
                        $h = ($cand.ToString().Trim() -split ':')[0]
                        if ($h -and $h -ne "0.0.0.0") { $null = $rawHosts.Add($h) }
                    }
                }
            }
        } catch {}
    }

    $cidrs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $dnsTasks = @{}
    foreach ($h in $rawHosts) {
        $ipObj = $null
        if ([System.Net.IPAddress]::TryParse($h, [ref]$ipObj)) {
            if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $h -notlike "127.*" -and $h -ne "0.0.0.0") {
                $null = $cidrs.Add("$($ipObj.ToString())/32")
            }
        } else {
            try { $dnsTasks[$h] = [System.Net.Dns]::GetHostAddressesAsync($h) } catch {}
        }
    }
    if ($dnsTasks.Count -gt 0) {
        try { [System.Threading.Tasks.Task]::WaitAll(@($dnsTasks.Values), 2000) | Out-Null } catch {}
        foreach ($kv in $dnsTasks.GetEnumerator()) {
            if ($kv.Value.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and $kv.Value.Result) {
                foreach ($addr in $kv.Value.Result) {
                    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $addr.ToString() -notlike "127.*") {
                        $null = $cidrs.Add("$($addr.ToString())/32")
                    }
                }
            }
        }
    }

    $script:ConfiguredVpnGwCache = @($cidrs | Sort-Object)
    return $script:ConfiguredVpnGwCache
}

# ── Dynamic Customer VPN State Inspector (FortiClient / AnyConnect / PANGP) ───
function Get-EnterpriseVpnState {
    param(
        $PhysicalGw,
        [System.Collections.Generic.HashSet[string]]$ProxyServerIPs
    )

    $vpnAdapters    = [System.Collections.Generic.List[string]]::new()
    $adapterSubnets = @{}
    $subnets        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $gwCidrs        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $dnsServers     = [System.Collections.Generic.List[string]]::new()
    $dnsBindings    = [System.Collections.Generic.List[object]]::new()
    $suffixes       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $hasFullTunnel  = $false

    # Always include configured VPN tunnel server /32s so kernel IPsec ESP/UDP-4500 & SSLVPN never enter tun0
    foreach ($cfgGw in (Get-ConfiguredVpnGateways)) {
        $null = $gwCidrs.Add($cfgGw)
    }

    $matchPattern = 'fortinet|fortissl|cisco|anyconnect|pangp|globalprotect|pulse|juniper|sonicwall|check point|checkpoint'
    $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq "Up" -and (
            $_.InterfaceDescription -match $matchPattern -or $_.Name -match $matchPattern
        )
    }

    foreach ($ad in $allAdapters) {
        $ifIdx = $ad.InterfaceIndex
        $ipIf = Get-NetIPInterface -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipIf -and $ipIf.ConnectionState -ne "Connected") { continue }

        $vpnAdapters.Add($ad.Name)
        $perAdRoutes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        # Collect active routes pushed onto this VPN adapter (both private & customer public blocks)
        $ifRoutes = Get-NetRoute -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($rt in $ifRoutes) {
            $pfx = $rt.DestinationPrefix
            if ($pfx -eq "0.0.0.0/0") {
                $hasFullTunnel = $true
                continue
            }
            if ($pfx -like "169.254.*" -or $pfx -like "224.*" -or $pfx -eq "255.255.255.255/32" -or $pfx -like "127.*") { continue }
            # Skip local link-broadcast or interface host self-/32 (RouteMetric 256 & NextHop 0.0.0.0)
            if ($pfx -like "*/32" -and $rt.NextHop -eq "0.0.0.0" -and $rt.RouteMetric -eq 256) { continue }
            $null = $subnets.Add($pfx)
            $null = $perAdRoutes.Add($pfx)
        }
        $adapterSubnets[$ad.Name] = @($perAdRoutes | Sort-Object)

        # Collect valid internal corporate DNS servers assigned by customer VPN (paired with owning adapter)
        $adDns = (Get-DnsClientServerAddress -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        foreach ($d in $adDns) {
            if ($d -and $d -ne "0.0.0.0" -and $d -notlike "127.*" -and $d -notlike "169.254.*" -and $d -notlike "172.19.0.*") {
                if (-not $dnsServers.Contains($d)) {
                    $dnsServers.Add($d)
                    $dnsBindings.Add([pscustomobject]@{ Ip = $d; Adapter = $ad.Name })
                }
            }
        }

        # Collect connection-specific DNS suffixes
        $dnsClient = Get-DnsClient -InterfaceIndex $ifIdx -ErrorAction SilentlyContinue
        if ($dnsClient) {
            if ($dnsClient.ConnectionSpecificSuffix) {
                $s = $dnsClient.ConnectionSpecificSuffix.Trim().TrimStart('.')
                if ($s) { $null = $suffixes.Add(".$s") }
            }
            foreach ($sItem in $dnsClient.ConnectionSpecificSuffixSearchList) {
                $s = $sItem.Trim().TrimStart('.')
                if ($s) { $null = $suffixes.Add(".$s") }
            }
        }
    }

    # Check Windows NRPT split-DNS namespaces and physical /32 gateway routes if a customer VPN is connected
    if ($vpnAdapters.Count -gt 0) {
        try {
            $nrpt = Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue
            foreach ($rule in $nrpt) {
                if ($rule.Namespace) {
                    $ns = $rule.Namespace.Trim()
                    if ($ns -and $ns -ne ".") {
                        if (-not $ns.StartsWith(".")) { $ns = ".$ns" }
                        $null = $suffixes.Add($ns)
                    }
                }
            }
        } catch {}

        if ($PhysicalGw) {
            $physHostRoutes = Get-NetRoute -InterfaceIndex $PhysicalGw.IfIndex -AddressFamily IPv4 -DestinationPrefix "*/32" -ErrorAction SilentlyContinue
            foreach ($pr in $physHostRoutes) {
                if ($pr.NextHop -eq $PhysicalGw.Gateway) {
                    $rawIp = $pr.DestinationPrefix -replace '/32$',''
                    if ($ProxyServerIPs -and $ProxyServerIPs.Contains($rawIp)) { continue }
                    if ($rawIp -ne $PhysicalGw.Gateway -and $rawIp -notlike "127.*" -and $rawIp -notlike "224.*") {
                        $null = $gwCidrs.Add($pr.DestinationPrefix)
                    }
                }
            }
        }
    }

    $sortedAdapters  = @($vpnAdapters | Sort-Object)
    $sortedSubnets   = @($subnets | Sort-Object)
    $publicSubnets   = @($sortedSubnets | Where-Object { -not (Test-IsRfc1918Cidr $_) })
    $sortedGw        = @($gwCidrs | Sort-Object)
    $sortedDns       = @($dnsServers | Sort-Object)
    $sortedSuffixes  = @($suffixes | Sort-Object)

    # Full Signature tracks display/adapter state; ReloadSignature triggers restart only when sing-box rules/DNS actually need updating
    $sig = (@(
        ($sortedAdapters -join ","),
        ($sortedSubnets -join ","),
        ($sortedGw -join ","),
        ($sortedDns -join ","),
        ($sortedSuffixes -join ","),
        $hasFullTunnel
    ) -join "|")

    $reloadSig = (@(
        ($publicSubnets -join ","),
        ($sortedGw -join ","),
        ($sortedDns -join ","),
        ($sortedSuffixes -join ",")
    ) -join "|")

    return [pscustomobject]@{
        Active          = ($vpnAdapters.Count -gt 0)
        PrimaryAdapter  = if ($vpnAdapters.Count -gt 0) { $vpnAdapters[0] } else { "" }
        Adapters        = $sortedAdapters
        AdapterSubnets  = $adapterSubnets
        Subnets         = $sortedSubnets
        PublicSubnets   = $publicSubnets
        GatewayCidrs    = $sortedGw
        DnsServers      = $sortedDns
        DnsBindings     = @($dnsBindings)
        Suffixes        = $sortedSuffixes
        HasFullTunnel   = $hasFullTunnel
        Signature       = $sig
        ReloadSignature = $reloadSig
    }
}

# ── Route & Firewall Helpers ──────────────────────────────────────────────────
function Add-TrackedRoutesBatch {
    param([string[]]$IPs, [string]$Gateway, [int]$IfIndex, [int]$Metric = 5)
    if (-not $IPs -or $IPs.Count -eq 0) { return }

    $existingRoutesByIP = @{}
    foreach ($rt in (Get-NetRoute -DestinationPrefix "*/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        $rawIp = $rt.DestinationPrefix -replace '/32$',''
        if (-not $existingRoutesByIP.ContainsKey($rawIp)) {
            $existingRoutesByIP[$rawIp] = [System.Collections.Generic.List[object]]::new()
        }
        $existingRoutesByIP[$rawIp].Add($rt)
    }

    foreach ($ip in $IPs) {
        if (-not $ip) { continue }
        $alreadyClean = $false
        if ($existingRoutesByIP.ContainsKey($ip)) {
            $rts = $existingRoutesByIP[$ip]
            if ($rts.Count -eq 1 -and $rts[0].NextHop -eq $Gateway -and $rts[0].InterfaceIndex -eq $IfIndex) {
                $alreadyClean = $true
            } else {
                Invoke-RouteNative @("delete", $ip)
            }
        }
        if (-not $alreadyClean) {
            Invoke-RouteNative @("add", $ip, "mask", "255.255.255.255", $Gateway, "metric", "$Metric", "if", "$IfIndex")
        }
        if (-not $CreatedRoutes.Contains($ip)) {
            $CreatedRoutes.Add($ip)
        }
    }

    try {
        [System.IO.File]::WriteAllLines($RouteTrackFile, @($CreatedRoutes), (New-Object System.Text.UTF8Encoding $false))
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

# 1. Locate sing-box binary & clear any orphaned state from interrupted runs
$singBoxExe = Find-SingBox
if (-not $singBoxExe) {
    Write-Err "sing-box.exe not found! Please place sing-box.exe in project folder."
    exit 1
}
Write-Ok "sing-box engine: $singBoxExe"

$staleProcs = Get-Process -Name "sing-box" -ErrorAction SilentlyContinue
if ($staleProcs) {
    Write-Warn "Found leftover sing-box process from an earlier run -- stopping it cleanly..."
    $staleProcs | ForEach-Object { try { $_.Kill(); $_.WaitForExit(2000) | Out-Null } catch {} }
}
Clear-TrackedRoutesFast
if ($isAdmin) {
    Remove-NetFirewallRule -DisplayName "MultipVPN*" -ErrorAction SilentlyContinue
}

# 2. Find and inspect all JSON config files in the target directory
Write-Info "Scanning for VPN configuration files in: $ConfigFolder"
$jsonFiles = Get-ChildItem -Path $ConfigFolder -Filter "*.json" |
             Where-Object { 
                 $_.Name -notlike "_singbox*" -and 
                 $_.Name -notlike "_geo*" -and 
                 $_.Name -notlike "_cluster*" -and 
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

# 5. Filter nodes: Deduplicate strictly by Type + IP + Port combination and keep only country-approved nodes
$approvedNodes        = [System.Collections.Generic.List[object]]::new()
$seenIpPortCombo      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$duplicateServerCount = 0

foreach ($node in $rawClusterNodes) {
    $srv = $node.server.ToString().Trim()
    if (-not ($serverStatusMap.ContainsKey($srv) -and $serverStatusMap[$srv] -eq $true)) {
        continue
    }

    # Resolve target IP and enforce Protocol Type + IP + Port uniqueness
    # (Prevents dropping Hysteria2 UDP vs VLESS TCP on the same port 443)
    $targetIp = if ($resolvedServerIPs.ContainsKey($srv)) { $resolvedServerIPs[$srv] } else { $srv }
    $typeIpPortKey = "$($node.type)://$targetIp`:$($node.server_port)".ToLowerInvariant()

    if ($seenIpPortCombo.Contains($typeIpPortKey)) {
        $duplicateServerCount++
        continue
    }
    $null = $seenIpPortCombo.Add($typeIpPortKey)
    $approvedNodes.Add($node)
}

$droppedCount = $rawClusterNodes.Count - $approvedNodes.Count
Write-Host ""
if ($duplicateServerCount -gt 0) {
    Write-Info "Deduplication: Filtered out $duplicateServerCount duplicate node(s) sharing identical Protocol + IP:Port."
}
Write-Ok "Cluster Pool: $($approvedNodes.Count) nodes passed security, region & Protocol+IP:Port filter ($droppedCount dropped)."
$protoSummary = ($approvedNodes | Group-Object type | ForEach-Object { "$($_.Name.ToUpper()): $($_.Count)" }) -join " | "
Write-Host "   Approved Protocols: $protoSummary" -ForegroundColor Yellow
Write-Host ""

if ($approvedNodes.Count -eq 0) {
    Write-Err "All nodes were filtered out! Check your config files or blocked countries list."
    exit 1
}

# 6. Detect Physical Gateway (Wi-Fi/Ethernet) & Live Customer VPN State
Write-Info "Detecting physical gateway (bypasses FortiClient / AnyConnect)..."
$gw = Get-PhysicalGateway
if (-not $gw) {
    Write-Err "Could not identify physical gateway. Check your internet connection."
    exit 1
}
$wifiDnsText = if ($gw.DnsServers.Count -gt 0) { " | DNS: $($gw.DnsServers -join ', ')" } else { "" }
Write-Ok "Physical Gateway: $($gw.Gateway) on '$($gw.Name)' (idx=$($gw.IfIndex)$wifiDnsText)"

$vpnState = Get-EnterpriseVpnState -PhysicalGw $gw -ProxyServerIPs $allowedServerIPs
if ($vpnState.Active) {
    Write-Ok "Customer VPN Detected: $($vpnState.Adapters -join ', ')"
    if ($vpnState.Subnets.Count -gt 0)      { Write-Host "   • Bypassed VPN Subnets : $($vpnState.Subnets -join ', ')" -ForegroundColor Cyan }
    if ($vpnState.GatewayCidrs.Count -gt 0) { Write-Host "   • Bypassed Gateway IP  : $($vpnState.GatewayCidrs -join ', ')" -ForegroundColor Cyan }
    if ($vpnState.DnsServers.Count -gt 0)   { Write-Host "   • Corporate DNS Server : $($vpnState.DnsServers -join ', ')" -ForegroundColor Cyan }
    if ($vpnState.HasFullTunnel) {
        Write-Warn "FortiClient/Customer VPN is pushing Full-Tunnel (0.0.0.0/0)."
        Write-Warn "If FortiClient enforces strict exclusive routing and drops TUN, run: .\connect-cluster.ps1 -ProxyOnly -SystemProxy"
    }
} else {
    Write-Info "No active Customer VPN detected right now (Live coexistence watcher is armed)."
    if ($vpnState.GatewayCidrs.Count -gt 0) {
        Write-Host "   • Pre-Excluded Gateways: $($vpnState.GatewayCidrs -join ', ') (IPsec/SSLVPN safe)" -ForegroundColor Cyan
    }
}

# 7. Add fast static host routes for approved cluster server IPs (preserves Customer VPN gateway route)
if ($isAdmin -and -not $ProxyOnly) {
    Write-Info "Adding bypass routes for $($allowedServerIPs.Count) cluster node(s) on '$($gw.Name)'..."
    Add-TrackedRoutesBatch -IPs @($allowedServerIPs) -Gateway $gw.Gateway -IfIndex $gw.IfIndex
    Write-Ok "All cluster endpoints bound to '$($gw.Name)' (FortiClient-safe, zero TUN route bloat)."

    # 8. Add scoped firewall rules
    Add-TrackedFwRule -Name "MultipVPN-Cluster-Out" -Direction Outbound -Protocol TCP
    Add-TrackedFwRule -Name "MultipVPN-Cluster-UDP" -Direction Outbound -Protocol UDP
} elseif ($ProxyOnly) {
    Write-Info "Proxy-Only Mode active: No TUN adapter or routing table changes will be made (100% FortiClient isolated)."
}

# ── Helper: Synthesize Sing-Box Cluster JSON ──────────────────────────────────
function New-SingBoxClusterConfig {
    param(
        $PhysicalGw,
        $EnterpriseVpn,
        [System.Collections.Generic.List[object]]$Nodes,
        $HostsTable,
        [string[]]$UserCustomerSubnets,
        [string[]]$ExtraCorpDomains,
        [bool]$UseProxyOnly,
        [int]$LocalMixedPort,
        [string]$OutConfigPath
    )

    $hasHosts = ($HostsTable.PSObject.Properties | Measure-Object).Count -gt 0
    $hasWifiDns = ($PhysicalGw.DnsServers -and $PhysicalGw.DnsServers.Count -gt 0)
    $wifiDnsTag = if ($hasWifiDns) { "dns-wifi" } else { "dns-local" }

    # Bind every proxy node explicitly to Physical Wi-Fi/Ethernet and IPv4-only domain resolution (prevents DNS64 [64:ff9b::] failures)
    $boundNodes = [System.Collections.Generic.List[object]]::new()
    foreach ($n in $Nodes) {
        $clone = $n.PSObject.Copy()
        $clone | Add-Member -MemberType NoteProperty -Name "bind_interface" -Value $PhysicalGw.Name -Force
        $srvName = if ($n.server) { $n.server.ToString().Trim() } else { "" }
        $nodeDnsTag = if ($hasHosts -and $srvName -and $HostsTable.PSObject.Properties[$srvName]) { "dns-hosts" } else { $wifiDnsTag }
        $clone | Add-Member -MemberType NoteProperty -Name "domain_resolver" -Value ([pscustomobject]@{
            server   = $nodeDnsTag
            strategy = "ipv4_only"
        }) -Force
        $boundNodes.Add($clone)
    }

    $allNodeTags = @($boundNodes | ForEach-Object { $_.tag })
    $hyTags      = @($boundNodes | Where-Object { $_.type -eq "hysteria2" } | ForEach-Object { $_.tag })
    $vlessTags   = @($boundNodes | Where-Object { $_.type -eq "vless" } | ForEach-Object { $_.tag })
    $vmessTrojan = @($boundNodes | Where-Object { $_.type -in @("vmess", "trojan", "shadowsocks") } | ForEach-Object { $_.tag })

    $clusterGroups = [System.Collections.Generic.List[object]]::new()

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

    $clusterGroups.Add([pscustomobject]@{
        type                        = "urltest"
        tag                         = "⚡ Cluster - Auto Lowest Ping"
        outbounds                   = @($allNodeTags)
        url                         = "https://www.gstatic.com/generate_204"
        interval                    = "1m"
        tolerance                   = 25
        interrupt_exist_connections = $false
    })

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

    $clusterGroups.Add([pscustomobject]@{
        type      = "selector"
        tag       = "⚙️ Manual Node Select"
        outbounds = @($allNodeTags)
    })

    # Direct Outbounds: Physical Wi-Fi Direct, Per-Adapter Customer VPN Direct (always bound, never empty), Standard OS Direct, Block
    $clusterGroups.Add([pscustomobject]@{
        type           = "direct"
        tag            = "direct-wifi"
        bind_interface = $PhysicalGw.Name
    })

    $vpnAdapterTags = @{}
    $custDnsTag = "direct"
    $targetCustDnsIp = ""
    if ($EnterpriseVpn.Active) {
        $vpnIdx = 0
        foreach ($adName in $EnterpriseVpn.Adapters) {
            if (-not $adName) { continue }
            $tagName = "direct-vpn-$vpnIdx"
            $vpnAdapterTags[$adName] = $tagName
            $clusterGroups.Add([pscustomobject]@{
                type           = "direct"
                tag            = $tagName
                bind_interface = $adName
            })
            $vpnIdx++
        }

        $primaryDnsOwner = $EnterpriseVpn.PrimaryAdapter
        if ($EnterpriseVpn.DnsBindings -and $EnterpriseVpn.DnsBindings.Count -gt 0) {
            $targetCustDnsIp = $EnterpriseVpn.DnsBindings[0].Ip
            $primaryDnsOwner = $EnterpriseVpn.DnsBindings[0].Adapter
        } elseif ($EnterpriseVpn.DnsServers.Count -gt 0) {
            $targetCustDnsIp = $EnterpriseVpn.DnsServers[0]
        }

        if ($primaryDnsOwner -and $vpnAdapterTags.ContainsKey($primaryDnsOwner)) {
            $custDnsTag = $vpnAdapterTags[$primaryDnsOwner]
        } elseif ($vpnAdapterTags.Count -gt 0) {
            $custDnsTag = @($vpnAdapterTags.Values)[0]
        }
    }
    $clusterGroups.Add([pscustomobject]@{ type = "direct"; tag = "direct" })
    $clusterGroups.Add([pscustomobject]@{ type = "block";  tag = "block" })

    $fullOutbounds = [System.Collections.Generic.List[object]]::new()
    foreach ($grp in $clusterGroups) { $fullOutbounds.Add($grp) }
    foreach ($bn  in $boundNodes)    { $fullOutbounds.Add($bn) }

    # Clean TUN Split-Tunnel Exclusions (RFC1918 + public VPN blocks + all FortiGate/GlobalProtect /32 gateways!)
    $standardPrivateSubnets = @(
        "127.0.0.0/8",         # Localhost loopback (Antigravity IDE, local agent IPC, language servers)
        "10.0.0.0/8",          # RFC 1918 Private / FortiClient / AnyConnect
        "172.16.0.0/12",       # RFC 1918 Private / Customer VPN
        "192.168.0.0/16",      # RFC 1918 Local LAN / Wi-Fi Gateway
        "169.254.0.0/16",      # Link-local / APIPA
        "224.0.0.0/4",         # Multicast
        "255.255.255.255/32"   # Broadcast
    )

    $tunExcludeList = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $standardPrivateSubnets)          { if (-not $tunExcludeList.Contains($p))   { $tunExcludeList.Add($p) } }
    foreach ($sub in $UserCustomerSubnets)           { if ($sub -and -not $tunExcludeList.Contains($sub)) { $tunExcludeList.Add($sub) } }
    foreach ($dynSub in $EnterpriseVpn.PublicSubnets){ if ($dynSub -and -not $tunExcludeList.Contains($dynSub)) { $tunExcludeList.Add($dynSub) } }
    foreach ($gwCidr in $EnterpriseVpn.GatewayCidrs) { if ($gwCidr -and -not $tunExcludeList.Contains($gwCidr)) { $tunExcludeList.Add($gwCidr) } }

    # Executables for FortiClient, Cisco AnyConnect, and Palo Alto GlobalProtect (always bypass TUN/Proxy)
    $vpnClientProcesses = @(
        "FortiClient.exe", "FortiClientConsole.exe", "FortiClientSecurity.exe",
        "FortiSSLVPNdaemon.exe", "FortiSSLVPNsys.exe", "FortiVPN.exe", "FortiTray.exe",
        "FortiSettings.exe", "FortiAuth.exe", "FCAuth.exe", "AzureToken2.exe",
        "FSSOMA.exe", "FortiWad.exe", "ipsec.exe", "scheduler.exe",
        "vpnagent.exe", "vpnui.exe", "csc_ui.exe",
        "PanGPA.exe", "PanGPS.exe"
    )

    # DNS Configuration (IPv4-only strategy avoids DNS64 64:ff9b:: failures on cellular/IPv4-only Wi-Fi)
    $dnsServers = [System.Collections.Generic.List[object]]::new()

    if ($hasHosts) {
        $dnsServers.Add([pscustomobject]@{
            tag        = "dns-hosts"
            type       = "hosts"
            predefined = $HostsTable
        })
    }

    # Physical Wi-Fi DNS (queries router/ISP DNS directly out Physical Wi-Fi)
    if ($hasWifiDns) {
        $dnsServers.Add([pscustomobject]@{
            tag    = "dns-wifi"
            type   = "udp"
            server = $PhysicalGw.DnsServers[0]
            detour = "direct-wifi"
        })
    }

    # Customer VPN Internal DNS (active only when FortiClient/AnyConnect/PANGP provides DNS)
    $hasCustDns = ($EnterpriseVpn.Active -and $targetCustDnsIp -ne "")
    if ($hasCustDns) {
        $dnsObj = [pscustomobject]@{
            tag    = "dns-custvpn"
            type   = "udp"
            server = $targetCustDnsIp
        }
        # Only detour to a bound adapter outbound (sing-box rejects detours to empty direct outbounds)
        if ($custDnsTag -ne "direct") {
            $dnsObj | Add-Member -MemberType NoteProperty -Name "detour" -Value $custDnsTag
        }
        $dnsServers.Add($dnsObj)
    }

    # Remote DoH DNS over port 443 through cluster
    $dnsServers.Add([pscustomobject]@{
        tag         = "dns-remote-doh"
        type        = "https"
        server      = "1.1.1.1"
        server_port = 443
        path        = "/dns-query"
        detour      = "proxy"
    })
    $dnsServers.Add([pscustomobject]@{
        tag         = "dns-google-doh"
        type        = "https"
        server      = "8.8.8.8"
        server_port = 443
        path        = "/dns-query"
        detour      = "proxy"
    })
    $dnsServers.Add([pscustomobject]@{
        tag  = "dns-local"
        type = "local"
    })

    $dnsRules = [System.Collections.Generic.List[object]]::new()
    if ($hasHosts) {
        $hostDomains = @($HostsTable.PSObject.Properties | ForEach-Object { $_.Name })
        $dnsRules.Add([pscustomobject]@{ domain = $hostDomains; server = "dns-hosts" })
    }
    $dnsRules.Add([pscustomobject]@{ domain = @("localhost", "localhost.localdomain"); server = "dns-local" })
    $dnsRules.Add([pscustomobject]@{ process_name = @($vpnClientProcesses); server = $wifiDnsTag })

    $corpDnsSuffixes = [System.Collections.Generic.List[string]]::new()
    foreach ($s in @(".local", ".lan", ".home", ".internal", ".corp", ".intranet", "in-addr.arpa", "ip6.arpa")) {
        $corpDnsSuffixes.Add($s)
    }
    foreach ($s in $EnterpriseVpn.Suffixes) {
        if ($s -and -not $corpDnsSuffixes.Contains($s)) { $corpDnsSuffixes.Add($s) }
    }
    foreach ($s in $ExtraCorpDomains) {
        $norm = $s.Trim()
        if ($norm -and -not $norm.StartsWith(".")) { $norm = ".$norm" }
        if ($norm -and -not $corpDnsSuffixes.Contains($norm)) { $corpDnsSuffixes.Add($norm) }
    }

    if ($hasCustDns) {
        $dnsRules.Add([pscustomobject]@{ domain_regex = @("^[^.]+$"); server = "dns-custvpn" })
        $dnsRules.Add([pscustomobject]@{ domain_suffix = @($corpDnsSuffixes); server = "dns-custvpn" })
    }

    $localCloudSuffixes = @(
        ".sharepoint.com", ".traps.paloaltonetworks.com",
        ".microsoft.com", ".office.com", ".office365.com", ".msftauth.net", ".live.com"
    )
    $localFallbackSuffixes = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $localCloudSuffixes) { $localFallbackSuffixes.Add($s) }
    if (-not $hasCustDns) {
        foreach ($s in $corpDnsSuffixes) {
            if (-not $localFallbackSuffixes.Contains($s)) { $localFallbackSuffixes.Add($s) }
        }
    }
    $dnsRules.Add([pscustomobject]@{ domain_suffix = @($localFallbackSuffixes); server = $wifiDnsTag })

    # Inbounds
    $inbounds = if ($UseProxyOnly) {
        @(
            [pscustomobject]@{
                type        = "mixed"
                tag         = "mixed-in"
                listen      = "127.0.0.1"
                listen_port = $LocalMixedPort
            }
        )
    } else {
        @(
            [pscustomobject]@{
                type                  = "tun"
                tag                   = "tun-in"
                address               = @("172.19.0.1/30")
                auto_route            = $true
                strict_route          = $false
                stack                 = "mixed"
                route_exclude_address = @($tunExcludeList)
            }
        )
    }

    # Route Rules
    $routeRules = [System.Collections.Generic.List[object]]::new()
    $routeRules.Add([pscustomobject]@{ action = "sniff" })
    if (-not $UseProxyOnly) {
        $routeRules.Add([pscustomobject]@{ protocol = "dns"; action = "hijack-dns" })
    }
    $routeRules.Add([pscustomobject]@{ process_name = @($vpnClientProcesses); outbound = "direct-wifi" })
    # Always bypass IPsec IKE/NAT-T (UDP 500 & 4500) and configured FortiGate/GlobalProtect gateway /32s to Wi-Fi
    $routeRules.Add([pscustomobject]@{ network = @("udp"); port = @(500, 4500); outbound = "direct-wifi" })
    if ($EnterpriseVpn.GatewayCidrs.Count -gt 0) {
        $routeRules.Add([pscustomobject]@{ ip_cidr = @($EnterpriseVpn.GatewayCidrs); outbound = "direct-wifi" })
    }

    if ($EnterpriseVpn.Active) {
        # Route each customer VPN adapter's subnets out its own interface
        if ($EnterpriseVpn.AdapterSubnets -and $vpnAdapterTags.Count -gt 0) {
            foreach ($adName in $EnterpriseVpn.Adapters) {
                $adRoutes = $EnterpriseVpn.AdapterSubnets[$adName]
                $adTag = $vpnAdapterTags[$adName]
                if ($adRoutes -and $adRoutes.Count -gt 0 -and $adTag) {
                    $routeRules.Add([pscustomobject]@{ ip_cidr = @($adRoutes); outbound = $adTag })
                }
            }
        } elseif ($EnterpriseVpn.Subnets.Count -gt 0) {
            $routeRules.Add([pscustomobject]@{ ip_cidr = @($EnterpriseVpn.Subnets); outbound = $custDnsTag })
        }

        $custDomainRules = [System.Collections.Generic.List[string]]::new()
        foreach ($s in $EnterpriseVpn.Suffixes) { if ($s -and -not $custDomainRules.Contains($s)) { $custDomainRules.Add($s) } }
        foreach ($s in $ExtraCorpDomains) {
            $norm = $s.Trim()
            if ($norm -and -not $norm.StartsWith(".")) { $norm = ".$norm" }
            if ($norm -and -not $custDomainRules.Contains($norm)) { $custDomainRules.Add($norm) }
        }
        if ($custDomainRules.Count -gt 0) {
            $routeRules.Add([pscustomobject]@{ domain_suffix = @($custDomainRules); outbound = $custDnsTag })
        }
        $routeRules.Add([pscustomobject]@{ domain_regex = @("^[^.]+$"); outbound = $custDnsTag })
    }

    $routeRules.Add([pscustomobject]@{
        domain_suffix = @(".traps.paloaltonetworks.com")
        outbound      = "direct-wifi"
    })
    $routeRules.Add([pscustomobject]@{ ip_is_private = $true; outbound = "direct" })
    $routeRules.Add([pscustomobject]@{ ip_cidr = @($tunExcludeList); outbound = "direct" })

    $clusterCfg = [pscustomobject]@{
        log = [pscustomobject]@{ level = "warn"; timestamp = $true }
        dns = [pscustomobject]@{
            strategy = "ipv4_only"
            servers  = @($dnsServers)
            rules    = @($dnsRules)
            final    = "dns-remote-doh"
        }
        inbounds  = @($inbounds)
        outbounds = @($fullOutbounds)
        route     = [pscustomobject]@{
            default_domain_resolver = [pscustomobject]@{
                server   = $wifiDnsTag
                strategy = "ipv4_only"
            }
            find_process            = $true
            rules                   = @($routeRules)
            auto_detect_interface   = $true
            final                   = "proxy"
        }
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $jsonOut = $clusterCfg | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($OutConfigPath, $jsonOut, $utf8NoBom)
    return $fullOutbounds.Count
}

# ── Helper: Start / Restart Sing-Box Process Cleanly ──────────────────────────
function Start-SingBoxClusterEngine {
    param([string]$ExePath, [string]$CfgPath)

    if ($script:SingBoxProcess -ne $null) {
        try {
            Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "SingBoxCluster*" } | Unregister-Event -ErrorAction SilentlyContinue
        } catch {}
        if (-not $script:SingBoxProcess.HasExited) {
            try { $script:SingBoxProcess.Kill(); $script:SingBoxProcess.WaitForExit(3000) | Out-Null } catch {}
        }
        $script:SingBoxProcess.Dispose()
        $script:SingBoxProcess = $null
        Start-Sleep -Milliseconds 300
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $ExePath
    $psi.Arguments              = "run -c `"$CfgPath`""
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $false

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $proc.EnableRaisingEvents = $true

    $idSuffix = [guid]::NewGuid().ToString("N").Substring(0, 8)
    Register-ObjectEvent $proc OutputDataReceived -SourceIdentifier "SingBoxClusterOut_$idSuffix" -Action {
        if ($Event.SourceEventArgs.Data) { Write-Host "[cluster] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkGray }
    } | Out-Null
    Register-ObjectEvent $proc ErrorDataReceived -SourceIdentifier "SingBoxClusterErr_$idSuffix" -Action {
        if ($Event.SourceEventArgs.Data) { Write-Host "[cluster] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkYellow }
    } | Out-Null

    $proc.Start() | Out-Null
    $proc.BeginOutputReadLine()
    $proc.BeginErrorReadLine()
    $script:SingBoxProcess = $proc

    Start-Sleep -Seconds 2
    return (-not $proc.HasExited)
}

# 9. Synthesize Initial Cluster Configuration
$totalTargets = New-SingBoxClusterConfig `
    -PhysicalGw $gw `
    -EnterpriseVpn $vpnState `
    -Nodes $approvedNodes `
    -HostsTable $hostsMap `
    -UserCustomerSubnets $CustomerSubnets `
    -ExtraCorpDomains $CorpDomains `
    -UseProxyOnly ([bool]$ProxyOnly) `
    -LocalMixedPort $MixedPort `
    -OutConfigPath $TempConfigPath

Write-Ok "Cluster configuration synthesized ($totalTargets total targets)."

# Optional System Proxy activation (for -ProxyOnly -SystemProxy)
if ($SystemProxy) {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $cur = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    $script:PrevProxyState = [pscustomobject]@{
        Enable   = if ($cur.ProxyEnable) { $cur.ProxyEnable } else { 0 }
        Server   = if ($cur.ProxyServer) { $cur.ProxyServer } else { "" }
        Override = if ($cur.ProxyOverride) { $cur.ProxyOverride } else { "" }
    }
    $bypassList = @("<local>", "localhost", "127.*", "10.*", "172.16.*", "192.168.*", "*.local", "*.internal", "*.corp", "*.lan")
    foreach ($sfx in $vpnState.Suffixes) { $bypassList += "*$sfx" }
    foreach ($cd in $CorpDomains)        { $bypassList += "*$cd" }
    $bypassStr = ($bypassList | Select-Object -Unique) -join ";"
    Set-WindowsSystemProxyState -Enable $true -Server "127.0.0.1:$MixedPort" -Bypass $bypassStr
    $script:AppliedSystemProxy = $true
    Write-Ok "Windows System Proxy enabled -> 127.0.0.1:$MixedPort (Corporate & LAN bypassed)."
}

# 10. Launch sing-box Cluster Engine
Write-Host ""
Write-Info "Starting sing-box Cluster Engine..."
$started = Start-SingBoxClusterEngine -ExePath $singBoxExe -CfgPath $TempConfigPath
if (-not $started) {
    Write-Err "sing-box cluster failed to start (exit code: $($SingBoxProcess.ExitCode))"
    Invoke-Cleanup
    exit 1
}

Write-Ok "sing-box Cluster is ACTIVE (PID: $($SingBoxProcess.Id))"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
if ($ProxyOnly) {
    Write-Host "  CONNECTED! PROXY-ONLY MODE (100% FORTICLIENT ISOLATED)" -ForegroundColor Green
} else {
    Write-Host "  CONNECTED! CLUSTER LOAD-BALANCER ACTIVE (FORTICLIENT SAFE)" -ForegroundColor Green
}
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  * Approved Nodes      : $($approvedNodes.Count) active nodes in pool ($droppedCount blocked)" -ForegroundColor White
Write-Host "  * Physical Binding    : Always bound directly to '$($gw.Name)' ($($gw.Gateway))" -ForegroundColor White
Write-Host "  * Active Mode         : ⚡ Auto Lowest-Ping (Health-checks every 1 min)" -ForegroundColor White
Write-Host "  * Antigravity Safe    : Blocked regions ($($BlockedCountries -join ', ')) filtered out" -ForegroundColor White
if ($ProxyOnly) {
    Write-Host "  * Local Proxy Address : http://127.0.0.1:$MixedPort  &  socks5://127.0.0.1:$MixedPort" -ForegroundColor Cyan
}
$vpnLabel = if ($vpnState.Active) { "ACTIVE ($($vpnState.Adapters -join ', ')) - Auto-Excluded & DNS Bridged" } else { "Monitoring (Connect FortiClient anytime - auto-bridges!)" }
Write-Host "  * Customer VPN Status : $vpnLabel" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press Ctrl+C to disconnect and restore all routes." -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

# 11. Keep-Alive & Dynamic Customer VPN Coexistence Watcher Loop
$lastCheck = Get-Date
$activeVpnSig = $vpnState.Signature
$activeReloadSig = $vpnState.ReloadSignature
try {
    while (-not $SingBoxProcess.HasExited) {
        Start-Sleep -Milliseconds 500
        if (((Get-Date) - $lastCheck).TotalSeconds -ge 2.0) {
            $lastCheck = Get-Date
            $probeVpn = Get-EnterpriseVpnState -PhysicalGw $gw -ProxyServerIPs $allowedServerIPs
            if ($probeVpn.Signature -ne $activeVpnSig) {
                # Brief debounce so FortiClient finishes applying all routes and DNS IPs
                Start-Sleep -Milliseconds 1500
                $probeVpn = Get-EnterpriseVpnState -PhysicalGw $gw -ProxyServerIPs $allowedServerIPs
                if ($probeVpn.Signature -ne $activeVpnSig) {
                    $activeVpnSig = $probeVpn.Signature
                    if ($probeVpn.ReloadSignature -ne $activeReloadSig) {
                        $activeReloadSig = $probeVpn.ReloadSignature
                        Write-Host ""
                        if ($probeVpn.Active) {
                            Write-Warn "Customer VPN ($($probeVpn.Adapters -join ', ')) introduced new DNS/public routes -> syncing cluster..."
                            if ($probeVpn.HasFullTunnel -and -not $ProxyOnly) {
                                Write-Warn "FortiClient is Full-Tunnel (0.0.0.0/0). If it rejects coexistence with TUN, run with -ProxyOnly -SystemProxy."
                            }
                        } else {
                            Write-Info "Customer VPN disconnected -> restoring standard cluster routing..."
                        }
                        $null = New-SingBoxClusterConfig `
                            -PhysicalGw $gw `
                            -EnterpriseVpn $probeVpn `
                            -Nodes $approvedNodes `
                            -HostsTable $hostsMap `
                            -UserCustomerSubnets $CustomerSubnets `
                            -ExtraCorpDomains $CorpDomains `
                            -UseProxyOnly ([bool]$ProxyOnly) `
                            -LocalMixedPort $MixedPort `
                            -OutConfigPath $TempConfigPath
                        $reloaded = Start-SingBoxClusterEngine -ExePath $singBoxExe -CfgPath $TempConfigPath
                        if ($reloaded) {
                            Write-Ok "Cluster hot-reloaded cleanly (PID: $($SingBoxProcess.Id)). Both VPNs synchronized!"
                        } else {
                            Write-Err "Cluster reload failed (exit code: $($SingBoxProcess.ExitCode))"
                            break
                        }
                    } else {
                        Write-Host ""
                        if ($probeVpn.Active) {
                            Write-Ok "Customer VPN ($($probeVpn.Adapters -join ', ')) active -- gateway & RFC1918 subnets already isolated (zero reload needed)."
                        } else {
                            Write-Info "Customer VPN disconnected (cluster unaffected)."
                        }
                    }
                }
            }
        }
    }
    if ($SingBoxProcess.HasExited) {
        Write-Warn "sing-box cluster stopped (exit code: $($SingBoxProcess.ExitCode))"
    }
} finally {
    Invoke-Cleanup
}
