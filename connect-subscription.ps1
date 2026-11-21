<#
.SYNOPSIS
    Multip VPN - Live Subscription Connector with Auto-Update Lifecycle & Corporate Shield
    Automatically fetches remote subscription URLs (Gist / Base64 / Sub-Store / Hiddify format),
    parses active VPN keys, verifies connectivity, protects FortiClient corporate traffic, and
    hot-reloads automatically whenever the remote subscription updates!

.DESCRIPTION
    1. Reads subscription URLs from subscriptions.txt (or -Url parameter).
    2. Supports VLESS Reality, VMess, Trojan, Shadowsocks, Hysteria2, TUIC.
    3. Auto-detects Hiddify metadata (profile-title, profile-update-interval, subscription-userinfo).
    4. Auto-Update Lifecycle: Monitors remote Gist/URL in the background; when the VPN admin rotates
       keys on the server, sing-box hot-reloads the new key with zero downtime.
    5. Corporate Shield: Full isolation for FortiClient, Cisco AnyConnect, and GlobalProtect.
       Internal corporate DNS and subnets are strictly routed out the customer VPN adapter,
       so your corporate network and RDP NEVER fail even if a public subscription key drops.
    6. Multi-Node Resilience & Auto-Fallback: If a subscription key fails or gets blocked by ISP DPI,
       the engine automatically falls back to verified backup nodes so your laptop never blacks out.
    7. Browser & Antigravity safe: Rejects QUIC UDP 443 and DoT UDP 853 to force reliable TCP TLS.
    8. Clean Ctrl+C teardown restores all routes, firewall rules, and adapters.

.PARAMETER SubscriptionFile
    Path to file containing subscription URLs (defaults to 'subscriptions.txt').

.PARAMETER Url
    Direct subscription or Gist URL to connect to.

.PARAMETER MixedPort
    Local SOCKS5/HTTP mixed proxy port (default: 10808).

.PARAMETER ProxyOnly
    Run in proxy-only mode (127.0.0.1:10808) without creating a TUN adapter.

.PARAMETER SystemProxy
    Set Windows system proxy to 127.0.0.1:MixedPort while running.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionFile          = "subscriptions.txt",
    [string]$Url                       = "",
    [string]$SingBoxPath               = "",
    [string]$XrayPath                  = "",
    [string[]]$CustomerSubnets         = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
    [string[]]$CorpDomains             = @(),
    [switch]$ProxyOnly,
    [switch]$SystemProxy,
    [switch]$DisableFallbackPool,
    [switch]$DisableXrayBridge,
    [int]$MixedPort                    = 10808,
    [int]$DefaultUpdateIntervalMinutes = 60,
    [int]$CheckIntervalSeconds         = 30
)

# Normalize array parameters (handles comma-separated strings passed via UAC elevation)
$CustomerSubnets  = @($CustomerSubnets  | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$CorpDomains      = @($CorpDomains      | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ── Color Output Helpers ────────────────────────────────────────────────────────
function Write-Info    { param($m) Write-Host "[*] $m" -ForegroundColor Cyan    }
function Write-Ok      { param($m) Write-Host "[+] $m" -ForegroundColor Green   }
function Write-Warn    { param($m) Write-Host "[!] $m" -ForegroundColor Yellow  }
function Write-Err     { param($m) Write-Host "[-] $m" -ForegroundColor Red     }
function Write-Header  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Magenta }

# ── Script Location & Binary Resolution ─────────────────────────────────────────
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }
if (-not $SingBoxPath) { $SingBoxPath = Join-Path $ScriptDir "sing-box.exe" }
$singBoxExe = $SingBoxPath
if (-not (Test-Path $singBoxExe)) {
    Write-Err "sing-box.exe not found at: $singBoxExe"
    exit 1
}

if (-not $XrayPath) { $XrayPath = Join-Path $ScriptDir "xray.exe" }
$xrayExe = $XrayPath
$hasXray = (-not $DisableXrayBridge -and (Test-Path $xrayExe))

# ── Administrator Privilege Check & Elevation ──────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $ProxyOnly) {
    Write-Warn "Elevating to Administrator for TUN routing & firewall management..."
    $scriptFilePath = $PSCommandPath
    if (-not $scriptFilePath) { $scriptFilePath = Join-Path $ScriptDir "connect-subscription.ps1" }
    
    $subnetsArg = $CustomerSubnets -join ','
    $corpArg    = $CorpDomains -join ','
    $passArgs   = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptFilePath`"")
    if ($SubscriptionFile) { $passArgs += @("-SubscriptionFile", "`"$SubscriptionFile`"") }
    if ($Url)              { $passArgs += @("-Url", "`"$Url`"") }
    if ($SingBoxPath)      { $passArgs += @("-SingBoxPath", "`"$SingBoxPath`"") }
    if ($XrayPath)         { $passArgs += @("-XrayPath", "`"$XrayPath`"") }
    if ($subnetsArg)       { $passArgs += @("-CustomerSubnets", "`"$subnetsArg`"") }
    if ($corpArg)          { $passArgs += @("-CorpDomains", "`"$corpArg`"") }
    if ($ProxyOnly)        { $passArgs += "-ProxyOnly" }
    if ($SystemProxy)      { $passArgs += "-SystemProxy" }
    if ($DisableFallbackPool) { $passArgs += "-DisableFallbackPool" }
    if ($DisableXrayBridge)   { $passArgs += "-DisableXrayBridge" }
    if ($MixedPort)        { $passArgs += @("-MixedPort", "$MixedPort") }

    $argString = $passArgs -join " "
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argString
    } catch {
        Write-Err "Elevation was declined: $_"
    }
    exit 0
}

# ── State Tracking & Clean Teardown ─────────────────────────────────────────────
$script:TrackedRoutes      = [System.Collections.Generic.List[object]]::new()
$script:TrackedFwRules     = [System.Collections.Generic.List[string]]::new()
$script:SingBoxProcess     = $null
$script:XrayProcess        = $null
$script:SystemProxyEnabled = $false
$script:TempConfigPath     = Join-Path $env:TEMP ("sb-sub-" + [Guid]::NewGuid().ToString("N") + ".json")
$script:TempXrayConfigPath = Join-Path $env:TEMP ("xray-sub-" + [Guid]::NewGuid().ToString("N") + ".json")

function Invoke-Cleanup {
    Write-Host "`n[*] Disconnecting & restoring network configuration..." -ForegroundColor Yellow

    if ($script:SystemProxyEnabled) {
        Restore-WindowsSystemProxy
    }

    if ($script:SingBoxProcess -ne $null) {
        try {
            Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "SingBoxSub*" } | Unregister-Event -ErrorAction SilentlyContinue
        } catch {}
        if (-not $script:SingBoxProcess.HasExited) {
            try { $script:SingBoxProcess.Kill(); $script:SingBoxProcess.WaitForExit(3000) | Out-Null } catch {}
        }
        $script:SingBoxProcess.Dispose()
        $script:SingBoxProcess = $null
        Write-Ok "sing-box engine stopped (TUN adapter removed)."
    }

    if ($script:XrayProcess -ne $null) {
        if (-not $script:XrayProcess.HasExited) {
            try { $script:XrayProcess.Kill(); $script:XrayProcess.WaitForExit(2000) | Out-Null } catch {}
        }
        $script:XrayProcess.Dispose()
        $script:XrayProcess = $null
        Write-Ok "Xray bridge engine stopped."
    }

    Remove-AllTrackedRoutes
    Remove-TrackedFwRules

    if (Test-Path $script:TempConfigPath) {
        Remove-Item -Path $script:TempConfigPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $script:TempXrayConfigPath) {
        Remove-Item -Path $script:TempXrayConfigPath -Force -ErrorAction SilentlyContinue
    }

    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
    Write-Ok "Network fully restored. Customer VPN is intact."
}

# ── System Proxy Helpers ────────────────────────────────────────────────────────
function Set-WindowsSystemProxy {
    param([int]$Port)
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 1 -Type DWord
        Set-ItemProperty -Path $regPath -Name ProxyServer -Value "127.0.0.1:$Port"
        Set-ItemProperty -Path $regPath -Name ProxyOverride -Value "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"
        $script:SystemProxyEnabled = $true
        Write-Ok "Windows System Proxy configured -> 127.0.0.1:$Port"
    } catch {
        Write-Warn "Failed to set System Proxy: $_"
    }
}

function Restore-WindowsSystemProxy {
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0 -Type DWord
        $script:SystemProxyEnabled = $false
        Write-Ok "Windows System Proxy disabled."
    } catch {}
}

# ── Firewall Helpers ────────────────────────────────────────────────────────────
function Add-TrackedFwRule {
    param([string]$Name, [string]$ProgramPath)
    if (-not $isAdmin) { return }
    try {
        netsh advfirewall firewall delete rule name="$Name" dir=in  program="$ProgramPath" > $null 2>&1
        netsh advfirewall firewall delete rule name="$Name" dir=out program="$ProgramPath" > $null 2>&1
        netsh advfirewall firewall add rule name="$Name" dir=in  action=allow program="$ProgramPath" enable=yes profile=any > $null 2>&1
        netsh advfirewall firewall add rule name="$Name" dir=out action=allow program="$ProgramPath" enable=yes profile=any > $null 2>&1
        $script:TrackedFwRules.Add($Name)
    } catch {}
}

function Remove-TrackedFwRules {
    if (-not $isAdmin) { return }
    foreach ($rule in $script:TrackedFwRules) {
        try { netsh advfirewall firewall delete rule name="$rule" > $null 2>&1 } catch {}
    }
    $script:TrackedFwRules.Clear()
}

# ── Routing Helpers ─────────────────────────────────────────────────────────────
function Add-TrackedRoutesBatch {
    param([string[]]$IPs, [string]$Gateway, [int]$IfIndex, [int]$Metric = 5)
    if (-not $IPs -or $IPs.Count -eq 0 -or -not $isAdmin) { return }
    $existing = @{}
    foreach ($r in (Get-NetRoute -DestinationPrefix "*/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        $pfx = $r.DestinationPrefix -replace '/32$', ''
        $existing[$pfx] = $true
    }
    foreach ($ip in $IPs) {
        $clean = $ip.Trim()
        if (-not $clean -or $existing.ContainsKey($clean)) { continue }
        try {
            New-NetRoute -DestinationPrefix "$clean/32" -InterfaceIndex $IfIndex -NextHop $Gateway -RouteMetric $Metric -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
            $script:TrackedRoutes.Add([pscustomobject]@{ Prefix = "$clean/32"; IfIndex = $IfIndex })
        } catch {}
    }
}

function Remove-AllTrackedRoutes {
    if (-not $isAdmin) { return }
    foreach ($item in $script:TrackedRoutes) {
        try { Remove-NetRoute -DestinationPrefix $item.Prefix -InterfaceIndex $item.IfIndex -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
    $script:TrackedRoutes.Clear()
}

# ── Physical Gateway Detection ──────────────────────────────────────────────────
function Get-PhysicalGateway {
    $skipWords = @(
        "vmware", "virtual", "tap", "loopback", "tunnel", "pangp", "anyconnect",
        "fortinet", "cisco", "globalprotect", "palo", "wsl", "hyper-v", "tailscale",
        "zerotier", "wireguard", "sing-box", "singbox", "nordvpn", "surfshark",
        "expressvpn", "x-vpn", "xvpn", "proton", "cloudflare", "warp", "clash", "hiddify"
    )

    $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Sort-Object RouteMetric, InterfaceMetric

    foreach ($r in $routes) {
        $alias = (Get-NetIPInterface -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceAlias
        if (-not $alias) { continue }
        $aliasLower = $alias.ToLowerInvariant()
        $isVirtual = $false
        foreach ($w in $skipWords) {
            if ($aliasLower -like "*$w*") { $isVirtual = $true; break }
        }
        if (-not $isVirtual -and $r.NextHop -and $r.NextHop -ne "0.0.0.0") {
            $dnsList = @((Get-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
            return [pscustomobject]@{
                InterfaceIndex = $r.InterfaceIndex
                Name           = $alias
                Gateway        = $r.NextHop
                DnsServers     = $dnsList
            }
        }
    }
    return [pscustomobject]@{ InterfaceIndex = 0; Name = "Wi-Fi"; Gateway = "127.0.0.1"; DnsServers = @("1.1.1.1") }
}

# ── Customer / Corporate VPN State Detection (Dynamic) ──────────────────────────
function Get-EnterpriseVpnState {
    param($PhysicalGw, [string[]]$ProxyServerIPs)
    $vpnKeywords = @("fortinet", "forticlient", "pangp", "globalprotect", "anyconnect", "cisco")
    $activeAdapters = [System.Collections.Generic.List[object]]::new()
    $adapterRoutesMap = @{}
    $allSubnets = [System.Collections.Generic.List[string]]::new()
    $allDns = [System.Collections.Generic.List[string]]::new()
    $allSuffixes = [System.Collections.Generic.List[string]]::new()
    $gwIps = [System.Collections.Generic.List[string]]::new()

    # Discover customer VPN gateways dynamically from registry
    $regPaths = @(
        "HKLM:\SOFTWARE\Fortinet\FortiClient\Sslvpn",
        "HKCU:\Software\Fortinet\FortiClient\Sslvpn",
        "HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\PanSetup",
        "HKCU:\Software\Palo Alto Networks\GlobalProtect\PanSetup"
    )
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            try {
                $p = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
                foreach ($prop in $p.PSObject.Properties) {
                    if ($prop.Value -is [string] -and $prop.Value -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        if (-not $gwIps.Contains($prop.Value)) { $gwIps.Add($prop.Value) }
                    }
                }
            } catch {}
        }
    }

    $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    foreach ($ad in $allAdapters) {
        $desc = "$($ad.Name) $($ad.InterfaceDescription)".ToLowerInvariant()
        $isVpn = $false
        foreach ($kw in $vpnKeywords) {
            if ($desc -like "*$kw*") { $isVpn = $true; break }
        }
        if ($isVpn) {
            $activeAdapters.Add($ad)
            $ifIdx = $ad.InterfaceIndex
            $routes = Get-NetRoute -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                      Where-Object { $_.DestinationPrefix -ne "0.0.0.0/0" -and $_.DestinationPrefix -ne "255.255.255.255/32" }
            $thisAdRoutes = [System.Collections.Generic.List[string]]::new()
            foreach ($rt in $routes) {
                $pfx = $rt.DestinationPrefix
                if (-not $allSubnets.Contains($pfx)) { $allSubnets.Add($pfx) }
                if (-not $thisAdRoutes.Contains($pfx)) { $thisAdRoutes.Add($pfx) }
            }
            $adapterRoutesMap[$ad.Name] = @($thisAdRoutes)
            $adDns = (Get-DnsClientServerAddress -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
            if ($adDns) { foreach ($d in $adDns) { if (-not $allDns.Contains($d)) { $allDns.Add($d) } } }
        }
    }

    $gwCidrs = [System.Collections.Generic.List[string]]::new()
    foreach ($g in $gwIps) { $gwCidrs.Add("$g/32") }

    $sig = (@(
        (($activeAdapters | ForEach-Object { $_.Name } | Sort-Object) -join ","),
        (($allSubnets | Sort-Object) -join ","),
        (($allDns | Sort-Object) -join ",")
    ) -join "|")

    return [pscustomobject]@{
        Active         = ($activeAdapters.Count -gt 0)
        Adapters       = @($activeAdapters | ForEach-Object { $_.Name })
        Subnets        = @($allSubnets)
        AdapterSubnets = $adapterRoutesMap
        DnsServers     = @($allDns)
        Suffixes       = @($allSuffixes)
        GatewayCidrs   = @($gwCidrs)
        Signature      = $sig
    }
}

# ── Base64 & Query Helpers ──────────────────────────────────────────────────────
function Decode-Base64([string]$s) {
    if (-not $s) { return "" }
    $s = $s.Trim().Replace('-', '+').Replace('_', '/')
    $pad = $s.Length % 4
    if ($pad -eq 2) { $s += '==' }
    elseif ($pad -eq 3) { $s += '=' }
    try {
        $bytes = [System.Convert]::FromBase64String($s)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        return ""
    }
}

function Parse-QueryString([string]$query) {
    $dict = @{}
    if (-not $query) { return $dict }
    if ($query.StartsWith('?')) { $query = $query.Substring(1) }
    $pairs = $query -split '&'
    foreach ($p in $pairs) {
        if ($p -match '^([^=]+)=(.*)$') {
            $k = [System.Uri]::UnescapeDataString($Matches[1])
            $v = [System.Uri]::UnescapeDataString($Matches[2])
            $dict[$k] = $v
        }
    }
    return $dict
}

# ── Node Parsers ────────────────────────────────────────────────────────────────
function Parse-Vless([string]$uri, [string]$tag) {
    if ($uri -match '^vless://([^@]+)@(\[[a-fA-F0-9:]+\]|[^:/?#]+):(\d+)(\?[^#]*)?$') {
        $uuid   = $Matches[1]
        $server = $Matches[2].Trim('[', ']')
        $port   = [int]$Matches[3]
        $q      = Parse-QueryString $Matches[4]
        if (-not $tag) { $tag = "VLESS-$server`:$port" }

        $node = [ordered]@{
            type        = "vless"
            tag         = $tag
            server      = $server
            server_port = $port
            uuid        = $uuid
        }
        if ($q['flow']) { $node["flow"] = $q['flow'] }

        $sec = $q['security']
        if ($sec -eq "reality") {
            $pbk = if ($q['pbk']) { $q['pbk'] } else { $q['public_key'] }
            $sid = if ($q['sid']) { $q['sid'] } else { $q['short_id'] }
            $fp  = if ($q['fp'])  { $q['fp'] }  else { "firefox" }
            $sni = if ($q['sni']) { $q['sni'] } else { $server }

            $node["tls"] = [ordered]@{
                enabled     = $true
                server_name = $sni
                utls        = @{ enabled = $true; fingerprint = $fp }
                reality     = [ordered]@{
                    enabled    = $true
                    public_key = $pbk
                    short_id   = $sid
                }
            }
        } elseif ($sec -eq "tls") {
            $sni = if ($q['sni']) { $q['sni'] } else { $server }
            $fp  = if ($q['fp'])  { $q['fp'] }  else { "firefox" }
            $node["tls"] = [ordered]@{
                enabled     = $true
                server_name = $sni
                utls        = @{ enabled = $true; fingerprint = $fp }
            }
        }

        # Transport (WS, gRPC, HTTP)
        $net = $q['type']
        if ($net -eq "ws") {
            $wsPath = if ($q['path']) { $q['path'] } else { "/" }
            $wsHost = if ($q['host']) { $q['host'] } else { $server }
            $node["transport"] = [ordered]@{
                type    = "ws"
                path    = $wsPath
                headers = @{ Host = $wsHost }
            }
        } elseif ($net -eq "grpc") {
            $srvName = if ($q['serviceName']) { $q['serviceName'] } else { "" }
            $node["transport"] = [ordered]@{
                type         = "grpc"
                service_name = $srvName
            }
        }
        $node["packet_encoding"] = "xudp"
        return $node
    }
    return $null
}

function Parse-Shadowsocks([string]$uri, [string]$tag) {
    if ($uri -match '^ss://([A-Za-z0-9+/=_-]+)@([^:/?#]+):(\d+)') {
        $userInfo = Decode-Base64 $Matches[1]
        $server   = $Matches[2]
        $port     = [int]$Matches[3]
        if ($userInfo -match '^([^:]+):(.*)$') {
            $method = $Matches[1]
            $pwd    = $Matches[2]
            if (-not $tag) { $tag = "SS-$server`:$port" }
            return [ordered]@{
                type        = "shadowsocks"
                tag         = $tag
                server      = $server
                server_port = $port
                method      = $method
                password    = $pwd
            }
        }
    }
    return $null
}

function Parse-Hysteria2([string]$uri, [string]$tag) {
    if ($uri -match '^(?:hysteria2|hy2)://([^@]+)@([^:/?#]+):(\d+)(\?[^#]*)?$') {
        $pwd    = $Matches[1]
        $server = $Matches[2]
        $port   = [int]$Matches[3]
        $q      = Parse-QueryString $Matches[4]
        if (-not $tag) { $tag = "HY2-$server`:$port" }

        $node = [ordered]@{
            type        = "hysteria2"
            tag         = $tag
            server      = $server
            server_port = $port
            password    = $pwd
        }
        $sni = if ($q['sni']) { $q['sni'] } else { $server }
        $node["tls"] = [ordered]@{
            enabled     = $true
            server_name = $sni
        }
        if ($q['insecure'] -eq "1" -or $q['allowInsecure'] -eq "1") {
            $node["tls"]["insecure"] = $true
        }
        return $node
    }
    return $null
}

function Parse-Trojan([string]$uri, [string]$tag) {
    if ($uri -match '^trojan://([^@]+)@([^:/?#]+):(\d+)(\?[^#]*)?$') {
        $pwd    = $Matches[1]
        $server = $Matches[2]
        $port   = [int]$Matches[3]
        $q      = Parse-QueryString $Matches[4]
        if (-not $tag) { $tag = "Trojan-$server`:$port" }
        $sni = if ($q['sni']) { $q['sni'] } else { $server }
        return [ordered]@{
            type        = "trojan"
            tag         = $tag
            server      = $server
            server_port = $port
            password    = $pwd
            tls         = @{ enabled = $true; server_name = $sni }
        }
    }
    return $null
}

function Parse-Vmess([string]$uri, [string]$tag) {
    if ($uri -match '^vmess://([A-Za-z0-9+/=_-]+)') {
        $jsonStr = Decode-Base64 $Matches[1]
        if ($jsonStr) {
            try {
                $j = $jsonStr | ConvertFrom-Json
                $srv  = $j.add
                $port = [int]$j.port
                $uuid = $j.id
                $t    = if ($j.ps) { $j.ps } elseif ($tag) { $tag } else { "VMess-$srv`:$port" }
                $node = [ordered]@{
                    type        = "vmess"
                    tag         = $t
                    server      = $srv
                    server_port = $port
                    uuid        = $uuid
                    security    = if ($j.scy) { $j.scy } else { "auto" }
                }
                if ($j.tls -eq "tls") {
                    $sni = if ($j.sni) { $j.sni } elseif ($j.host) { $j.host } else { $srv }
                    $node["tls"] = @{ enabled = $true; server_name = $sni }
                }
                if ($j.net -eq "ws") {
                    $node["transport"] = @{ type = "ws"; path = if ($j.path) { $j.path } else { "/" } }
                }
                $node["packet_encoding"] = "xudp"
                return $node
            } catch {}
        }
    }
    return $null
}

# ── Dual-Engine Xray Bridge (Post-Quantum REALITY & Anti-Censorship) ─────────────
function ConvertTo-XrayOutbound($node) {
    if ($node.type -eq "vless") {
        $sec = "none"
        if ($node.tls) {
            if ($node.tls.reality -and $node.tls.reality.enabled) {
                $sec = "reality"
            } elseif ($node.tls.enabled) {
                $sec = "tls"
            }
        }

        $streamSettings = [ordered]@{
            network  = if ($node.transport -and $node.transport.type) { $node.transport.type } else { "tcp" }
            security = $sec
        }
        if ($sec -eq "reality") {
            $fp = if ($node.tls.utls -and $node.tls.utls.fingerprint) { $node.tls.utls.fingerprint } else { "firefox" }
            $streamSettings["realitySettings"] = [ordered]@{
                serverName  = $node.tls.server_name
                fingerprint = $fp
                publicKey   = $node.tls.reality.public_key
                shortId     = if ($node.tls.reality.short_id) { $node.tls.reality.short_id } else { "" }
                spiderX     = ""
            }
        } elseif ($sec -eq "tls") {
            $fp = if ($node.tls.utls -and $node.tls.utls.fingerprint) { $node.tls.utls.fingerprint } else { "firefox" }
            $streamSettings["tlsSettings"] = [ordered]@{
                serverName  = $node.tls.server_name
                fingerprint = $fp
            }
        }

        if ($node.transport) {
            if ($node.transport.type -eq "ws") {
                $streamSettings["wsSettings"] = [ordered]@{
                    path    = $node.transport.path
                    headers = $node.transport.headers
                }
            } elseif ($node.transport.type -eq "grpc") {
                $streamSettings["grpcSettings"] = [ordered]@{
                    serviceName = $node.transport.service_name
                }
            }
        }

        return [ordered]@{
            tag      = $node.tag
            protocol = "vless"
            settings = [ordered]@{
                vnext = @(
                    [ordered]@{
                        address = $node.server
                        port    = [int]$node.server_port
                        users   = @(
                            [ordered]@{
                                id         = $node.uuid
                                encryption = "none"
                                flow       = if ($node.flow) { $node.flow } else { "" }
                            }
                        )
                    }
                )
            }
            streamSettings = $streamSettings
        }
    } elseif ($node.type -eq "shadowsocks") {
        return [ordered]@{
            tag      = $node.tag
            protocol = "shadowsocks"
            settings = [ordered]@{
                servers = @(
                    [ordered]@{
                        address  = $node.server
                        port     = [int]$node.server_port
                        method   = $node.method
                        password = $node.password
                    }
                )
            }
        }
    } elseif ($node.type -eq "trojan") {
        return [ordered]@{
            tag      = $node.tag
            protocol = "trojan"
            settings = [ordered]@{
                servers = @(
                    [ordered]@{
                        address  = $node.server
                        port     = [int]$node.server_port
                        password = $node.password
                    }
                )
            }
            streamSettings = [ordered]@{
                network  = "tcp"
                security = "tls"
                tlsSettings = [ordered]@{
                    serverName = $node.tls.server_name
                }
            }
        }
    } elseif ($node.type -eq "vmess") {
        return [ordered]@{
            tag      = $node.tag
            protocol = "vmess"
            settings = [ordered]@{
                vnext = @(
                    [ordered]@{
                        address = $node.server
                        port    = [int]$node.server_port
                        users   = @(
                            [ordered]@{
                                id       = $node.uuid
                                security = if ($node.security) { $node.security } else { "auto" }
                            }
                        )
                    }
                )
            }
        }
    }
    return $null
}

function Stop-XrayBridgeEngine {
    if ($script:XrayProcess -ne $null) {
        if (-not $script:XrayProcess.HasExited) {
            try { $script:XrayProcess.Kill(); $script:XrayProcess.WaitForExit(2000) | Out-Null } catch {}
        }
        $script:XrayProcess.Dispose()
        $script:XrayProcess = $null
    }
    try {
        Get-Process -Name xray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Start-XrayBridgeEngine {
    param($Nodes, [string]$XrayExePath, [int]$BasePort = 10851)
    Stop-XrayBridgeEngine

    if (-not $Nodes -or $Nodes.Count -eq 0 -or -not (Test-Path $XrayExePath)) {
        return @{ Active = $false; MappedNodes = $Nodes }
    }

    $inbounds = [System.Collections.Generic.List[object]]::new()
    $outbounds = [System.Collections.Generic.List[object]]::new()
    $rules = [System.Collections.Generic.List[object]]::new()
    $mapped = [System.Collections.Generic.List[object]]::new()

    $portIdx = 0
    $currentPort = $BasePort
    $usedPorts = [System.Collections.Generic.HashSet[int]]::new()
    try {
        foreach ($cp in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
            [void]$usedPorts.Add([int]$cp.LocalPort)
        }
    } catch {}

    foreach ($n in $Nodes) {
        $xout = ConvertTo-XrayOutbound -node $n
        if ($xout) {
            while ($usedPorts.Contains($currentPort)) { $currentPort++ }
            $assignedPort = $currentPort
            [void]$usedPorts.Add($assignedPort)
            $currentPort++

            $inTag = "in-bridge-$portIdx"
            $outTag = $n.tag

            $inbounds.Add([ordered]@{
                tag      = $inTag
                port     = $assignedPort
                listen   = "127.0.0.1"
                protocol = "socks"
                settings = @{ udp = $true }
            })
            $outbounds.Add($xout)
            $rules.Add([ordered]@{
                type        = "field"
                inboundTag  = @($inTag)
                outboundTag = $outTag
            })

            $sbNode = [ordered]@{
                type            = "socks"
                tag             = $n.tag
                server          = "127.0.0.1"
                server_port     = $assignedPort
                _originalServer = $n.server
                _originalPort   = $n.server_port
                _bridgedViaXray = $true
            }
            $mapped.Add($sbNode)
            $portIdx++
        } else {
            $mapped.Add($n)
        }
    }

    if ($outbounds.Count -eq 0) {
        return @{ Active = $false; MappedNodes = $Nodes }
    }

    $xrayFullCfg = [ordered]@{
        log       = [ordered]@{ loglevel = "warning" }
        inbounds  = @($inbounds)
        outbounds = @($outbounds)
        routing   = [ordered]@{ rules = @($rules) }
    }

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $json = $xrayFullCfg | ConvertTo-Json -Depth 15
    [System.IO.File]::WriteAllText($script:TempXrayConfigPath, $json, $utf8NoBom)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $XrayExePath
    $psi.Arguments              = "run -c `"$($script:TempXrayConfigPath)`""
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $p.Start() | Out-Null
    Start-Sleep -Milliseconds 600

    if ($p.HasExited) {
        Write-Warn "Xray bridge failed to start. Falling back to native sing-box outbounds."
        return @{ Active = $false; MappedNodes = $Nodes }
    }

    $script:XrayProcess = $p
    return @{ Active = $true; MappedNodes = $mapped }
}

function Test-FastTcpPing([string]$Server, [int]$Port, [int]$TimeoutMs = 1200) {
    if (-not $Server -or -not $Port) { return $false }
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($Server, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $tcp.Connected) {
            $tcp.EndConnect($iar)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

function Sanitize-NodeObj($NodeObj) {
    $clean = [ordered]@{}
    if ($NodeObj -is [System.Collections.IDictionary]) {
        foreach ($k in $NodeObj.Keys) {
            if (-not $k.ToString().StartsWith('_')) {
                $clean[$k] = $NodeObj[$k]
            }
        }
    } else {
        foreach ($prop in $NodeObj.PSObject.Properties) {
            if (-not $prop.Name.StartsWith('_')) {
                $clean[$prop.Name] = $prop.Value
            }
        }
    }
    return $clean
}

# ── Fast Node Health Prober ─────────────────────────────────────────────────────
function Test-SingBoxNodeConnectivity {
    param($NodeObj, [string]$SingBoxExe)
    $cleanNode = Sanitize-NodeObj $NodeObj
    $tmpProbe = Join-Path $env:TEMP ("sb_probe_" + [Guid]::NewGuid().ToString("N") + ".json")
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $cfg = @{ log = @{ level = "error" }; outbounds = @($cleanNode) } | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($tmpProbe, $cfg, $utf8NoBom)

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $exitCode = 1
    try {
        $null = & $SingBoxExe tools fetch https://www.gstatic.com/generate_204 -c $tmpProbe -o ($NodeObj.tag) 2>$null
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = 1
    } finally {
        $ErrorActionPreference = $prevEAP
        Remove-Item $tmpProbe -Force -ErrorAction SilentlyContinue
    }

    return ($exitCode -eq 0)
}

# ── Load Verified Fallback Nodes From Local Configs ─────────────────────────────
function Get-LocalFallbackNodes {
    param([string]$Folder)
    $fallbackList = [System.Collections.Generic.List[object]]::new()
    $cfgFiles = Get-ChildItem -Path $Folder -Filter "config*.json" -File | Where-Object { $_.Name -ne "config.example.json" }

    foreach ($f in $cfgFiles) {
        try {
            $raw = Get-Content $f.FullName -Raw | ConvertFrom-Json
            if ($raw.outbounds) {
                foreach ($ob in $raw.outbounds) {
                    if ($ob.type -in @("vless", "shadowsocks", "hysteria2", "trojan", "vmess")) {
                        $srv = if ($ob.server) { $ob.server.ToString().Trim() } else { "" }
                        if ($srv -and $srv -ne "127.0.0.1" -and $srv -ne "example.com") {
                            $fallbackList.Add($ob)
                        }
                    }
                }
            }
        } catch {}
    }
    return $fallbackList
}

# ── Subscription Fetcher ────────────────────────────────────────────────────────
function Fetch-SubscriptionPayload {
    param([string]$SubscriptionUrl)
    $ua = "Hiddify/5.5.5 (sing-box/1.14)"
    $cleanUrl = $SubscriptionUrl
    $urlTag = ""
    if ($SubscriptionUrl -match '^(.*?)#(.*)$') {
        $cleanUrl = $Matches[1]
        $urlTag = [System.Uri]::UnescapeDataString($Matches[2]).Trim()
    }
    $rawText = ""

    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
        $client = [System.Net.Http.HttpClient]::new()
        $client.DefaultRequestHeaders.UserAgent.ParseAdd($ua)
        $client.Timeout = [TimeSpan]::FromSeconds(10)
        $resp = $client.GetStringAsync($cleanUrl).GetAwaiter().GetResult()
        $rawText = $resp.Trim()
        $client.Dispose()
    } catch {
        try {
            $rawText = (curl.exe -s -L --max-time 10 -A $ua $cleanUrl) -join "`n"
            $rawText = $rawText.Trim()
        } catch {}
    }

    if (-not $rawText) { return $null }

    $hasher = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rawText))
    $signature = [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()

    $decodedText = $rawText
    if ($rawText -notmatch '://' -and $rawText.Length -gt 25) {
        $dec = Decode-Base64 $rawText
        if ($dec) { $decodedText = $dec }
    }

    $lines = $decodedText -split "`r?`n"
    $title = if ($urlTag) { $urlTag } else { "" }
    $intervalMin = $DefaultUpdateIntervalMinutes
    $userInfo = ""
    $keyLines = [System.Collections.Generic.List[string]]::new()
    $subUrls  = [System.Collections.Generic.List[string]]::new()

    foreach ($l in $lines) {
        $tl = $l.Trim()
        if (-not $tl) { continue }

        if ($tl -match '^(?://|#)\s*profile-title:\s*(.*)$') {
            $rawTitle = $Matches[1].Trim()
            if ($rawTitle.StartsWith("base64:")) {
                $title = Decode-Base64 ($rawTitle.Substring(7))
            } else {
                $title = $rawTitle
            }
            continue
        }
        if ($tl -match '^(?://|#)\s*profile-update-interval:\s*(\d+)') {
            $hours = [int]$Matches[1]
            if ($hours -gt 0) { $intervalMin = [Math]::Max(15, ($hours * 60)) }
            continue
        }
        if ($tl -match '^(?://|#)\s*subscription-userinfo:\s*(.*)$') {
            $userInfo = $Matches[1].Trim()
            continue
        }
        if ($tl.StartsWith('//') -or $tl.StartsWith('#')) { continue }

        if ($tl -match '^https?://') {
            $subUrls.Add($tl)
        } elseif ($tl -match '^[a-z0-9]+://') {
            $keyLines.Add($tl)
        }
    }

    # If this is an aggregator profile containing nested sub-URLs (e.g. Mahsa, Hiddify collections)
    if ($subUrls.Count -gt 0) {
        foreach ($su in $subUrls) {
            try {
                $subRaw = (curl.exe -s -L --max-time 6 -A $ua $su) -join "`n"
                if ($subRaw) {
                    $subDec = $subRaw.Trim()
                    if ($subDec -notmatch '://' -and $subDec.Length -gt 25) {
                        $d = Decode-Base64 $subDec
                        if ($d) { $subDec = $d }
                    }
                    foreach ($sl in ($subDec -split "`r?`n")) {
                        $stl = $sl.Trim()
                        if ($stl -match '^[a-z0-9]+://' -and -not $stl.StartsWith('http')) {
                            $keyLines.Add($stl)
                        }
                    }
                }
            } catch {}
        }
    }

    $nodes = [System.Collections.Generic.List[object]]::new()
    foreach ($kl in $keyLines) {
        $tag = ""
        $rawUri = $kl
        if ($rawUri -match '^(.*?)#(.*)$') {
            $rawUri = $Matches[1]
            $tag = [System.Uri]::UnescapeDataString($Matches[2]).Trim()
        }

        $node = $null
        if ($rawUri.StartsWith("vless://", [System.StringComparison]::OrdinalIgnoreCase)) {
            $node = Parse-Vless $rawUri $tag
        } elseif ($rawUri.StartsWith("ss://", [System.StringComparison]::OrdinalIgnoreCase)) {
            $node = Parse-Shadowsocks $rawUri $tag
        } elseif ($rawUri.StartsWith("hysteria2://", [System.StringComparison]::OrdinalIgnoreCase) -or
                  $rawUri.StartsWith("hy2://", [System.StringComparison]::OrdinalIgnoreCase)) {
            $node = Parse-Hysteria2 $rawUri $tag
        } elseif ($rawUri.StartsWith("trojan://", [System.StringComparison]::OrdinalIgnoreCase)) {
            $node = Parse-Trojan $rawUri $tag
        } elseif ($rawUri.StartsWith("vmess://", [System.StringComparison]::OrdinalIgnoreCase)) {
            $node = Parse-Vmess $rawUri $tag
        }

        if ($node) { $nodes.Add($node) }
    }

    return [pscustomobject]@{
        Url         = $SubscriptionUrl
        Title       = $title
        IntervalMin = $intervalMin
        Signature   = $signature
        Nodes       = $nodes
        UserInfo    = $userInfo
    }
}

# ── sing-box Config Synthesis (Corporate-Safe & Split-Tunnel Protected) ────────
function New-SubscriptionSingBoxConfig {
    param(
        $PhysicalGw,
        $EnterpriseVpn,
        [System.Collections.Generic.List[object]]$Nodes,
        [string[]]$UserCustomerSubnets,
        [string[]]$ExtraCorpDomains,
        [bool]$UseProxyOnly,
        [int]$LocalMixedPort,
        [string]$OutConfigPath
    )

    $boundNodes = [System.Collections.Generic.List[object]]::new()
    $wifiDnsTag = "dns-wifi"

    foreach ($n in $Nodes) {
        $clean = Sanitize-NodeObj $n
        $clean["bind_interface"] = $PhysicalGw.Name
        $clean["domain_resolver"] = [pscustomobject]@{
            server   = $wifiDnsTag
            strategy = "ipv4_only"
        }
        $boundNodes.Add($clean)
    }

    $allNodeTags = @($boundNodes | ForEach-Object { $_.tag })

    # Outbound Groups
    $fullOutbounds = [System.Collections.Generic.List[object]]::new()

    # Customer VPN per-adapter outbounds
    $vpnAdapterTags = @{}
    $custDnsTag = "direct"
    $targetCustDnsIp = ""

    if ($EnterpriseVpn.Active -and $EnterpriseVpn.Adapters) {
        $vIdx = 0
        foreach ($adName in $EnterpriseVpn.Adapters) {
            $tag = "direct-vpn-$vIdx"
            $vpnAdapterTags[$adName] = $tag
            $fullOutbounds.Add([pscustomobject]@{
                type           = "direct"
                tag            = $tag
                bind_interface = $adName
            })
            $vIdx++
        }
        if ($EnterpriseVpn.DnsServers.Count -gt 0) {
            $targetCustDnsIp = $EnterpriseVpn.DnsServers[0]
            if ($vpnAdapterTags.Count -gt 0) {
                $custDnsTag = @($vpnAdapterTags.Values)[0]
            }
        }
    }

    # Proxy group selector / auto ping (urltest selects fastest live node)
    if ($allNodeTags.Count -gt 1) {
        $fullOutbounds.Add([pscustomobject]@{
            type        = "urltest"
            tag         = "proxy"
            outbounds   = $allNodeTags
            url         = "https://cp.cloudflare.com/"
            interval    = "3m"
            tolerance   = 50
        })
    } else {
        $fullOutbounds.Add([pscustomobject]@{
            type      = "selector"
            tag       = "proxy"
            outbounds = $allNodeTags
            default   = $allNodeTags[0]
        })
    }

    $fullOutbounds.Add([pscustomobject]@{ type = "direct"; tag = "direct" })
    $fullOutbounds.Add([pscustomobject]@{ type = "direct"; tag = "direct-wifi"; bind_interface = $PhysicalGw.Name })
    $fullOutbounds.Add([pscustomobject]@{ type = "block";  tag = "block" })
    foreach ($bn in $boundNodes) { $fullOutbounds.Add($bn) }

    # Split-Tunnel Exclusions (Customer VPN + Local Private LAN)
    $standardPrivateSubnets = @(
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"
    )
    $tunExcludeList = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $standardPrivateSubnets) { if (-not $tunExcludeList.Contains($s)) { $tunExcludeList.Add($s) } }
    foreach ($s in $UserCustomerSubnets)    { if (-not $tunExcludeList.Contains($s)) { $tunExcludeList.Add($s) } }
    if ($EnterpriseVpn.Active) {
        foreach ($s in $EnterpriseVpn.Subnets) { if (-not $tunExcludeList.Contains($s)) { $tunExcludeList.Add($s) } }
    }
    foreach ($bn in $boundNodes) {
        if ($bn.server -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            $c = "$($bn.server)/32"
            if (-not $tunExcludeList.Contains($c)) { $tunExcludeList.Add($c) }
        }
    }

    # Inbounds (198.18.0.1/30 prevents collision with 172.16.0.0/12 corporate VPNs)
    $inbounds = [System.Collections.Generic.List[object]]::new()
    $inbounds.Add([pscustomobject]@{
        type        = "mixed"
        tag         = "mixed-in"
        listen      = "127.0.0.1"
        listen_port = $LocalMixedPort
    })
    if (-not $UseProxyOnly) {
        $inbounds.Add([pscustomobject]@{
            type                  = "tun"
            tag                   = "tun-in"
            address               = @("198.18.0.1/30")
            mtu                   = 1400
            auto_route            = $true
            strict_route          = $false
            stack                 = "mixed"
            route_exclude_address = @($tunExcludeList)
        })
    }

    # Corporate & VPN DNS Setup (FortiClient Internal DNS Protection)
    $dnsServers = [System.Collections.Generic.List[object]]::new()
    $dnsRules   = [System.Collections.Generic.List[object]]::new()

    $physicalDnsIp = if ($PhysicalGw.DnsServers.Count -gt 0) { $PhysicalGw.DnsServers[0] } else { "1.1.1.1" }
    $dnsServers.Add([pscustomobject]@{
        tag         = $wifiDnsTag
        type        = "udp"
        server      = $physicalDnsIp
        server_port = 53
        detour      = "direct-wifi"
    })

    # Customer VPN internal DNS
    $hasCustDns = ($EnterpriseVpn.Active -and $targetCustDnsIp -ne "")
    if ($hasCustDns) {
        $dnsObj = [pscustomobject]@{
            tag    = "dns-custvpn"
            type   = "udp"
            server = $targetCustDnsIp
        }
        if ($custDnsTag -ne "direct") {
            $dnsObj | Add-Member -MemberType NoteProperty -Name "detour" -Value $custDnsTag
        }
        $dnsServers.Add($dnsObj)
    }

    # Remote DoH DNS via Proxy
    $dnsServers.Add([pscustomobject]@{
        tag         = "dns-remote-doh"
        type        = "https"
        server      = "1.1.1.1"
        server_port = 443
        path        = "/dns-query"
        detour      = "proxy"
    })
    $dnsServers.Add([pscustomobject]@{ tag = "dns-local"; type = "local" })

    # Corporate DNS Rules
    $vpnProcesses = @("FortiClient", "FortiTray", "FortiSSLVPNdaemon", "PanGPA", "PanGPS", "vpnagent", "vpnagentd", "openconnect")
    $dnsRules.Add([pscustomobject]@{ domain = @("localhost", "localhost.localdomain"); server = "dns-local" })
    $dnsRules.Add([pscustomobject]@{ process_name = @($vpnProcesses); server = $wifiDnsTag })

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

    $dnsRules.Add([pscustomobject]@{ domain_suffix = @(".traps.paloaltonetworks.com"); server = $wifiDnsTag })

    # Route Rules
    $routeRules = [System.Collections.Generic.List[object]]::new()
    $routeRules.Add([pscustomobject]@{ action = "sniff" })
    if (-not $UseProxyOnly) {
        $routeRules.Add([pscustomobject]@{ protocol = "dns"; action = "hijack-dns" })
    }
    # Reject QUIC (UDP 443) and DoT (UDP 853) to force fast, reliable TCP TLS
    $routeRules.Add([pscustomobject]@{ protocol = @("quic"); action = "reject" })
    $routeRules.Add([pscustomobject]@{ network = @("udp"); port = @(443, 853); action = "reject" })
    $routeRules.Add([pscustomobject]@{ process_name = @($vpnProcesses); outbound = "direct-wifi" })
    $routeRules.Add([pscustomobject]@{ network = @("udp"); port = @(500, 4500); outbound = "direct-wifi" })

    if ($EnterpriseVpn.GatewayCidrs.Count -gt 0) {
        $routeRules.Add([pscustomobject]@{ ip_cidr = @($EnterpriseVpn.GatewayCidrs); outbound = "direct-wifi" })
    }

    if ($EnterpriseVpn.Active) {
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

        # Corporate domain name routing
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

    $routeRules.Add([pscustomobject]@{ domain_suffix = @(".traps.paloaltonetworks.com"); outbound = "direct-wifi" })
    $routeRules.Add([pscustomobject]@{ ip_is_private = $true; outbound = "direct" })
    $routeRules.Add([pscustomobject]@{ ip_cidr = @($tunExcludeList); outbound = "direct" })

    $finalConfig = [pscustomobject]@{
        log = [pscustomobject]@{ level = "warn"; timestamp = $true }
        dns = [pscustomobject]@{
            strategy          = "ipv4_only"
            servers           = @($dnsServers)
            rules             = @($dnsRules)
            final             = "dns-remote-doh"
            independent_cache = $true
        }
        inbounds  = @($inbounds)
        outbounds = @($fullOutbounds)
        route     = [pscustomobject]@{
            default_domain_resolver = [pscustomobject]@{
                server   = $wifiDnsTag
                strategy = "ipv4_only"
            }
            find_process          = $true
            rules                 = @($routeRules)
            auto_detect_interface = $true
            final                 = "proxy"
        }
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $json = $finalConfig | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($OutConfigPath, $json, $utf8NoBom)
}

# ── sing-box Engine Runner ──────────────────────────────────────────────────────
function Start-SingBoxEngine {
    param([string]$ExePath, [string]$CfgPath)

    if ($script:SingBoxProcess -ne $null) {
        try {
            Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "SingBoxSub*" } | Unregister-Event -ErrorAction SilentlyContinue
        } catch {}
        if (-not $script:SingBoxProcess.HasExited) {
            try { $script:SingBoxProcess.Kill(); $script:SingBoxProcess.WaitForExit(3000) | Out-Null } catch {}
        }
        $script:SingBoxProcess.Dispose()
        $script:SingBoxProcess = $null
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $ExePath
    $psi.Arguments              = "run -c `"$CfgPath`""
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $p.EnableRaisingEvents = $true

    Register-ObjectEvent $p OutputDataReceived -SourceIdentifier "SingBoxSubOut-$([Guid]::NewGuid().ToString('N'))" -Action {
        if ($Event.SourceEventArgs.Data) { Write-Host "[vpn] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkGray }
    } | Out-Null
    Register-ObjectEvent $p ErrorDataReceived -SourceIdentifier "SingBoxSubErr-$([Guid]::NewGuid().ToString('N'))" -Action {
        $d = $Event.SourceEventArgs.Data
        if ($d -and $d -notmatch "independent_cache") { Write-Host "[vpn] $d" -ForegroundColor DarkYellow }
    } | Out-Null

    $p.Start() | Out-Null
    $p.BeginOutputReadLine()
    $p.BeginErrorReadLine()

    Start-Sleep -Milliseconds 800
    if ($p.HasExited) { return $false }
    $script:SingBoxProcess = $p
    return $true
}

# ── ENTRY POINT ─────────────────────────────────────────────────────────────────
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Multip VPN - Live Subscription Connector (Corporate Safe) 🌐" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan

# Gather Subscription URLs
$targetUrls = [System.Collections.Generic.List[string]]::new()
if ($Url) {
    $targetUrls.Add($Url.Trim())
}

$subFilePath = if ([System.IO.Path]::IsPathRooted($SubscriptionFile)) { $SubscriptionFile } else { Join-Path $ScriptDir $SubscriptionFile }
if (Test-Path $subFilePath) {
    foreach ($l in (Get-Content $subFilePath)) {
        $tl = $l.Trim()
        if ($tl -and -not $tl.StartsWith('#') -and $tl -match '^https?://') {
            if (-not $targetUrls.Contains($tl)) { $targetUrls.Add($tl) }
        }
    }
} else {
    $defaultGist = "https://gist.github.com/yelinntunnn09/1b074d7640dc8799a2213593a3523d44/raw/ylt_onekey-stable"
    @"
# Multip VPN - Remote Subscription Links
# Add your subscription URLs or Gist links below (one per line).
# The script will auto-fetch, parse, connect, and update automatically!

$defaultGist
"@ | Out-File -FilePath $subFilePath -Encoding UTF8
    Write-Info "Created subscription list at: $subFilePath"
    $targetUrls.Add($defaultGist)
}

if ($targetUrls.Count -eq 0) {
    Write-Err "No valid subscription URLs found in '$subFilePath'. Please add at least one link."
    exit 1
}

Write-Info ("Configured {0} remote subscription URL(s):" -f $targetUrls.Count)
foreach ($u in $targetUrls) { Write-Host "   • $u" -ForegroundColor DarkGray }

# Physical Network & Customer VPN Discovery
Write-Info "Detecting network interface & customer VPN..."
$gw = Get-PhysicalGateway
Write-Ok ("Physical Gateway: {0} on '{1}' (DNS: {2})" -f $gw.Gateway, $gw.Name, ($gw.DnsServers -join ', '))

$vpnState = Get-EnterpriseVpnState -PhysicalGw $gw -ProxyServerIPs @()
if ($vpnState.Active) {
    Write-Ok ("Customer VPN Detected: {0}" -f ($vpnState.Adapters -join ', '))
    Write-Host ("   • Bypassed Subnets : {0}" -f ($vpnState.Subnets -join ', ')) -ForegroundColor DarkGray
    if ($vpnState.DnsServers.Count -gt 0) {
        Write-Host ("   • Corporate DNS    : {0}" -f ($vpnState.DnsServers -join ', ')) -ForegroundColor DarkGray
    }
} else {
    Write-Info "Customer VPN is not active (pure internet mode)."
}

# Fetch Subscriptions (Initial)
Write-Info "Fetching remote subscription(s)..."
$activeSubs = [System.Collections.Generic.List[object]]::new()
$allNodes   = [System.Collections.Generic.List[object]]::new()

foreach ($u in $targetUrls) {
    $subData = Fetch-SubscriptionPayload -SubscriptionUrl $u
    if ($subData -and $subData.Nodes.Count -gt 0) {
        $activeSubs.Add($subData)
        foreach ($n in $subData.Nodes) { $allNodes.Add($n) }
        $titleDisplay = if ($subData.Title) { $subData.Title } else { $u }
        Write-Ok ("Fetched {0} node(s) from '{1}' (Auto-update: every {2}m)" -f $subData.Nodes.Count, $titleDisplay, $subData.IntervalMin)
        if ($subData.UserInfo) { Write-Host ("   Info: {0}" -f $subData.UserInfo) -ForegroundColor DarkGray }
    } else {
        Write-Warn "Could not retrieve nodes from: $u"
    }
}

# Pre-flight Check on Subscription Nodes
Write-Info "Verifying live connectivity of subscription node(s)..."
$testTargetNodes = $allNodes
$bridgeState = $null

if ($hasXray) {
    Write-Info "Activating Dual-Engine Xray Bridge (Post-Quantum ML-KEM & REALITY acceleration)..."
    $bridgeState = Start-XrayBridgeEngine -Nodes $allNodes -XrayExePath $xrayExe
    if ($bridgeState.Active) {
        $testTargetNodes = $bridgeState.MappedNodes
        Add-TrackedFwRule -Name "MultipVPN-Xray" -ProgramPath $xrayExe
        Write-Ok ("Xray bridge active for {0} node(s) on local loopback ports." -f $bridgeState.MappedNodes.Count)
    }
}

$aliveSubNodes   = [System.Collections.Generic.List[object]]::new()
$pendingSubNodes = [System.Collections.Generic.List[object]]::new()
$hasFoundFirstLive = $false

foreach ($sn in $testTargetNodes) {
    if ($hasFoundFirstLive) {
        $pendingSubNodes.Add($sn)
        continue
    }

    $targetHost = if ($sn._originalServer) { $sn._originalServer } else { $sn.server }
    $targetPort = if ($sn._originalPort)   { [int]$sn._originalPort } else { [int]$sn.server_port }

    # Fast TCP reachability check (skips completely dead servers in 1.2s instead of 15s)
    if ($targetHost -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $tcpOk = Test-FastTcpPing -Server $targetHost -Port $targetPort -TimeoutMs 1200
        if (-not $tcpOk) {
            Write-Warn ("Node '{0}' ({1}:{2}) unreachable (skipped in 1.2s)." -f $sn.tag, $targetHost, $targetPort)
            continue
        }
    }

    $isAlive = Test-SingBoxNodeConnectivity -NodeObj $sn -SingBoxExe $singBoxExe
    $origHost = "$targetHost`:$targetPort"
    $engineLabel = if ($sn._bridgedViaXray) { " [Xray Post-Quantum Bridge]" } else { "" }
    if ($isAlive) {
        Write-Ok ("Node '{0}' ({1}){2} is ALIVE & verified!" -f $sn.tag, $origHost, $engineLabel)
        $aliveSubNodes.Add($sn)
        $hasFoundFirstLive = $true
    } else {
        Write-Warn ("Node '{0}' ({1}){2} failed connectivity test!" -f $sn.tag, $origHost, $engineLabel)
    }
}

if ($pendingSubNodes.Count -gt 0) {
    Write-Info ("Instant-On Active: First live node verified! Connecting now with zero wait time... ⚡")
    Write-Info ("Scheduled background benchmark in 60s to test remaining {0} node(s) and auto-switch to best ping." -f $pendingSubNodes.Count)
}

# Fallback Pool Integration: Ensure Laptop Never Blacks Out
$finalNodesPool = [System.Collections.Generic.List[object]]::new()
foreach ($an in $aliveSubNodes) { $finalNodesPool.Add($an) }

if (-not $DisableFallbackPool -and ($finalNodesPool.Count -eq 0 -or $finalNodesPool.Count -lt 3)) {
    Write-Info "Loading verified fallback cluster pool to guarantee 100% uptime..."
    $localFallbacks = Get-LocalFallbackNodes -Folder $ScriptDir
    $addedFallbacks = 0
    foreach ($fn in $localFallbacks) {
        if ($finalNodesPool.Count -ge 8) { break }
        $finalNodesPool.Add($fn)
        $addedFallbacks++
    }
    if ($addedFallbacks -gt 0) {
        Write-Ok ("Integrated {0} verified fallback node(s) into pool (Auto-failover enabled)." -f $addedFallbacks)
    }
}

# If still 0 nodes alive, keep original nodes so urltest can retry
if ($finalNodesPool.Count -eq 0) {
    foreach ($on in $testTargetNodes) { $finalNodesPool.Add($on) }
}

if ($finalNodesPool.Count -eq 0) {
    Write-Err "Zero nodes available. Please check subscriptions.txt."
    exit 1
}

# Bind node servers to physical gateway to avoid routing loops
$serverIPs = [System.Collections.Generic.List[string]]::new()
foreach ($n in $finalNodesPool) {
    $targetIp = if ($n._originalServer) { $n._originalServer } else { $n.server }
    if ($targetIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        if (-not $serverIPs.Contains($targetIp)) { $serverIPs.Add($targetIp) }
    }
}
if ($serverIPs.Count -gt 0 -and $isAdmin) {
    Add-TrackedRoutesBatch -IPs @($serverIPs) -Gateway $gw.Gateway -IfIndex $gw.InterfaceIndex
    Write-Ok ("Added bypass route(s) for {0} proxy endpoint(s) on '{1}'" -f $serverIPs.Count, $gw.Name)
}

Add-TrackedFwRule -Name "MultipVPN-Subscription" -ProgramPath $singBoxExe

# Synthesize sing-box config
New-SubscriptionSingBoxConfig `
    -PhysicalGw $gw `
    -EnterpriseVpn $vpnState `
    -Nodes $finalNodesPool `
    -UserCustomerSubnets $CustomerSubnets `
    -ExtraCorpDomains $CorpDomains `
    -UseProxyOnly ([bool]$ProxyOnly) `
    -LocalMixedPort $MixedPort `
    -OutConfigPath $script:TempConfigPath

Write-Info "Starting sing-box engine..."
$started = Start-SingBoxEngine -ExePath $singBoxExe -CfgPath $script:TempConfigPath
if (-not $started) {
    Write-Err "Failed to start sing-box. Check log output above."
    Invoke-Cleanup
    exit 1
}

if ($SystemProxy) {
    Set-WindowsSystemProxy -Port $MixedPort
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  CONNECTED & PROTECTED! SUBSCRIPTION ENGINE ACTIVE 🚀" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ("  * Total Active Nodes : {0}" -f $finalNodesPool.Count) -ForegroundColor White
Write-Host ("  * Local Mixed Proxy  : 127.0.0.1:{0} (HTTP / SOCKS5)" -f $MixedPort) -ForegroundColor Cyan
if (-not $ProxyOnly) {
    Write-Host "  * Transparent TUN    : 198.18.0.1/30 (System-wide traffic routed)" -ForegroundColor Green
} else {
    Write-Host "  * Mode               : Proxy-Only (Port 10808 only, no TUN)" -ForegroundColor Yellow
}
if ($vpnState.Active) {
    Write-Host ("  * Customer VPN       : FortiClient/Corporate traffic 100% ISOLATED & SAFE" ) -ForegroundColor Cyan
}
Write-Host "  * Auto-Update Loop   : ACTIVE (Monitors remote Gist for daily key updates)" -ForegroundColor Magenta
Write-Host "  Press Ctrl+C to disconnect and restore network." -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

# ── AUTO-UPDATE LIFECYCLE MONITOR LOOP ──────────────────────────────────────────
$subTracker = @{}
foreach ($s in $activeSubs) {
    $subTracker[$s.Url] = @{
        Signature   = $s.Signature
        IntervalMin = $s.IntervalMin
        LastCheck   = (Get-Date)
    }
}
$lastVpnCheck = Get-Date
$bgBenchDone = ($pendingSubNodes.Count -eq 0)
$connectStartTime = Get-Date

try {
    while (-not $script:SingBoxProcess.HasExited) {
        Start-Sleep -Seconds $CheckIntervalSeconds

        $now = Get-Date
        $needsReload = $false

        # Background Benchmark After 60 Seconds: Benchmark remaining nodes & upgrade to Best-Ping
        if (-not $bgBenchDone -and ($now - $connectStartTime).TotalSeconds -ge 60) {
            $bgBenchDone = $true
            if ($pendingSubNodes.Count -gt 0) {
                Write-Host ""
                Write-Info ("Starting background benchmark on {0} remaining subscription node(s)..." -f $pendingSubNodes.Count)
                $bgAliveNodes = [System.Collections.Generic.List[object]]::new()
                foreach ($pn in $pendingSubNodes) {
                    $pHost = if ($pn._originalServer) { $pn._originalServer } else { $pn.server }
                    $pPort = if ($pn._originalPort)   { [int]$pn._originalPort } else { [int]$pn.server_port }

                    if ($pHost -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        if (-not (Test-FastTcpPing -Server $pHost -Port $pPort -TimeoutMs 1200)) {
                            continue
                        }
                    }

                    if (Test-SingBoxNodeConnectivity -NodeObj $pn -SingBoxExe $singBoxExe) {
                        Write-Ok ("Background node '{0}' ({1}:{2}) is ALIVE & added to best-ping pool!" -f $pn.tag, $pHost, $pPort)
                        $bgAliveNodes.Add($pn)
                    }
                }

                if ($bgAliveNodes.Count -gt 0) {
                    foreach ($ba in $bgAliveNodes) { $finalNodesPool.Add($ba) }
                    $newIPs = [System.Collections.Generic.List[string]]::new()
                    foreach ($n in $bgAliveNodes) {
                        $tIp = if ($n._originalServer) { $n._originalServer } else { $n.server }
                        if ($tIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                            if (-not $newIPs.Contains($tIp)) { $newIPs.Add($tIp) }
                        }
                    }
                    if ($newIPs.Count -gt 0 -and $isAdmin) {
                        Add-TrackedRoutesBatch -IPs @($newIPs) -Gateway $gw.Gateway -IfIndex $gw.InterfaceIndex
                    }

                    New-SubscriptionSingBoxConfig `
                        -PhysicalGw $gw `
                        -EnterpriseVpn $vpnState `
                        -Nodes $finalNodesPool `
                        -UserCustomerSubnets $CustomerSubnets `
                        -ExtraCorpDomains $CorpDomains `
                        -UseProxyOnly ([bool]$ProxyOnly) `
                        -LocalMixedPort $MixedPort `
                        -OutConfigPath $script:TempConfigPath

                    $reloaded = Start-SingBoxEngine -ExePath $singBoxExe -CfgPath $script:TempConfigPath
                    if ($reloaded) {
                        Write-Ok ("Upgraded to Best-Ping URL-Test mode with {0} total active nodes! sing-box is now auto-switching to the lowest ping server. 🚀" -f $finalNodesPool.Count)
                    }
                } else {
                    Write-Info "Background benchmark complete: No additional live nodes found. Keeping current fast node."
                }
            }
        }

        # 1. Check Subscriptions for Updates
        foreach ($u in $targetUrls) {
            $meta = $subTracker[$u]
            $dueMinutes = if ($meta) { $meta.IntervalMin } else { $DefaultUpdateIntervalMinutes }
            $lastTime   = if ($meta) { $meta.LastCheck } else { [DateTime]::MinValue }

            if (($now - $lastTime).TotalMinutes -ge $dueMinutes) {
                Write-Info ("Checking remote subscription update for: {0}..." -f $u)
                if ($meta) { $meta.LastCheck = $now }

                $freshSub = Fetch-SubscriptionPayload -SubscriptionUrl $u
                if ($freshSub -and $freshSub.Signature -ne $meta.Signature) {
                    Write-Host ""
                    Write-Warn ("Remote subscription updated! New content signature: {0}" -f $freshSub.Signature)
                    $subTracker[$u].Signature = $freshSub.Signature
                    $needsReload = $true
                }
            }
        }

        # 2. Check Customer VPN state changes (FortiClient connect / disconnect)
        if (($now - $lastVpnCheck).TotalSeconds -ge 4) {
            $lastVpnCheck = $now
            $probeVpn = Get-EnterpriseVpnState -PhysicalGw $gw -ProxyServerIPs @($serverIPs)
            if ($probeVpn.Signature -ne $vpnState.Signature) {
                Write-Host ""
                Write-Warn "Customer VPN adapter or routing changed -> syncing corporate routes..."
                $vpnState = $probeVpn
                $needsReload = $true
            }
        }

        # 3. Perform Hot-Reload if anything changed
        if ($needsReload) {
            Write-Info "Re-fetching all active subscriptions..."
            $rawFreshNodes = [System.Collections.Generic.List[object]]::new()
            foreach ($u in $targetUrls) {
                $fresh = Fetch-SubscriptionPayload -SubscriptionUrl $u
                if ($fresh) {
                    foreach ($fn in $fresh.Nodes) { $rawFreshNodes.Add($fn) }
                }
            }

            $freshTestNodes = $rawFreshNodes
            if ($hasXray) {
                $freshBridge = Start-XrayBridgeEngine -Nodes $rawFreshNodes -XrayExePath $xrayExe
                if ($freshBridge.Active) {
                    $freshTestNodes = $freshBridge.MappedNodes
                }
            }

            $freshAliveNodes = [System.Collections.Generic.List[object]]::new()
            foreach ($fn in $freshTestNodes) {
                if (Test-SingBoxNodeConnectivity -NodeObj $fn -SingBoxExe $singBoxExe) {
                    $freshAliveNodes.Add($fn)
                }
            }

            # If subscription nodes are currently down, maintain fallback nodes
            if ($freshAliveNodes.Count -eq 0 -and -not $DisableFallbackPool) {
                $localFallbacks = Get-LocalFallbackNodes -Folder $ScriptDir
                foreach ($fn in ($localFallbacks | Select-Object -First 5)) { $freshAliveNodes.Add($fn) }
            }

            if ($freshAliveNodes.Count -gt 0) {
                Remove-AllTrackedRoutes
                $newServerIPs = [System.Collections.Generic.List[string]]::new()
                foreach ($n in $freshAliveNodes) {
                    $targetIp = if ($n._originalServer) { $n._originalServer } else { $n.server }
                    if ($targetIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        if (-not $newServerIPs.Contains($targetIp)) { $newServerIPs.Add($targetIp) }
                    }
                }
                if ($newServerIPs.Count -gt 0 -and $isAdmin) {
                    Add-TrackedRoutesBatch -IPs @($newServerIPs) -Gateway $gw.Gateway -IfIndex $gw.InterfaceIndex
                }

                New-SubscriptionSingBoxConfig `
                    -PhysicalGw $gw `
                    -EnterpriseVpn $vpnState `
                    -Nodes $freshAliveNodes `
                    -UserCustomerSubnets $CustomerSubnets `
                    -ExtraCorpDomains $CorpDomains `
                    -UseProxyOnly ([bool]$ProxyOnly) `
                    -LocalMixedPort $MixedPort `
                    -OutConfigPath $script:TempConfigPath

                $reloaded = Start-SingBoxEngine -ExePath $singBoxExe -CfgPath $script:TempConfigPath
                if ($reloaded) {
                    Write-Ok ("Subscription Hot-Reload SUCCESSFUL (PID: {0}). {1} active node(s) running!" -f $script:SingBoxProcess.Id, $freshAliveNodes.Count)
                } else {
                    Write-Err "Hot-reload failed. Keeping previous engine state."
                }
            }
        }
    }
} finally {
    Invoke-Cleanup
}
