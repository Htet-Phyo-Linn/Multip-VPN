#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Universal Hiddify/sing-box Connect Script with Automatic Split-Tunneling
    - NO hardcoded server names, IPs, or outbound tags.
    - Inspects any exported Hiddify JSON dynamically.
    - Resolves all server endpoints (domains and direct IPs) across all nodes.
    - Bypasses Customer VPNs (FortiClient, AnyConnect) for all server endpoints.
    - System-wide transparent TUN mode (no manual proxy variables needed).
    - Automatically cleans up all routes, firewall rules, and adapters on exit (Ctrl+C).

.USAGE
    .\connect-hiddify.ps1
    .\connect-hiddify.ps1 -ConfigPath "C:\path\to\exported_hiddify.json"
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [string]$SingBoxPath = "",
    [string[]]$CustomerSubnets = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
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
    Write-Warn "TUN mode requires Administrator permissions."
    Write-Info "Re-launching elevated (UAC prompt)..."
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($ConfigPath)  { $argList += " -ConfigPath `"$ConfigPath`"" }
    if ($SingBoxPath) { $argList += " -SingBoxPath `"$SingBoxPath`"" }
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit 0
}

# ── Tracking for Clean Exit ───────────────────────────────────────────────────
$CreatedFirewallRules = New-Object System.Collections.Generic.List[string]
$CreatedRoutes        = New-Object System.Collections.Generic.List[object]
$SingBoxProcess       = $null
$TempConfigPath       = ""

# ── Cleanup Routine ───────────────────────────────────────────────────────────
function Invoke-Cleanup {
    Write-Host ""
    Write-Info "Shutting down... Restoring network..."

    # 1. Kill sing-box (destroys TUN interface and Windows auto-routes)
    if ($SingBoxProcess -ne $null -and -not $SingBoxProcess.HasExited) {
        try {
            $SingBoxProcess.Kill()
            $SingBoxProcess.WaitForExit(3000)
            Write-Ok "sing-box stopped (TUN adapter removed)."
        } catch {}
    }
    Get-Process -Name "sing-box" -ErrorAction SilentlyContinue |
        ForEach-Object { try { $_.Kill() } catch {} }

    # 2. Remove all added static bypass routes
    if ($CreatedRoutes.Count -gt 0) {
        Write-Info "Removing $($CreatedRoutes.Count) static bypass route(s)..."
        foreach ($r in $CreatedRoutes) {
            try {
                Remove-NetRoute -DestinationPrefix $r.Prefix -NextHop $r.Gateway `
                                -Confirm:$false -ErrorAction SilentlyContinue
                Write-Ok "  Removed route: $($r.Prefix) via $($r.Gateway)"
            } catch {}
        }
    }

    # 3. Remove all added firewall rules
    if ($CreatedFirewallRules.Count -gt 0) {
        Write-Info "Removing $($CreatedFirewallRules.Count) firewall rule(s)..."
        foreach ($rule in $CreatedFirewallRules) {
            try {
                Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
                Write-Ok "  Removed rule: $rule"
            } catch {}
        }
    }

    # 4. Remove temporary configuration
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
    # Fallback to the first active default route
    $best = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1
    if ($best -and $best.NextHop -ne "0.0.0.0") {
        $adapter = Get-NetAdapter -InterfaceIndex $best.InterfaceIndex -ErrorAction SilentlyContinue
        return @{ Gateway = $best.NextHop; IfIndex = $best.InterfaceIndex; Name = $adapter.Name }
    }
    return $null
}

# ── Firewall Helper ───────────────────────────────────────────────────────────
function Add-FwRule {
    param($Name, $Direction, $Protocol, $RemoteAddress)
    try {
        $p = @{ DisplayName = $Name; Direction = $Direction; Action = "Allow"; Enabled = "True"; Profile = "Any" }
        if ($Protocol)      { $p.Protocol      = $Protocol }
        if ($RemoteAddress) { $p.RemoteAddress  = $RemoteAddress }
        New-NetFirewallRule @p -ErrorAction Stop | Out-Null
        $CreatedFirewallRules.Add($Name)
        Write-Ok "  FW rule: $Name"
    } catch { Write-Warn "  FW rule ($Name): $_" }
}

# ── Static Route Helper ───────────────────────────────────────────────────────
function Add-Route {
    param($Prefix, $Gateway, $IfIndex, $Metric = 5)
    try {
        Remove-NetRoute -DestinationPrefix $Prefix -NextHop $Gateway -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $Prefix -NextHop $Gateway `
                     -InterfaceIndex $IfIndex -RouteMetric $Metric `
                     -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $CreatedRoutes.Add([pscustomobject]@{ Prefix = $Prefix; Gateway = $Gateway })
        Write-Ok "  Bypass route: $Prefix via $Gateway"
    } catch { Write-Warn "  Route ($Prefix): $_" }
}

# ══════════════════════════════════════════════════════════════════════════════
#  DYNAMIC INSPECTION & PARSER ENGINE
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Universal Hiddify Connect - Dynamic TUN Split Tunnel" -ForegroundColor Cyan
Write-Host "   Zero Hardcoding * Auto Endpoint Discovery * AnyConnect/Forti Safe" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Locate sing-box executable
$singBoxExe = Find-SingBox
if (-not $singBoxExe) {
    Write-Err "sing-box.exe not found! Run .\install-singbox.ps1 first."
    exit 1
}
Write-Ok "sing-box binary: $singBoxExe"

# 2. Check and load JSON
if (-not (Test-Path $ConfigPath)) {
    Write-Err "Config file not found: $ConfigPath"
    Write-Err "Place your exported Hiddify JSON at: $ConfigPath"
    exit 1
}
Write-Ok "Reading JSON: $ConfigPath"

$rawContent = Get-Content $ConfigPath -Raw -Encoding UTF8
$rawConfig = $rawContent | ConvertFrom-Json

# 3. Extract outbounds
$allOutbounds = if ($rawConfig.PSObject.Properties["outbounds"]) { @($rawConfig.outbounds) } else { @($rawConfig) }
if (-not $allOutbounds -or $allOutbounds.Count -eq 0) {
    Write-Err "No outbounds detected in $ConfigPath!"
    exit 1
}
Write-Info "Found $($allOutbounds.Count) outbound definitions."

# Clean outbounds: remove deprecated dns outbound type
$cleanOutbounds = @($allOutbounds | Where-Object { $_.type -ne "dns" })
if (-not ($cleanOutbounds | Where-Object { $_.tag -eq "direct" })) {
    $cleanOutbounds += [pscustomobject]@{ type = "direct"; tag = "direct" }
}
if (-not ($cleanOutbounds | Where-Object { $_.tag -eq "block" })) {
    $cleanOutbounds += [pscustomobject]@{ type = "block"; tag = "block" }
}

# 4. Dynamically detect the Main Outbound Tag (selector or urltest)
$mainTag = $null
$selectors = @($cleanOutbounds | Where-Object { $_.type -eq "selector" })
if ($selectors.Count -gt 0) {
    # Check for conventional group names first
    $candidate = $selectors | Where-Object { $_.tag -in @("proxy", "select", "auto", "Default", "Internet") } | Select-Object -First 1
    if ($candidate) {
        $mainTag = $candidate.tag
    } else {
        $mainTag = $selectors[0].tag
    }
} else {
    $urltests = @($cleanOutbounds | Where-Object { $_.type -eq "urltest" })
    if ($urltests.Count -gt 0) {
        $mainTag = $urltests[0].tag
    } else {
        $firstProxy = $cleanOutbounds | Where-Object { $_.type -notin @("direct", "block", "dns") } | Select-Object -First 1
        if ($firstProxy) { $mainTag = $firstProxy.tag } else { $mainTag = "direct" }
    }
}
Write-Ok "Main outbound entry point: '$mainTag'"

# 5. Dynamically extract all server hostnames and direct IPs
$detectedServerHosts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($ob in $cleanOutbounds) {
    if ($ob.PSObject.Properties["server"] -and $ob.server) {
        $srv = $ob.server.ToString().Trim()
        if ($srv -ne "") { $null = $detectedServerHosts.Add($srv) }
    }
}

Write-Info "Discovered $($detectedServerHosts.Count) unique server endpoint(s):"
foreach ($srv in $detectedServerHosts) {
    Write-Host "   - $srv" -ForegroundColor White
}

# 6. Resolve all endpoints to IPv4 addresses & build hosts map
Write-Info "Resolving endpoints..."
$hostsMap = [pscustomobject]@{}
$allResolvedIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($srv in $detectedServerHosts) {
    $parsedIP = $null
    if ([System.Net.IPAddress]::TryParse($srv, [ref]$parsedIP)) {
        if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $null = $allResolvedIPs.Add($parsedIP.ToString())
            Write-Ok "  $srv is a direct IP"
        }
    } else {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($srv) |
                        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
            if ($resolved) {
                $ipStrings = @($resolved | ForEach-Object { $_.ToString() })
                $hostsMap | Add-Member -MemberType NoteProperty -Name $srv -Value $ipStrings
                foreach ($ip in $ipStrings) { $null = $allResolvedIPs.Add($ip) }
                Write-Ok "  $srv -> $($ipStrings -join ', ')"
            } else {
                Write-Warn "  $srv did not return any IPv4 address."
            }
        } catch {
            Write-Warn "  Could not resolve ${srv}: $_"
        }
    }
}

# 7. Identify physical gateway (Wi-Fi/Ethernet)
Write-Info "Detecting physical gateway (to bypass Customer VPN)..."
$gw = Get-PhysicalGateway
if (-not $gw) {
    Write-Err "Could not identify physical gateway. Check your internet connection."
    exit 1
}
Write-Ok "Physical Gateway: $($gw.Gateway) on $($gw.Name) (idx=$($gw.IfIndex))"

# 8. Add static host routes for ALL detected VPN server IPs
# This guarantees that traffic to the VPN servers exits via your physical Wi-Fi, bypassing AnyConnect/FortiClient
Write-Info "Adding bypass routes for all VPN server endpoints..."
foreach ($ip in $allResolvedIPs) {
    Add-Route -Prefix "$ip/32" -Gateway $gw.Gateway -IfIndex $gw.IfIndex
}

# 9. Configure Firewall rules
Write-Info "Setting firewall rules..."
Add-FwRule -Name "MultipVPN-SingBox-Out" -Direction Outbound -Protocol TCP
foreach ($ip in $allResolvedIPs) {
    Add-FwRule -Name "MultipVPN-Server-$ip" -Direction Outbound -Protocol TCP -RemoteAddress $ip
}

# 10. Construct universal sing-box configuration
Write-Info "Synthesizing universal TUN configuration..."

$excludeList = [System.Collections.Generic.List[string]]::new()
foreach ($sub in $CustomerSubnets) { $excludeList.Add($sub) }
foreach ($ip in $allResolvedIPs) {
    $cidr = "$ip/32"
    if (-not $excludeList.Contains($cidr)) { $excludeList.Add($cidr) }
}

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
    detour = $mainTag
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

$tunInbound = [pscustomobject]@{
    type                  = "tun"
    tag                   = "tun-in"
    address               = @("172.19.0.1/30")
    auto_route            = $true
    strict_route          = $false
    stack                 = "mixed"
    route_exclude_address = @($excludeList)
}

$finalConfig = [pscustomobject]@{
    log = [pscustomobject]@{ level = "warn"; timestamp = $true }
    dns = [pscustomobject]@{
        servers = @($dnsServers)
        rules   = $dnsRules
        final   = "dns-remote"
    }
    inbounds  = @($tunInbound)
    outbounds = $cleanOutbounds
    route     = [pscustomobject]@{
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
        final                 = $mainTag
    }
}

$TempConfigPath = Join-Path $PSScriptRoot "_singbox_dynamic_run.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$json = $finalConfig | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($TempConfigPath, $json, $utf8NoBom)
Write-Ok "Dynamic config synthesized: $TempConfigPath"

# 11. Start sing-box
Write-Host ""
Write-Info "Starting sing-box TUN service..."

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
    if ($Event.SourceEventArgs.Data) { Write-Host "[sing-box] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkGray }
} | Out-Null
Register-ObjectEvent $SingBoxProcess ErrorDataReceived -Action {
    if ($Event.SourceEventArgs.Data) { Write-Host "[sing-box] $($Event.SourceEventArgs.Data)" -ForegroundColor DarkYellow }
} | Out-Null

$SingBoxProcess.Start() | Out-Null
$SingBoxProcess.BeginOutputReadLine()
$SingBoxProcess.BeginErrorReadLine()

Start-Sleep -Seconds 2

if ($SingBoxProcess.HasExited) {
    Write-Err "sing-box failed to start (exit code: $($SingBoxProcess.ExitCode))"
    Invoke-Cleanup
    exit 1
}

Write-Ok "sing-box TUN service is RUNNING (PID: $($SingBoxProcess.Id))"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  CONNECTED! System-Wide Transparent TUN Active" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  * Active Outbound Group : $mainTag" -ForegroundColor White
Write-Host "  * Discovered Endpoints  : $($detectedServerHosts.Count) server(s) mapped" -ForegroundColor White
Write-Host "  * All apps & AI agents  : Transparently routed through VPN" -ForegroundColor White
Write-Host "  * Customer VPN Subnets  : $($CustomerSubnets -join ', ') (untouched)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press Ctrl+C to disconnect and restore all routes." -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

# 12. Keep alive loop
try {
    while (-not $SingBoxProcess.HasExited) {
        Start-Sleep -Milliseconds 500
    }
    Write-Warn "sing-box stopped (exit code: $($SingBoxProcess.ExitCode))"
} finally {
    Invoke-Cleanup
}
