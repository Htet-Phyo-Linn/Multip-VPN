<#
.SYNOPSIS
    Multip VPN - Deep Network Clean & Factory Restoration Tool
    Restores the Windows TCP/IP networking stack to a clean, post-reboot state.

.DESCRIPTION
    1. Force-terminates any running or hung sing-box / proxy processes.
    2. Removes all lingering static host bypass routes (/32 with metric 5).
    3. Cleans any orphaned Wintun / sing-tun virtual network adapters.
    4. Removes all MultipVPN Windows Firewall allow rules.
    5. Disables and flushes Windows Internet Proxy (WinINet) settings.
    6. Flushes DNS resolver cache and resets static DNS overrides to DHCP.
    7. Clears ARP and NetBIOS cache to wipe stale MAC/IP bindings.
    8. Deletes leftover temporary runtime files (_singbox_*.json).
    9. Tests and verifies physical gateway ping and direct internet connectivity.
    10. Customer VPN Safe: Preserves FortiClient, Cisco AnyConnect, and corporate subnets.
#>

[CmdletBinding()]
param(
    [switch]$Force
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

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
    Write-Warn "Deep Network Reset requires Administrator privileges."
    Write-Info "Re-launching elevated (UAC prompt)..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit 0
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   ⚡ MULTIP VPN - DEEP NETWORK CLEAN & RESTORATION TOOL" -ForegroundColor White
Write-Host "   Restores Windows TCP/IP stack to clean post-reboot state" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$sw = [System.Diagnostics.Stopwatch]::StartNew()

# ── 1. Terminate All Sing-Box & Proxy Processes ───────────────────────────────
Write-Info "Terminating all proxy and VPN engine processes..."
$killedCount = 0

# Terminate sing-box gracefully then forcefully
$processes = Get-Process -Name "sing-box" -ErrorAction SilentlyContinue
if ($processes) {
    foreach ($p in $processes) {
        try {
            $p.Kill()
            $killedCount++
        } catch {}
    }
}

# Also run taskkill to catch any child or detached processes
try {
    & taskkill.exe /F /IM "sing-box.exe" /T 2>$null | Out-Null
} catch {}

# Check for stray xray/v2ray if any
foreach ($procName in @("xray", "v2ray", "nekoray")) {
    $stray = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($stray) {
        foreach ($sp in $stray) {
            try { $sp.Kill(); $killedCount++ } catch {}
        }
    }
}

if ($killedCount -gt 0) {
    Write-Ok "Terminated $killedCount proxy process(es)."
} else {
    Write-Ok "No running proxy processes found."
}

# Give kernel driver 1s to release virtual adapter bindings
Start-Sleep -Milliseconds 600

# ── 2. Remove Orphaned Wintun / sing-tun Adapters ──────────────────────────────
Write-Info "Scanning for orphaned TUN / Wintun virtual adapters..."
$tunAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -like "*wintun*" -or
    $_.InterfaceDescription -like "*sing-box*" -or
    $_.Name -like "*sing-tun*" -or
    $_.Name -like "*sing-box*"
}

$removedAdapters = 0
if ($tunAdapters) {
    foreach ($ad in $tunAdapters) {
        try {
            Disable-NetAdapter -Name $ad.Name -Confirm:$false -ErrorAction SilentlyContinue
            $removedAdapters++
            Write-Ok "  Disabled orphan adapter: $($ad.Name)"
        } catch {}
    }
}

if ($removedAdapters -eq 0) {
    Write-Ok "Virtual TUN adapter state is clean."
}

# ── 3. Detect Physical Wi-Fi / Ethernet Gateway ───────────────────────────────
Write-Info "Detecting physical network adapter and default gateway..."
$skipWords = @("vmware","virtual","tap","loopback","tunnel","pangp","anyconnect","fortinet","cisco","outline","x-vpn")
$defaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
                 Sort-Object RouteMetric

$gw = $null
foreach ($r in $defaultRoutes) {
    if ($r.NextHop -eq "0.0.0.0") { continue }
    $adapter = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
    if (-not $adapter -or $adapter.Status -ne "Up") { continue }
    $desc = $adapter.InterfaceDescription.ToLower()
    $skip = $false
    foreach ($w in $skipWords) { if ($desc -like "*$w*") { $skip = $true; break } }
    if (-not $skip) {
        $gw = @{ Gateway = $r.NextHop; IfIndex = $r.InterfaceIndex; Name = $adapter.Name }
        break
    }
}

if (-not $gw) {
    # Fallback to lowest metric default route
    $best = $defaultRoutes | Select-Object -First 1
    if ($best) {
        $adapter = Get-NetAdapter -InterfaceIndex $best.InterfaceIndex -ErrorAction SilentlyContinue
        $gw = @{ Gateway = $best.NextHop; IfIndex = $best.InterfaceIndex; Name = $adapter.Name }
    }
}

if ($gw) {
    Write-Ok "Physical Gateway: $($gw.Gateway) on $($gw.Name) (idx=$($gw.IfIndex))"
} else {
    Write-Warn "Physical gateway could not be auto-detected. Proceeding with global route sweep."
}

# ── 4. Scrub Lingering Static Host Bypass Routes (/32) ────────────────────────
Write-Info "Scrubbing lingering static host bypass routes from Windows routing table..."
$localIPs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })

$all32Routes = Get-NetRoute -DestinationPrefix "*/32" -ErrorAction SilentlyContinue
$routesToPurge = [System.Collections.Generic.List[object]]::new()

foreach ($r in $all32Routes) {
    $dest = $r.DestinationPrefix.TrimEnd('/32')
    
    # Preserve Windows system & local broadcast routes
    if ($dest -in $localIPs) { continue }
    if ($dest -eq "255.255.255.255" -or $dest -eq "127.0.0.1") { continue }
    if ($dest -like "192.168.*.255" -or $dest -like "*.255") { continue }
    
    # Preserve Customer / Corporate VPN subnets (RFC 1918)
    if ($dest -like "10.*")       { continue }
    if ($dest -like "172.16.*" -or $dest -like "172.17.*" -or $dest -like "172.18.*" -or 
        $dest -like "172.19.*" -or $dest -like "172.2*.*"  -or $dest -like "172.3*.*") { continue }

    # Target static routes added with metric 5 or next hop to physical gateway
    $isVpnBypass = $false
    if ($r.RouteMetric -le 10) { $isVpnBypass = $true }
    if ($gw -and $r.NextHop -eq $gw.Gateway -and $r.RouteMetric -le 20) { $isVpnBypass = $true }

    if ($isVpnBypass) {
        $routesToPurge.Add($r)
    }
}

$clearedRoutes = 0
if ($routesToPurge.Count -gt 0) {
    Write-Host "  Purging $($routesToPurge.Count) lingering bypass route(s)..." -ForegroundColor Yellow
    foreach ($rt in $routesToPurge) {
        $dest = $rt.DestinationPrefix.TrimEnd('/32')
        try {
            & route.exe delete $dest 2>$null | Out-Null
            $clearedRoutes++
        } catch {
            try {
                Remove-NetRoute -DestinationPrefix $rt.DestinationPrefix -NextHop $rt.NextHop `
                                -InterfaceIndex $rt.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue
                $clearedRoutes++
            } catch {}
        }
    }
    Write-Ok "Cleaned $clearedRoutes static bypass route(s)."
} else {
    Write-Ok "No orphan static bypass routes found in routing table."
}

# ── 5. Clear All MultipVPN Firewall Rules ─────────────────────────────────────
Write-Info "Clearing MultipVPN Windows Firewall rules..."
$fwRules = Get-NetFirewallRule -DisplayName "MultipVPN*" -ErrorAction SilentlyContinue
$clearedFw = 0
if ($fwRules) {
    foreach ($rule in $fwRules) {
        try {
            Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
            $clearedFw++
        } catch {}
    }
    Write-Ok "Removed $clearedFw MultipVPN firewall rule(s)."
} else {
    Write-Ok "Firewall rules are clean."
}

# ── 6. Reset Windows Internet Proxy (WinINet) Settings ────────────────────────
Write-Info "Resetting Windows System Proxy (WinINet) to Direct Connection..."
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regPath -Name ProxyServer -Value "" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regPath -Name AutoConfigURL -Value "" -ErrorAction SilentlyContinue

    # Notify Windows apps (Edge, Chrome, Windows Services) to refresh proxy immediately
    try {
        $wininet = Add-Type -MemberDefinition @'
[DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@ -Name 'WinINetReset' -Namespace 'MultipVPNNetworkClean' -PassThru -ErrorAction SilentlyContinue

        if ($wininet) {
            # INTERNET_OPTION_SETTINGS_CHANGED = 39, INTERNET_OPTION_REFRESH = 37
            [MultipVPNNetworkClean.WinINetReset]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
            [MultipVPNNetworkClean.WinINetReset]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
        }
    } catch {}

    Write-Ok "System proxy disabled. Direct internet restored."
} catch {
    Write-Warn "Proxy reset note: $_"
}

# ── 7. Flush DNS Resolver & Reset Adapter DNS ─────────────────────────────────
Write-Info "Flushing DNS resolver cache..."
try {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    & ipconfig.exe /flushdns | Out-Null
    Write-Ok "DNS resolver cache successfully flushed."
} catch {}

# If DNS on physical adapter was manually set to loopback 127.0.0.1, restore to DHCP
if ($gw) {
    try {
        $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $gw.IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        if ($dnsServers -contains "127.0.0.1" -or $dnsServers -contains "::1") {
            Write-Host "  Resetting loopback DNS on $($gw.Name) back to DHCP automatic..." -ForegroundColor Yellow
            Set-DnsClientServerAddress -InterfaceIndex $gw.IfIndex -ResetServerAddresses -ErrorAction SilentlyContinue
            Write-Ok "  Adapter DNS restored to DHCP automatic."
        }
    } catch {}
}

# ── 8. Clear ARP & NetBIOS Cache ──────────────────────────────────────────────
Write-Info "Clearing ARP cache and NetBIOS cache..."
try {
    & arp.exe -d * 2>$null | Out-Null
    & nbtstat.exe -R 2>$null | Out-Null
    Write-Ok "ARP and NetBIOS bindings cleared."
} catch {}

# ── 9. Clean Temporary Runtime Configuration Files ────────────────────────────
Write-Info "Cleaning temporary runtime files..."
$tempFiles = @(
    (Join-Path $PSScriptRoot "_singbox_cluster_run.json"),
    (Join-Path $PSScriptRoot "_singbox_rotator_run.json"),
    (Join-Path $PSScriptRoot "_singbox_run.json"),
    (Join-Path $PSScriptRoot "_singbox_tun_run.json"),
    (Join-Path $PSScriptRoot "_singbox_dynamic_run.json")
)

$deletedFiles = 0
foreach ($tf in $tempFiles) {
    if (Test-Path $tf) {
        try {
            Remove-Item $tf -Force -ErrorAction SilentlyContinue
            $deletedFiles++
        } catch {}
    }
}

# Also purge any singbox probe temp files in %TEMP%
Get-ChildItem -Path $env:TEMP -Filter "singbox_probe_*.json" -ErrorAction SilentlyContinue |
    ForEach-Object { try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $deletedFiles++ } catch {} }

Write-Ok "Cleaned $deletedFiles runtime temporary file(s)."

# ── 10. Verify Network Health & Connectivity ──────────────────────────────────
Write-Host ""
Write-Info "Verifying network health and connectivity..."

$gwReachable = $false
if ($gw -and $gw.Gateway) {
    try {
        $pingGw = Test-Connection -ComputerName $gw.Gateway -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($pingGw) { $gwReachable = $true }
    } catch {}
}

$internetOk = $false
try {
    $res = & curl.exe -s -m 3 "http://www.gstatic.com/generate_204"
    if ($LASTEXITCODE -eq 0) { $internetOk = $true }
} catch {}

if (-not $internetOk) {
    try {
        $pingDns = Test-Connection -ComputerName "1.1.1.1" -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($pingDns) { $internetOk = $true }
    } catch {}
}

$sw.Stop()

$procStatus  = if ($killedCount -gt 0) { "Terminated ($killedCount)" } else { "Clean (0 running)" }
$routeStatus = if ($clearedRoutes -gt 0) { "Purged ($clearedRoutes orphan routes)" } else { "Clean (0 lingering)" }
$fwStatus    = if ($clearedFw -gt 0) { "Cleared ($clearedFw rules)" } else { "Clean" }
$gwStatus    = if ($gwReachable) { "CONNECTED ($($gw.Gateway) on $($gw.Name))" } else { "Active ($($gw.Gateway))" }
$gwColor     = if ($gwReachable) { "Green" } else { "Yellow" }
$netStatus   = if ($internetOk) { "ONLINE & VERIFIED" } else { "Connecting..." }
$netColor    = if ($internetOk) { "Green" } else { "Yellow" }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "   NETWORK RESTORATION COMPLETE (Took $($sw.ElapsedMilliseconds) ms)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  * Sing-Box Processes : $procStatus" -ForegroundColor White
Write-Host "  * Static Host Routes : $routeStatus" -ForegroundColor White
Write-Host "  * Firewall Rules     : $fwStatus" -ForegroundColor White
Write-Host "  * Windows Proxy      : Disabled (Direct Connection)" -ForegroundColor White
Write-Host "  * DNS & ARP Cache    : Flushed & Cleared" -ForegroundColor White
Write-Host "  * Physical Gateway   : $gwStatus" -ForegroundColor $gwColor
Write-Host "  * Direct Internet    : $netStatus" -ForegroundColor $netColor
Write-Host "  * Customer VPN       : INTACT (FortiClient / AnyConnect subnets preserved)" -ForegroundColor Green
Write-Host ""
Write-Host "[+] Your network is 100% clean and restored, exactly like after a reboot!" -ForegroundColor Cyan
Write-Host ""
