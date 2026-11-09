<#
.SYNOPSIS
    Universal VPN Share Link to sing-box JSON Converter (Alive-Only Filter)
    Probes candidate keys and converts ONLY the working/alive keys into clean sing-box config JSON.

.DESCRIPTION
    1. Reads raw VPN share links from key.txt (or any specified file / base64 subscription).
    2. Parses protocols: ss://, vless://, vmess://, trojan://, hysteria2://, hy2://, tuic://.
    3. Normalizes and deduplicates tags.
    4. Probes each candidate key using sing-box tools fetch before saving.
    5. Discards dead, timed out, and expired keys.
    6. Saves ONLY alive keys into sing-box config JSON.
    7. Validates syntax with sing-box.exe check.

.PARAMETER InputFile
    Input file containing share links. Defaults to 'key.txt'.

.PARAMETER OutputFile
    Target output JSON file (e.g. 'config01.json' or 'config.json'). 
    If omitted, automatically selects the next available 'configXX.json'.

.PARAMETER Split
    Saves each alive key into its own separate config file.
#>

param(
    [string]$InputFile = "key.txt",
    [string]$OutputFile,
    [switch]$Split,
    [int]$Threads = 16,
    [int]$TimeoutMs = 5000
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir   = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = "d:\CODE\Multip VPN" }
$SingBoxBin  = Join-Path $ScriptDir "sing-box.exe"
$utf8NoBom   = New-Object System.Text.UTF8Encoding $false

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   VPN Key to sing-box JSON Converter" -ForegroundColor White
Write-Host "   Supports: SS, VLESS (WS/Reality/TLS), VMess, Trojan, Hy2, TUIC" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan

# Resolve input file
$resolvedInput = $InputFile
if (-not (Test-Path $resolvedInput)) {
    $resolvedInput = Join-Path $ScriptDir $InputFile
}
if (-not (Test-Path $resolvedInput)) {
    Write-Host "[-] ERROR: Input file '$InputFile' not found." -ForegroundColor Red
    exit 1
}

Write-Host ("[+] Reading keys from: {0}" -f (Resolve-Path $resolvedInput)) -ForegroundColor Green

# Helper: Base64 decode with auto padding & url-safe support
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

# Helper: Parse URL query string
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

# Helper: Extract subscription payload (handles base64, JSON sing-box, or share link lines)
function Extract-SubscriptionPayload([string]$raw) {
    $results = [System.Collections.Generic.List[string]]::new()
    if (-not $raw) { return $results }
    $trimmed = $raw.Trim()

    # Case A: Base64 encoded blob
    if ($trimmed -notmatch '://' -and $trimmed.Length -gt 15) {
        $dec = Decode-Base64 $trimmed
        if ($dec) { $trimmed = $dec.Trim() }
    }

    # Case B: Sing-box JSON with outbounds
    if ($trimmed.StartsWith('{') -and $trimmed.Contains('"outbounds"')) {
        try {
            $jsonObj = $trimmed | ConvertFrom-Json
            if ($jsonObj.outbounds) {
                # JSON outbounds will be handled directly if passed
            }
        } catch {}
    }

    # Case C: Line-by-line share links or base64 lines
    foreach ($l in ($trimmed -split "`r?`n")) {
        $tl = $l.Trim()
        if ($tl -and -not $tl.StartsWith('#') -and -not $tl.StartsWith('//')) {
            if ($tl -notmatch '://' -and $tl.Length -gt 25) {
                $lineDec = Decode-Base64 $tl
                if ($lineDec -match '://') {
                    foreach ($subLine in ($lineDec -split "`r?`n")) {
                        $stl = $subLine.Trim()
                        if ($stl -match '^[a-z0-9]+://') { $results.Add($stl) }
                    }
                    continue
                }
            }
            if ($tl -match '^[a-z0-9]+://') {
                $results.Add($tl)
            }
        }
    }
    return $results
}

# Extract raw key lines (supports URLs, base64 subscriptions, raw links, and JSON)
function Get-KeyLines([string]$filePath) {
    $rawText = Get-Content -Path $filePath -Raw -Encoding UTF8
    if (-not $rawText) { return @() }
    
    $trimmed = $rawText.Trim()
    
    # 1. If whole file is a single base64 subscription blob
    if ($trimmed -notmatch '://' -and $trimmed.Length -gt 25) {
        $dec = Decode-Base64 $trimmed
        if ($dec -match '://' -or $dec -match '"outbounds"') {
            $rawText = $dec
        }
    }

    # Collect initial lines from file
    $initialLines = @()
    foreach ($line in ($rawText -split "`r?`n")) {
        $tl = $line.Trim()
        if ($tl -and -not $tl.StartsWith('#') -and -not $tl.StartsWith('//')) {
            $initialLines += $tl
        }
    }

    $urls = @($initialLines | Where-Object { $_ -match '^https?://' })
    $directKeys = @($initialLines | Where-Object { $_ -notmatch '^https?://' })

    $collectedLines = [System.Collections.Generic.List[string]]::new()

    # Process HTTP/HTTPS Subscription URLs
    if ($urls.Count -gt 0) {
        Write-Host ("[*] Detected {0} subscription URL(s) in {1}. Fetching..." -f $urls.Count, (Split-Path $filePath -Leaf)) -ForegroundColor Cyan
        
        try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch {}

        $hasHttpClient = $false
        try {
            $testClient = [System.Net.Http.HttpClient]::new()
            $testClient.Dispose()
            $hasHttpClient = $true
        } catch { $hasHttpClient = $false }

        if ($hasHttpClient) {
            $httpClient = [System.Net.Http.HttpClient]::new()
            $httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("v2rayN/6.23")
            $httpClient.Timeout = [TimeSpan]::FromSeconds(8)

            $tasks = @{}
            foreach ($u in $urls) {
                try {
                    $tasks[$u] = $httpClient.GetStringAsync($u)
                } catch {}
            }

            try {
                [System.Threading.Tasks.Task]::WaitAll(@($tasks.Values))
            } catch {}

            $uIdx = 0
            foreach ($u in $urls) {
                $uIdx++
                if ($tasks.ContainsKey($u) -and $tasks[$u].Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion) {
                    $payload = $tasks[$u].Result.Trim()
                    $subExtracted = Extract-SubscriptionPayload $payload
                    foreach ($k in $subExtracted) { $collectedLines.Add($k) }
                    Write-Host ("  [{0}/{1}] Fetched {2} node(s) from: {3}" -f $uIdx, $urls.Count, $subExtracted.Count, $u) -ForegroundColor Green
                } else {
                    $curlResp = curl.exe -s -L --max-time 6 -A "v2rayN/6.23" $u
                    if ($curlResp) {
                        $subExtracted = Extract-SubscriptionPayload $curlResp.Trim()
                        foreach ($k in $subExtracted) { $collectedLines.Add($k) }
                        Write-Host ("  [{0}/{1}] Fetched {2} node(s) (curl fallback) from: {3}" -f $uIdx, $urls.Count, $subExtracted.Count, $u) -ForegroundColor Green
                    } else {
                        Write-Host ("  [{0}/{1}] WARNING: Failed to fetch: {2}" -f $uIdx, $urls.Count, $u) -ForegroundColor Yellow
                    }
                }
            }
            $httpClient.Dispose()
        } else {
            $uIdx = 0
            foreach ($u in $urls) {
                $uIdx++
                $curlResp = curl.exe -s -L --max-time 6 -A "v2rayN/6.23" $u
                if ($curlResp) {
                    $subExtracted = Extract-SubscriptionPayload $curlResp.Trim()
                    foreach ($k in $subExtracted) { $collectedLines.Add($k) }
                    Write-Host ("  [{0}/{1}] Fetched {2} node(s) from: {3}" -f $uIdx, $urls.Count, $subExtracted.Count, $u) -ForegroundColor Green
                } else {
                    Write-Host ("  [{0}/{1}] WARNING: Failed to fetch: {2}" -f $uIdx, $urls.Count, $u) -ForegroundColor Yellow
                }
            }
        }
    }

    # Process direct keys & raw base64 lines
    foreach ($line in $directKeys) {
        $extracted = Extract-SubscriptionPayload $line
        foreach ($k in $extracted) { $collectedLines.Add($k) }
    }

    return @($collectedLines)
}

# Protocol Parsers
function Parse-Shadowsocks([string]$uri, [string]$tag) {
    $body = $uri.Substring(5) # strip 'ss://'
    $server = ""; $port = 0; $method = ""; $password = ""

    # SIP002 format: ss://base64(method:password)@server:port
    if ($body -match '^([^@]+)@(\[[a-fA-F0-9:]+\]|[^:/?#]+):(\d+)') {
        $cred = Decode-Base64 $Matches[1]
        $server = $Matches[2].Trim('[', ']')
        $port = [int]$Matches[3]
        if ($cred -match '^([^:]+):(.*)$') {
            $method = $Matches[1]
            $password = $Matches[2]
        }
    } else {
        # Legacy format: ss://base64(method:password@server:port)
        $cleanBody = ($body -split '[/?#]')[0]
        $dec = Decode-Base64 $cleanBody
        if ($dec -match '^([^:]+):(.*)@(\[[a-fA-F0-9:]+\]|[^:/?#]+):(\d+)$') {
            $method   = $Matches[1]
            $password = $Matches[2]
            $server   = $Matches[3].Trim('[', ']')
            $port     = [int]$Matches[4]
        }
    }

    if ($server -and $port -and $method) {
        if (-not $tag) { $tag = "SS-$server`:$port" }
        return [ordered]@{
            type        = "shadowsocks"
            tag         = $tag
            server      = $server
            server_port = $port
            method      = $method
            password    = $password
        }
    }
    return $null
}

function Parse-Vless([string]$uri, [string]$tag) {
    # vless://uuid@server:port?query
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

        # Security: Reality / TLS / None
        $sec = $q['security']
        if ($sec -eq "reality") {
            $pbk = if ($q['pbk']) { $q['pbk'] } else { $q['public_key'] }
            $sid = if ($q['sid']) { $q['sid'] } else { $q['short_id'] }
            $fp  = if ($q['fp'])  { $q['fp'] }  else { "chrome" }
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
            $node["tls"] = [ordered]@{
                enabled     = $true
                server_name = $sni
            }
            if ($q['fp']) {
                $node.tls["utls"] = @{ enabled = $true; fingerprint = $q['fp'] }
            }
            if ($q['alpn']) {
                # If transport is ws or httpupgrade, do NOT enforce h2/h3 ALPN
                # as that breaks standard WebSocket TLS handshakes on CDN fronts!
                if ($q['type'] -in @("ws", "httpupgrade")) {
                    $node.tls["alpn"] = @("http/1.1")
                } else {
                    $node.tls["alpn"] = @($q['alpn'] -split ',')
                }
            }
        }

        # Transport: ws, grpc, http, httpupgrade, tcp
        $type = $q['type']
        if ($type -eq "ws") {
            $ws = [ordered]@{ type = "ws" }
            if ($q['path']) { $ws["path"] = $q['path'] }
            if ($q['host']) { $ws["headers"] = @{ Host = $q['host'] } }
            $node["transport"] = $ws
        } elseif ($type -eq "grpc") {
            $grpc = [ordered]@{ type = "grpc" }
            $svc = if ($q['serviceName']) { $q['serviceName'] } else { $q['path'] }
            if ($svc) { $grpc["service_name"] = $svc }
            $node["transport"] = $grpc
        } elseif ($type -eq "httpupgrade") {
            $hu = [ordered]@{ type = "httpupgrade" }
            if ($q['path']) { $hu["path"] = $q['path'] }
            if ($q['host']) { $hu["host"] = $q['host'] }
            $node["transport"] = $hu
        } elseif ($type -eq "http") {
            $tr = [ordered]@{ type = "http" }
            if ($q['path']) { $tr["path"] = $q['path'] }
            if ($q['host']) { $tr["host"] = @($q['host'] -split ',') }
            $node["transport"] = $tr
        }

        $node["packet_encoding"] = if ($q['packetEncoding']) { $q['packetEncoding'] } else { "xudp" }
        return $node
    }
    return $null
}

function Parse-Vmess([string]$uri, [string]$tag) {
    # vmess://base64(json)
    $b64 = $uri.Substring(8)
    $jsonStr = Decode-Base64 $b64
    if (-not $jsonStr) { return $null }

    try {
        $v = $jsonStr | ConvertFrom-Json
        $server = $v.add
        $port   = [int]$v.port
        $uuid   = $v.id
        $customTag = if ($tag) { $tag } elseif ($v.ps) { $v.ps } else { "VMess-$server`:$port" }

        $node = [ordered]@{
            type        = "vmess"
            tag         = $customTag
            server      = $server
            server_port = $port
            uuid        = $uuid
            security    = if ($v.scy) { $v.scy } else { "auto" }
            alter_id    = if ($v.aid) { [int]$v.aid } else { 0 }
        }

        # TLS
        if ($v.tls -eq "tls") {
            $sni = if ($v.sni) { $v.sni } elseif ($v.host) { $v.host } else { $server }
            $node["tls"] = [ordered]@{
                enabled     = $true
                server_name = $sni
            }
        }

        # Transport
        $net = $v.net
        if ($net -eq "ws") {
            $ws = [ordered]@{ type = "ws" }
            if ($v.path) { $ws["path"] = $v.path }
            if ($v.host) { $ws["headers"] = @{ Host = $v.host } }
            $node["transport"] = $ws
        } elseif ($net -eq "httpupgrade") {
            $hu = [ordered]@{ type = "httpupgrade" }
            if ($v.path) { $hu["path"] = $v.path }
            if ($v.host) { $hu["host"] = $v.host }
            $node["transport"] = $hu
        } elseif ($net -eq "grpc") {
            $node["transport"] = [ordered]@{
                type         = "grpc"
                service_name = $v.path
            }
        }

        $node["packet_encoding"] = "xudp"
        return $node
    } catch {
        return $null
    }
}

function Parse-Trojan([string]$uri, [string]$tag) {
    # trojan://password@server:port?query
    if ($uri -match '^trojan://([^@]+)@(\[[a-fA-F0-9:]+\]|[^:/?#]+):(\d+)(\?[^#]*)?$') {
        $password = $Matches[1]
        $server   = $Matches[2].Trim('[', ']')
        $port     = [int]$Matches[3]
        $q        = Parse-QueryString $Matches[4]

        if (-not $tag) { $tag = "Trojan-$server`:$port" }

        $sni = if ($q['sni']) { $q['sni'] } elseif ($q['peer']) { $q['peer'] } else { $server }

        $node = [ordered]@{
            type        = "trojan"
            tag         = $tag
            server      = $server
            server_port = $port
            password    = $password
            tls         = [ordered]@{
                enabled     = $true
                server_name = $sni
            }
        }

        if ($q['alpn']) { $node.tls["alpn"] = @($q['alpn'] -split ',') }

        $type = $q['type']
        if ($type -eq "ws") {
            $ws = [ordered]@{ type = "ws" }
            if ($q['path']) { $ws["path"] = $q['path'] }
            if ($q['host']) { $ws["headers"] = @{ Host = $q['host'] } }
            $node["transport"] = $ws
        } elseif ($type -eq "grpc") {
            $svc = if ($q['serviceName']) { $q['serviceName'] } else { $q['path'] }
            $node["transport"] = [ordered]@{
                type         = "grpc"
                service_name = $svc
            }
        }

        return $node
    }
    return $null
}

function Parse-Hysteria2([string]$uri, [string]$tag) {
    # hysteria2://password@server:port?query or hy2://
    if ($uri -match '^(?:hysteria2|hy2)://([^@]+)@(\[[a-fA-F0-9:]+\]|[^:/?#]+):(\d+)(\?[^#]*)?$') {
        $password = $Matches[1]
        $server   = $Matches[2].Trim('[', ']')
        $port     = [int]$Matches[3]
        $q        = Parse-QueryString $Matches[4]

        if (-not $tag) { $tag = "Hy2-$server`:$port" }

        $sni = if ($q['sni']) { $q['sni'] } else { $server }

        $node = [ordered]@{
            type        = "hysteria2"
            tag         = $tag
            server      = $server
            server_port = $port
            password    = $password
            tls         = [ordered]@{
                enabled     = $true
                server_name = $sni
            }
        }

        if ($q['insecure'] -eq "1" -or $q['insecure'] -eq "true") {
            $node.tls["insecure"] = $true
        }

        if ($q['obfs']) {
            $obfsType = $q['obfs']
            $obfsPass = if ($q['obfs-password']) { $q['obfs-password'] } else { $q['obfs_password'] }
            $node["obfs"] = @{
                type     = $obfsType
                password = $obfsPass
            }
        }

        return $node
    }
    return $null
}

function Parse-Tuic([string]$uri, [string]$tag) {
    # tuic://uuid:password@server:port?query
    if ($uri -match '^tuic://([^:]+):([^@]+)@(\[[a-fA-F0-9:]+\]|[^:/?#]+):(\d+)(\?[^#]*)?$') {
        $uuid     = $Matches[1]
        $password = $Matches[2]
        $server   = $Matches[3].Trim('[', ']')
        $port     = [int]$Matches[4]
        $q        = Parse-QueryString $Matches[5]

        if (-not $tag) { $tag = "TUIC-$server`:$port" }

        $sni = if ($q['sni']) { $q['sni'] } else { $server }

        $node = [ordered]@{
            type               = "tuic"
            tag                = $tag
            server             = $server
            server_port        = $port
            uuid               = $uuid
            password           = $password
            congestion_control = if ($q['congestion_control']) { $q['congestion_control'] } else { "bbr" }
            tls                = [ordered]@{
                enabled     = $true
                server_name = $sni
            }
        }
        return $node
    }
    return $null
}

# Main parsing loop
$keyLines = Get-KeyLines $resolvedInput
Write-Host ("[*] Found {0} key line(s) to convert." -f $keyLines.Count) -ForegroundColor Cyan

if ($keyLines.Count -eq 0) {
    Write-Host "[!] No valid keys found in input file." -ForegroundColor Yellow
    exit 0
}

$parsedOutbounds = @()
$tagCounts = @{}
$seenSignatures = @{}
$seenServerPorts = @{}

$lineNum = 0
foreach ($line in $keyLines) {
    $lineNum++
    $tag = ""
    $rawUri = $line
    if ($rawUri -match '^(.*?)#(.*)$') {
        $rawUri = $Matches[1]
        $tag = [System.Uri]::UnescapeDataString($Matches[2]).Trim()
    }

    $node = $null
    if ($rawUri.StartsWith("ss://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $node = Parse-Shadowsocks $rawUri $tag
    } elseif ($rawUri.StartsWith("vless://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $node = Parse-Vless $rawUri $tag
    } elseif ($rawUri.StartsWith("vmess://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $node = Parse-Vmess $rawUri $tag
    } elseif ($rawUri.StartsWith("trojan://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $node = Parse-Trojan $rawUri $tag
    } elseif ($rawUri.StartsWith("hysteria2://", [System.StringComparison]::OrdinalIgnoreCase) -or 
              $rawUri.StartsWith("hy2://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $node = Parse-Hysteria2 $rawUri $tag
    } elseif ($rawUri.StartsWith("tuic://", [System.StringComparison]::OrdinalIgnoreCase)) {
        $node = Parse-Tuic $rawUri $tag
    } else {
        Write-Host ("  [?] Item {0}: Unknown or unsupported protocol: {1}" -f $lineNum, ($line.Substring(0, [Math]::Min(20, $line.Length)) + "...")) -ForegroundColor Yellow
        continue
    }

    if ($node) {
        $hostHdr = if ($node.transport -and $node.transport.headers -and $node.transport.headers.Host) {
            $node.transport.headers.Host
        } elseif ($node.transport -and $node.transport.host) {
            $node.transport.host
        } else { "" }
        $sig = ("{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}" -f $node.type, $node.server, $node.server_port, $node.uuid, $node.password, 
                ($node.tls.server_name), $hostHdr, ($node.transport.path)).ToLowerInvariant()

        if ($seenSignatures.ContainsKey($sig)) {
            continue
        }
        $seenSignatures[$sig] = $true

        # Deduplicate by protocol type + server + port combination
        # (Allows Hysteria2 UDP and VLESS TCP on the same server:port)
        $srvPortKey = ("{0}://{1}:{2}" -f $node.type, $node.server, $node.server_port).ToLowerInvariant()
        if ($seenServerPorts.ContainsKey($srvPortKey)) {
            Write-Host ("  [!] Node {0}: Skipped duplicate protocol endpoint ({1}://{2}:{3})" -f $lineNum, $node.type, $node.server, $node.server_port) -ForegroundColor DarkGray
            continue
        }
        $seenServerPorts[$srvPortKey] = $true

        # Ensure unique tag
        $cleanTag = $node.tag
        if ($tagCounts.ContainsKey($cleanTag)) {
            $tagCounts[$cleanTag]++
            $node.tag = ("{0} ({1})" -f $cleanTag, $tagCounts[$cleanTag])
        } else {
            $tagCounts[$cleanTag] = 1
        }
        $parsedOutbounds += $node
        Write-Host ("  [+] Node {0}: Parsed {1,-10} -> '{2}' ({3}:{4})" -f $parsedOutbounds.Count, $node.type, $node.tag, $node.server, $node.server_port) -ForegroundColor Green
    } else {
        Write-Host ("  [-] Item {0}: Failed to parse link." -f $lineNum) -ForegroundColor Red
    }
}

if ($parsedOutbounds.Count -eq 0) {
    Write-Host "[-] ERROR: Zero nodes were successfully parsed." -ForegroundColor Red
    exit 1
}

# ----------------------------------------------------------------
# Live Health Probe & Alive-Only Filter (Before Saving)
# ----------------------------------------------------------------
$aliveOutbounds = @()
$deadCount = 0

if (Test-Path $SingBoxBin) {
    if ($Threads -lt 1) { $Threads = 16 }
    if ($TimeoutMs -lt 1000) { $TimeoutMs = 5000 }
    Write-Host ("`n[*] Probing live connectivity of candidate keys with {0} parallel thread(s) (Timeout: {1}ms)..." -f $Threads, $TimeoutMs) -ForegroundColor Cyan
    
    $activeJobs = [System.Collections.Generic.List[PSObject]]::new()
    $totalCandidates = $parsedOutbounds.Count
    $nodeIdx = 0
    $completedCount = 0
    $timeoutMs = $TimeoutMs

    $aliveCollector = [System.Collections.Generic.List[PSObject]]::new()

    while ($nodeIdx -lt $totalCandidates -or $activeJobs.Count -gt 0) {
        # Fill worker pool up to $Threads
        while ($nodeIdx -lt $totalCandidates -and $activeJobs.Count -lt $Threads) {
            $curIdx = $nodeIdx
            $nodeIdx++
            $n = $parsedOutbounds[$curIdx]
            $itemNum = $curIdx + 1

            # Fast DNS pre-check
            $dnsOk = $false
            try {
                $ips = [System.Net.Dns]::GetHostAddresses($n.server)
                if ($ips) { $dnsOk = $true }
            } catch {}

            if (-not $dnsOk) {
                $completedCount++
                $deadCount++
                Write-Host ("  [{0}/{1}] {2,-10} '{3}' -> DEAD (DNS Resolve Failed) [DROPPED]" -f $itemNum, $totalCandidates, $n.type, $n.tag) -ForegroundColor Red
                continue
            }

            # Setup temp probe config
            $probeTmp = Join-Path $env:TEMP ("sb_conv_probe_" + [Guid]::NewGuid().ToString("N") + ".json")
            $cloneObj = ($n | ConvertTo-Json -Depth 10) | ConvertFrom-Json
            $cloneObj.tag = "probe"

            $pConfig = @{
                log = @{ level = "error" }
                outbounds = @($cloneObj)
            }
            $pJson = $pConfig | ConvertTo-Json -Depth 10
            [System.IO.File]::WriteAllText($probeTmp, $pJson, $utf8NoBom)

            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = $SingBoxBin
            $pinfo.Arguments = "tools fetch https://www.gstatic.com/generate_204 -c `"$probeTmp`" -o probe"
            $pinfo.RedirectStandardOutput = $true
            $pinfo.RedirectStandardError = $true
            $pinfo.UseShellExecute = $false
            $pinfo.CreateNoWindow = $true

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $proc = [System.Diagnostics.Process]::Start($pinfo)

            $activeJobs.Add([PSObject]@{
                Process   = $proc
                Stopwatch = $sw
                TmpFile   = $probeTmp
                Node      = $n
                Index     = $itemNum
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

                if ($p.HasExited) {
                    $sw.Stop()
                    $exitCode = $p.ExitCode
                    $errText = ""
                    try { $errText = ($p.StandardError.ReadToEnd() -split "`n")[0].Trim() } catch {}
                    $p.Dispose()
                    Remove-Item $job.TmpFile -Force -ErrorAction SilentlyContinue

                    $completedCount++
                    if ($exitCode -eq 0) {
                        $aliveCollector.Add($job.Node)
                        Write-Host ("  [{0}/{1}] {2,-10} '{3}' -> ALIVE ({4}ms) [KEPT]" -f $job.Index, $totalCandidates, $job.Node.type, $job.Node.tag, $elapsed) -ForegroundColor Green
                    } else {
                        $deadCount++
                        $err = $errText
                        if ($err -match "status code: (\d+)") {
                            $err = "Auth error (HTTP $($Matches[1]))"
                        } elseif ($err -match "EOF") {
                            $err = "Server dropped connection (EOF)"
                        } elseif ($err -match "refused") {
                            $err = "Connection refused"
                        } elseif ($err -match "reality verification failed") {
                            $err = "Reality handshake failed"
                        }
                        if (-not $err) { $err = "Failed" }
                        Write-Host ("  [{0}/{1}] {2,-10} '{3}' -> DEAD ({4}) [DROPPED]" -f $job.Index, $totalCandidates, $job.Node.type, $job.Node.tag, $err) -ForegroundColor Yellow
                    }
                } elseif ($elapsed -gt $timeoutMs) {
                    $sw.Stop()
                    try { $p.Kill(); $p.Dispose() } catch {}
                    Remove-Item $job.TmpFile -Force -ErrorAction SilentlyContinue

                    $completedCount++
                    $deadCount++
                    Write-Host ("  [{0}/{1}] {2,-10} '{3}' -> DEAD (Timeout >$($timeoutMs)ms) [DROPPED]" -f $job.Index, $totalCandidates, $job.Node.type, $job.Node.tag) -ForegroundColor Red
                } else {
                    $stillRunning.Add($job)
                }
            }
            $activeJobs = $stillRunning
            Start-Sleep -Milliseconds 25
        }
    }

    $aliveOutbounds = @($aliveCollector)

    if ($aliveOutbounds.Count -eq 0) {
        Write-Host ("`n[-] FAILED: None of the {0} candidate key(s) are alive. No config files were created." -f $parsedOutbounds.Count) -ForegroundColor Red
        exit 1
    }

    Write-Host ("`n[+] Alive Filter Result: {0} alive key(s) kept, {1} dead key(s) dropped." -f $aliveOutbounds.Count, $deadCount) -ForegroundColor Green
} else {
    $aliveOutbounds = $parsedOutbounds
}

# ----------------------------------------------------------------
# Save ONLY Alive Keys to JSON
# ----------------------------------------------------------------
$createdFiles = @()

if ($Split) {
    Write-Host "`n[*] SPLIT MODE: Creating 1 config JSON file per alive key..." -ForegroundColor Cyan
    $idx = 1
    foreach ($n in $aliveOutbounds) {
        $candidatePath = $null
        while ($true) {
            $candidateName = ("config{0:D2}.json" -f $idx)
            $candidatePath = Join-Path $ScriptDir $candidateName
            if (-not (Test-Path $candidatePath)) {
                break
            }
            $idx++
        }
        $singleConfig = [ordered]@{
            outbounds = @($n)
        }
        $jsonOutput = $singleConfig | ConvertTo-Json -Depth 15
        [System.IO.File]::WriteAllText($candidatePath, $jsonOutput, $utf8NoBom)
        $createdFiles += $candidatePath
        Write-Host ("  [+] Created {0,-14} -> '{1}' ({2}:{3})" -f (Split-Path -Leaf $candidatePath), $n.tag, $n.server, $n.server_port) -ForegroundColor Green
        $idx++
    }
} else {
    # Determine target output file
    $targetOutputPath = $null
    if ($OutputFile) {
        $targetOutputPath = if ([System.IO.Path]::IsPathRooted($OutputFile)) { $OutputFile } else { Join-Path $ScriptDir $OutputFile }
    } else {
        # Auto-find next available configXX.json
        $idx = 1
        while ($true) {
            $candidateName = ("config{0:D2}.json" -f $idx)
            $candidatePath = Join-Path $ScriptDir $candidateName
            if (-not (Test-Path $candidatePath)) {
                $targetOutputPath = $candidatePath
                break
            }
            $idx++
        }
    }

    $finalConfig = [ordered]@{
        outbounds = $aliveOutbounds
    }

    $jsonOutput = $finalConfig | ConvertTo-Json -Depth 15
    [System.IO.File]::WriteAllText($targetOutputPath, $jsonOutput, $utf8NoBom)
    $createdFiles += $targetOutputPath

    Write-Host ("`n[+] SUCCESS: Saved {0} alive node(s) to: {1}" -f $aliveOutbounds.Count, (Split-Path -Leaf $targetOutputPath)) -ForegroundColor Green
    Write-Host ("    Full Path: {0}" -f $targetOutputPath) -ForegroundColor Gray
}

# Validate config with sing-box check
if (Test-Path $SingBoxBin) {
    Write-Host "`n[*] Validating configuration(s) with sing-box check..." -ForegroundColor Cyan
    $allValid = $true
    foreach ($cf in $createdFiles) {
        $checkProc = & $SingBoxBin check -c $cf 2>&1
        if ($LASTEXITCODE -ne 0) {
            $allValid = $false
            Write-Host ("[-] sing-box check WARNING for {0}: {1}" -f (Split-Path -Leaf $cf), ($checkProc -join ' ')) -ForegroundColor Yellow
        }
    }
    if ($allValid) {
        Write-Host "[+] sing-box validation PASSED for all file(s)!" -ForegroundColor Green
    }
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "   CONVERSION COMPLETE!" -ForegroundColor White
if ($Split) {
    Write-Host ("   Output Files ({0}):" -f $createdFiles.Count) -ForegroundColor Green
    foreach ($cf in $createdFiles) {
        Write-Host ("     - {0}" -f (Split-Path -Leaf $cf)) -ForegroundColor White
    }
} else {
    Write-Host ("   Output File : {0}" -f (Split-Path -Leaf $createdFiles[0])) -ForegroundColor Green
    Write-Host "   You can now connect to this file using:" -ForegroundColor Gray
    Write-Host ("     .\connect-vpn.ps1 {0}" -f (Split-Path -Leaf $createdFiles[0])) -ForegroundColor White
}
Write-Host "   Or run cluster / cleaner:" -ForegroundColor Gray
Write-Host "     .\connect-cluster.ps1   (auto-includes all new configs!)" -ForegroundColor White
Write-Host "     .\clean-configs.ps1     (health & country sweep)" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
