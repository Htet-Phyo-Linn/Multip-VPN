<#
.SYNOPSIS
    Multip VPN - Extractor for VPN Injector & Decrypted Tunnel Files
    Extracts proxy outbounds from decrypted injector files (*.txt, *.dark, *.json, result_*.txt, 
    *-unlocked.txt, OpenVPN, SSH, VLESS, VMess, Shadowsocks, Trojan) and generates standard 
    sing-box configuration JSON (vpn_file_01.json).

.DESCRIPTION
    Scans the 'vpn file' directory (or custom path) and extracts:
    1. Decrypted HTTP Custom / SP-DECODE / Ghost Developer JSON files (*-unlocked.txt, result_*.txt).
    2. Dark Tunnel configurations (*.dark with darktunnel:// base64 payloads).
    3. Direct and embedded SSH tunnel configurations (host:port@user:pass).
    4. Embedded VLESS, VMess, Shadowsocks, Trojan, and Hy2 share links.
    5. Deduplicates discovered nodes and exports standard sing-box { "outbounds": [...] } format.
    6. Validates the generated configuration with sing-box.exe check.

.PARAMETER Folder
    Path to directory containing VPN files (defaults to '.\vpn file').

.PARAMETER OutputFile
    Destination sing-box JSON configuration file (defaults to 'vpn_file_01.json').

.PARAMETER Overwrite
    Overwrite output file if it already exists.
#>

[CmdletBinding()]
param(
    [string]$Folder     = "",
    [string]$OutputFile = "vpn_file_01.json",
    [switch]$Overwrite
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

function Write-Info    { param($m) Write-Host "[*] $m" -ForegroundColor Cyan    }
function Write-Ok      { param($m) Write-Host "[+] $m" -ForegroundColor Green   }
function Write-Warn    { param($m) Write-Host "[!] $m" -ForegroundColor Yellow  }
function Write-Err     { param($m) Write-Host "[-] $m" -ForegroundColor Red     }
function Write-Header  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Magenta }

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }
if (-not $Folder) { $Folder = Join-Path $ScriptDir "vpn file" }

if (-not (Test-Path $Folder)) {
    Write-Err "Folder not found: $Folder"
    exit 1
}

$singBoxExe = Join-Path $ScriptDir "sing-box.exe"

Write-Header "VPN File Extractor -> sing-box JSON"
Write-Info "Source Folder : $Folder"
Write-Info "Output File   : $OutputFile"

$discoveredOutbounds = [System.Collections.Generic.List[object]]::new()
$processedFiles      = 0
$encryptedBinaryList = [System.Collections.Generic.List[string]]::new()
$seenNodeKeys        = [System.Collections.Generic.HashSet[string]]::new()

# Helper: Add outbound with deduplication
function Add-DiscoveredOutbound {
    param($OutboundObj, [string]$Source)

    if (-not $OutboundObj -or -not $OutboundObj.type) { return }

    $srv  = if ($OutboundObj.server) { $OutboundObj.server.ToString().Trim().ToLowerInvariant() } else { "" }
    $port = if ($OutboundObj.server_port) { [int]$OutboundObj.server_port } else { 0 }
    $type = $OutboundObj.type.ToString().Trim().ToLowerInvariant()
    $user = if ($OutboundObj.user) { $OutboundObj.user.ToString().Trim() } else { "" }

    $uniqueKey = "{0}://{1}:{2}@{3}" -f $type, $srv, $port, $user
    if ($seenNodeKeys.Contains($uniqueKey)) {
        Write-Host "  [-] Duplicate node skipped: $uniqueKey (from $Source)" -ForegroundColor DarkGray
        return
    }

    [void]$seenNodeKeys.Add($uniqueKey)
    $discoveredOutbounds.Add($OutboundObj)
    Write-Ok ("Extracted [{0}] '{1}' -> {2}:{3} (from {4})" -f $type, $OutboundObj.tag, $srv, $port, $Source)
}

# ── Helper: Parse Base64 Dark Tunnel (*.dark) ───────────────────────────────────
function Parse-DarkTunnelFile {
    param([System.IO.FileInfo]$File)

    $content = Get-Content $File.FullName -Raw
    if ($content -match 'darktunnel://([A-Za-z0-9+/=_-]+)') {
        try {
            $b64 = $Matches[1].Replace('-', '+').Replace('_', '/')
            while ($b64.Length % 4 -ne 0) { $b64 += '=' }
            $bytes = [System.Convert]::FromBase64String($b64)
            $jsonText = [System.Text.Encoding]::UTF8.GetString($bytes)
            $data = $jsonText | ConvertFrom-Json

            $tagName = if ($data.name) { "DarkTunnel-$($data.name)" } else { "DarkTunnel-$($File.BaseName)" }
            $sshCfg = $data.sshTunnelConfig.sshConfig

            if ($sshCfg -and $sshCfg.host) {
                $ob = [ordered]@{
                    type        = "ssh"
                    tag         = $tagName
                    server      = $sshCfg.host.ToString().Trim()
                    server_port = [int]$sshCfg.port
                    user        = if ($sshCfg.username) { $sshCfg.username.ToString().Trim() } else { "root" }
                    password    = if ($sshCfg.password) { $sshCfg.password.ToString().Trim() } else { "" }
                }
                Add-DiscoveredOutbound -OutboundObj $ob -Source $File.Name
                return $true
            }
        } catch {
            Write-Warn "Failed to decode DarkTunnel JSON in $($File.Name): $_"
        }
    }
    return $false
}

# ── Helper: Parse Decrypted JSON Files (*.txt, *.json) ─────────────────────────
function Parse-DecryptedJsonFile {
    param([System.IO.FileInfo]$File)

    $raw = Get-Content $File.FullName -Raw
    if (-not $raw) { return $false }

    $foundAny = $false

    # Match JSON block if surrounded by headers/decorations
    if ($raw -match '(?s)(\{[\s\S]*"config"[\s\S]*\})') {
        try {
            $jsonObj = $Matches[1] | ConvertFrom-Json
            if ($jsonObj.config) {
                $configs = @($jsonObj.config)
                $idx = 0
                foreach ($cfg in $configs) {
                    $idx++
                    $tagName = if ($cfg.name) { $cfg.name } elseif ($cfg.label) { $cfg.label } else { "$($File.BaseName)-$idx" }
                    $tagName = $tagName -replace '[^a-zA-Z0-9_\-\. ]', ''

                    # 1. Standard SSH Protocol
                    if ($cfg.protocol -eq "SSH" -or ($cfg.host -and $cfg.username)) {
                        $h = if ($cfg.host) { $cfg.host.ToString().Trim() } else { "" }
                        $p = if ($cfg.port) { [int]$cfg.port } else { 443 }
                        $u = if ($cfg.username) { $cfg.username.ToString().Trim() } else { "" }
                        $pwd = if ($cfg.password) { $cfg.password.ToString().Trim() } else { "" }

                        if ($h -and $u) {
                            $ob = [ordered]@{
                                type        = "ssh"
                                tag         = "SSH-$tagName"
                                server      = $h
                                server_port = $p
                                user        = $u
                                password    = $pwd
                            }
                            Add-DiscoveredOutbound -OutboundObj $ob -Source $File.Name
                            $foundAny = $true
                        }
                    }

                    # 2. sshField format: "host:port@user:password" or "user:password@host:port"
                    if ($cfg.sshField) {
                        $field = $cfg.sshField.ToString().Trim()
                        if ($field -match '^([^:]+):(\d+)@([^:]+):(.*)$') {
                            $ob = [ordered]@{
                                type        = "ssh"
                                tag         = "SSH-$tagName"
                                server      = $Matches[1]
                                server_port = [int]$Matches[2]
                                user        = $Matches[3]
                                password    = $Matches[4]
                            }
                            Add-DiscoveredOutbound -OutboundObj $ob -Source $File.Name
                            $foundAny = $true
                        } elseif ($field -match '^([^:]+):(.*)@([^:]+):(\d+)$') {
                            $ob = [ordered]@{
                                type        = "ssh"
                                tag         = "SSH-$tagName"
                                server      = $Matches[3]
                                server_port = [int]$Matches[4]
                                user        = $Matches[1]
                                password    = $Matches[2]
                            }
                            Add-DiscoveredOutbound -OutboundObj $ob -Source $File.Name
                            $foundAny = $true
                        }
                    }
                }
            }
        } catch {
            Write-Warn "JSON parsing error in $($File.Name): $_"
        }
    }

    return $foundAny
}

# ── Helper: Extract Share Links (VLESS, VMess, SS, Trojan, SSH) from text ─────
function Parse-EmbeddedShareLinks {
    param([System.IO.FileInfo]$File)

    $text = Get-Content $File.FullName -Raw
    if (-not $text) { return $false }

    $foundAny = $false

    # Match ssh://user:password@host:port
    $sshMatches = [regex]::Matches($text, 'ssh://([^:]+):([^@]+)@([^:]+):(\d+)')
    foreach ($m in $sshMatches) {
        $ob = [ordered]@{
            type        = "ssh"
            tag         = "SSH-$($m.Groups[3].Value)"
            server      = $m.Groups[3].Value
            server_port = [int]$m.Groups[4].Value
            user        = $m.Groups[1].Value
            password    = $m.Groups[2].Value
        }
        Add-DiscoveredOutbound -OutboundObj $ob -Source $File.Name
        $foundAny = $true
    }

    # Match vless:// links
    $vlessMatches = [regex]::Matches($text, 'vless://([a-fA-F0-9\-]+)@([^:]+):(\d+)(\?[^\s#]+)?(#([^\s]+))?')
    foreach ($m in $vlessMatches) {
        $uuid   = $m.Groups[1].Value
        $server = $m.Groups[2].Value
        $port   = [int]$m.Groups[3].Value
        $query  = $m.Groups[4].Value
        $rawTag = if ($m.Groups[6].Value) { [System.Uri]::UnescapeDataString($m.Groups[6].Value) } else { "VLESS-$server" }

        $ob = [ordered]@{
            type        = "vless"
            tag         = $rawTag
            server      = $server
            server_port = $port
            uuid        = $uuid
        }

        # Query parsing (type=ws, security=reality, sni, etc.)
        if ($query) {
            $q = $query.TrimStart('?')
            $params = @{}
            foreach ($part in ($q -split '&')) {
                $kv = $part -split '=', 2
                if ($kv.Length -eq 2) { $params[$kv[0].ToLowerInvariant()] = [System.Uri]::UnescapeDataString($kv[1]) }
            }

            if ($params.ContainsKey("security")) {
                $sec = $params["security"]
                if ($sec -eq "tls" -or $sec -eq "reality") {
                    $tls = [ordered]@{ enabled = $true }
                    if ($params.ContainsKey("sni")) { $tls["server_name"] = $params["sni"] }
                    if ($sec -eq "reality") {
                        $reality = [ordered]@{ enabled = $true }
                        if ($params.ContainsKey("pbk")) { $reality["public_key"] = $params["pbk"] }
                        if ($params.ContainsKey("sid")) { $reality["short_id"] = $params["sid"] }
                        $tls["reality"] = $reality
                    }
                    $ob["tls"] = $tls
                }
            }

            if ($params.ContainsKey("type") -and $params["type"] -eq "ws") {
                $ws = [ordered]@{ type = "ws" }
                if ($params.ContainsKey("path")) { $ws["path"] = $params["path"] }
                if ($params.ContainsKey("host")) {
                    $ws["headers"] = [ordered]@{ Host = $params["host"] }
                }
                $ob["transport"] = $ws
            }
        }

        Add-DiscoveredOutbound -OutboundObj $ob -Source $File.Name
        $foundAny = $true
    }

    # Match ss:// links
    $ssMatches = [regex]::Matches($text, 'ss://([A-Za-z0-9+/=_-]+)@([^:]+):(\d+)(#([^\s]+))?')
    foreach ($m in $ssMatches) {
        $server = $m.Groups[2].Value
        $port   = [int]$m.Groups[3].Value
        $rawTag = if ($m.Groups[5].Value) { [System.Uri]::UnescapeDataString($m.Groups[5].Value) } else { "SS-$server" }
        $secPart = $m.Groups[1].Value

        try {
            $b64 = $secPart.Replace('-', '+').Replace('_', '/')
            while ($b64.Length % 4 -ne 0) { $b64 += '=' }
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
            $subParts = $decoded -split ':', 2
            if ($subParts.Length -eq 2) {
                $ob = [ordered]@{
                    type        = "shadowsocks"
                    tag         = $rawTag
                    server      = $server
                    server_port = $port
                    method      = $subParts[0]
                    password    = $subParts[1]
                }
                Add-DiscoveredOutbound -OutboundObj $ob -Source $File.Name
                $foundAny = $true
            }
        } catch {}
    }

    return $foundAny
}

# ── SCAN FILES IN TARGET DIRECTORY ──────────────────────────────────────────────
$files = Get-ChildItem -Path $Folder -File
Write-Info "Scanning $($files.Count) file(s) in '$Folder'..."

foreach ($f in $files) {
    $processedFiles++
    $ext = $f.Extension.ToLowerInvariant()
    $name = $f.Name

    $extracted = $false

    # 1. Dark Tunnel format (*.dark)
    if ($ext -eq ".dark") {
        $extracted = Parse-DarkTunnelFile -File $f
    }

    # 2. Decrypted/Unlocked text format (*.txt, *.json)
    if ($ext -in @(".txt", ".json")) {
        $jsonOk = Parse-DecryptedJsonFile -File $f
        $linksOk = Parse-EmbeddedShareLinks -File $f
        $extracted = ($jsonOk -or $linksOk)
    }

    # 3. Encrypted binary container formats
    if ($ext -in @(".hc", ".ehi", ".ssc", ".npvs", ".nm", ".ar")) {
        # Check if any plain text share links leaked inside binary
        $plainOk = Parse-EmbeddedShareLinks -File $f
        if ($plainOk) {
            $extracted = $true
        } else {
            $encryptedBinaryList.Add($f.Name)
        }
    }
}

Write-Host ""
Write-Header "Extraction Summary"
Write-Ok "Total Unique Outbounds Extracted : $($discoveredOutbounds.Count)"

if ($encryptedBinaryList.Count -gt 0) {
    Write-Warn ("{0} encrypted binary file(s) detected (.hc, .ehi, .npvs, .ssc, .nm, .ar):" -f $encryptedBinaryList.Count)
    foreach ($eb in $encryptedBinaryList) {
        Write-Host "    * $eb" -ForegroundColor DarkGray
    }
    Write-Host "    [Note] These formats are proprietary encrypted Android APK containers." -ForegroundColor DarkCyan
    Write-Host "    To unlock them, forward the file to a decryption bot (e.g. Telegram @decrypt_file_vpn / @syuw3n)," -ForegroundColor DarkCyan
    Write-Host "    save the resulting unlocked .txt file back into 'vpn file', and re-run this script!" -ForegroundColor DarkCyan
}

if ($discoveredOutbounds.Count -eq 0) {
    Write-Err "No proxy configurations could be extracted."
    exit 1
}

# ── EXPORT TO STANDARD SING-BOX JSON ───────────────────────────────────────────
$outConfig = [ordered]@{
    outbounds = @($discoveredOutbounds)
}

$outPath = $OutputFile
if (-not [System.IO.Path]::IsPathRooted($outPath)) {
    $outPath = Join-Path $ScriptDir $OutputFile
}

if ((Test-Path $outPath) -and -not $Overwrite) {
    Write-Warn "Output file already exists at: $outPath (overwriting)"
}

$jsonText = $outConfig | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($outPath, $jsonText, [System.Text.UTF8Encoding]::new($false))
Write-Ok "Saved $($discoveredOutbounds.Count) outbounds to: $outPath"

# ── VALIDATE WITH SING-BOX CHECK ────────────────────────────────────────────────
if (Test-Path $singBoxExe) {
    Write-Info "Validating exported configuration with sing-box..."
    $checkProc = Start-Process -FilePath $singBoxExe -ArgumentList "check -c `"$outPath`"" -Wait -NoNewWindow -PassThru
    if ($checkProc.ExitCode -eq 0) {
        Write-Ok "sing-box validation PASSED! File is 100% compliant with sing-box standard."
    } else {
        Write-Warn "sing-box check returned non-zero exit code: $($checkProc.ExitCode)"
    }
} else {
    Write-Warn "sing-box.exe not found for validation, but JSON file created successfully."
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  EXTRACTION COMPLETE!" -ForegroundColor Green
Write-Host ("  Output File : {0}" -f (Split-Path -Leaf $outPath)) -ForegroundColor White
Write-Host ("  Nodes Ready : {0}" -f $discoveredOutbounds.Count) -ForegroundColor Cyan
Write-Host "  You can now run this config with:" -ForegroundColor White
Write-Host ("    .\connect-cluster.ps1   (auto-discovers all configs)") -ForegroundColor Green
Write-Host ("    .\clean-configs.ps1     (health probe sweep)") -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
