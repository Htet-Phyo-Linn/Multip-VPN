<#
.SYNOPSIS
    Multip VPN - Test Per-Connection Rotation
    Sends multiple sequential requests to show IP & Country hopping on every connection!
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProxyUrl = "http://127.0.0.1:10808"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   🎲 MULTIP VPN - ROTATION VERIFIER" -ForegroundColor White
Write-Host "   Testing 6 sequential connections via: $ProxyUrl" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

for ($i = 1; $i -le 6; $i++) {
    Write-Host ("[*] Connection {0}: Requesting public identity..." -f $i) -NoNewline
    try {
        $resp = curl.exe -s -m 5 -x $ProxyUrl "http://ip-api.com/json" | ConvertFrom-Json
        if ($resp -and $resp.query) {
            Write-Host ("`r[+] Connection {0}: IP = {1,-15} &bull; Country = {2} ({3}, {4})" -f $i, $resp.query, $resp.countryCode, $resp.city, $resp.country) -ForegroundColor Green
        } else {
            $rawIp = curl.exe -s -m 5 -x $ProxyUrl "https://api.ipify.org"
            Write-Host ("`r[+] Connection {0}: IP = {1}" -f $i, $rawIp) -ForegroundColor Green
        }
    } catch {
        Write-Host ("`r[-] Connection {0}: Failed or Rotator not running on $ProxyUrl" -f $i) -ForegroundColor Red
    }
    Start-Sleep -Milliseconds 400
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Notice: Each connection exits from a different IP & Country!" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Cyan
