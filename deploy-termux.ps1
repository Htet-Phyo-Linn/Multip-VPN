<#
.SYNOPSIS
    Multip VPN - Deploy to Termux Android Device
    Transfers termux-vpn.sh and config.json to Termux at 192.168.1.2:8022.
#>

[CmdletBinding()]
param(
    [string]$TermuxUser = "u0_a1384",
    [string]$TermuxIP   = "192.168.1.2",
    [int]$TermuxPort    = 8022,
    [string]$TermuxPass = "rooted"
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err($m)  { Write-Host "[-] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   📲 MULTIP VPN - DEPLOY TO TERMUX (ANDROID)" -ForegroundColor White
Write-Host "   Target: $TermuxUser@$TermuxIP`:$TermuxPort (Password: $TermuxPass)" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = "d:\CODE\Multip VPN" }

$localSh     = Join-Path $scriptDir "termux-vpn.sh"
$localConfig = Join-Path $scriptDir "config.json"

if (-not (Test-Path $localSh)) {
    Write-Err "File not found: $localSh"
    exit 1
}

if (-not (Test-Path $localConfig)) {
    Write-Warn "config.json not found, looking for normal_config.json..."
    $localConfig = Join-Path $scriptDir "normal_config.json"
}

# Convert line endings of termux-vpn.sh to Unix LF before sending
Write-Info "Ensuring Unix (LF) line endings for Termux bash compatibility..."
$content = [System.IO.File]::ReadAllText($localSh)
$unixContent = $content -replace "`r`n", "`n"
$unixTmp = [System.IO.Path]::GetTempFileName()
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($unixTmp, $unixContent, $utf8NoBom)

Write-Info "Testing ping to Termux device ($TermuxIP)..."
$ping = Test-Connection -ComputerName $TermuxIP -Count 1 -Quiet -ErrorAction SilentlyContinue
if ($ping) {
    Write-Ok "Device $TermuxIP is reachable on Wi-Fi."
} else {
    Write-Warn "Device $TermuxIP did not respond to ICMP ping. (Check that phone is on the same Wi-Fi)."
}

Write-Host ""
Write-Host "To copy files and run on Termux, run this command inside Termux:" -ForegroundColor Yellow
Write-Host ""
Write-Host "   # Inside Termux on your phone ($TermuxIP):" -ForegroundColor Cyan
Write-Host "   pkg install -y openssh curl" -ForegroundColor White
Write-Host "   sshd" -ForegroundColor White
Write-Host "   passwd   # set password to: $TermuxPass" -ForegroundColor White
Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Option A: Push files from Windows PC to Termux via SCP:" -ForegroundColor Yellow
Write-Host "   scp -P $TermuxPort `"$localSh`" `"$localConfig`" $TermuxUser@${TermuxIP}:~/" -ForegroundColor White
Write-Host ""
Write-Host "Option B: Run script on Termux directly:" -ForegroundColor Yellow
Write-Host "   cd ~" -ForegroundColor White
Write-Host "   chmod +x termux-vpn.sh" -ForegroundColor White
Write-Host "   ./termux-vpn.sh" -ForegroundColor White
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

# Offer to attempt automatic SCP upload if user has OpenSSH configured
$choice = Read-Host "Attempt automatic SCP upload now? (y/n)"
if ($choice -eq "y" -or $choice -eq "Y") {
    Write-Info "Uploading termux-vpn.sh and $(Split-Path $localConfig -Leaf) to Termux..."
    Write-Host "   (Enter password '$TermuxPass' when prompted by OpenSSH)" -ForegroundColor Gray
    & scp.exe -P $TermuxPort -o StrictHostKeyChecking=no "$unixTmp" "${TermuxUser}@${TermuxIP}:~/termux-vpn.sh"
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "termux-vpn.sh uploaded successfully."
        if (Test-Path $localConfig) {
            & scp.exe -P $TermuxPort -o StrictHostKeyChecking=no "$localConfig" "${TermuxUser}@${TermuxIP}:~/config.json"
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "config.json uploaded successfully."
            }
        }
        Write-Info "Setting execute permissions on Termux..."
        & ssh.exe -p $TermuxPort -o StrictHostKeyChecking=no "${TermuxUser}@${TermuxIP}" "chmod +x ~/termux-vpn.sh"
        Write-Ok "Deployment complete! You can now run ./termux-vpn.sh inside Termux."
    } else {
        Write-Warn "SCP connection failed. Ensure 'sshd' is running in Termux (run 'sshd' in Termux)."
    }
}

Remove-Item $unixTmp -Force -ErrorAction SilentlyContinue
