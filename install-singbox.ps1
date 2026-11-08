#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Downloads and installs the latest sing-box release into the project folder.
    Run this once before using connect-vpn.ps1
#>

$projectDir = $PSScriptRoot
$apiUrl = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

Write-Host "[*] Fetching latest sing-box release..." -ForegroundColor Cyan
try {
    $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
    $version = $release.tag_name
    Write-Host "[+] Latest version: $version" -ForegroundColor Green

    # Find Windows AMD64 asset
    $asset = $release.assets | Where-Object {
        $_.name -like "*windows-amd64*" -and $_.name -like "*.zip"
    } | Select-Object -First 1

    if (-not $asset) {
        Write-Host "[-] Could not find Windows amd64 zip in release assets!" -ForegroundColor Red
        Write-Host "    Assets available:" -ForegroundColor Yellow
        $release.assets | ForEach-Object { Write-Host "      $($_.name)" -ForegroundColor Gray }
        exit 1
    }

    $zipPath = Join-Path $projectDir "sing-box-temp.zip"
    $extractDir = Join-Path $projectDir "sing-box-temp"

    Write-Host "[*] Downloading $($asset.name)..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

    Write-Host "[*] Extracting..." -ForegroundColor Cyan
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    # Find sing-box.exe inside extracted folder
    $exe = Get-ChildItem -Path $extractDir -Filter "sing-box.exe" -Recurse | Select-Object -First 1
    if (-not $exe) {
        Write-Host "[-] sing-box.exe not found in archive!" -ForegroundColor Red
        exit 1
    }

    $dest = Join-Path $projectDir "sing-box.exe"
    Copy-Item $exe.FullName $dest -Force
    Write-Host "[+] sing-box installed: $dest" -ForegroundColor Green

    # Cleanup temp files
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    # Show version
    $ver = & $dest version 2>&1 | Select-Object -First 1
    Write-Host "[+] $ver" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] Now run: .\connect-vpn.ps1" -ForegroundColor Cyan

} catch {
    Write-Host "[-] Failed: $_" -ForegroundColor Red
    Write-Host "    Manual download: https://github.com/SagerNet/sing-box/releases" -ForegroundColor Yellow
    exit 1
}
