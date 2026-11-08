@echo off
title Multip VPN - Config Health Cleaner & Pruner
cd /d "D:\CODE\Multip VPN"

echo ================================================================
echo    Multip VPN - Config Cleaner & Antigravity Health Pruner
echo ================================================================
echo.

if "%~1"=="" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\clean-configs.ps1"
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\clean-configs.ps1" -TargetFile "%~nx1"
)

echo.
echo ================================================================
echo   Cleanup completed. Press any key to exit.
echo ================================================================
pause >nul
