@echo off
title Multip VPN - Live Subscription Connector (Auto-Update)
cd /d "D:\CODE\Multip VPN"

echo ================================================================
echo    Multip VPN - Live Subscription Connector ^& Auto-Updater
echo ================================================================
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\connect-subscription.ps1" %*
    goto end
)

:: Re-launch elevated if not already admin
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"D:\CODE\Multip VPN\connect-subscription.ps1\"\" %*'"

:end
