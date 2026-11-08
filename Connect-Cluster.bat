@echo off
title Multip VPN Cluster Launcher

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    cd /d "D:\CODE\Multip VPN"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\connect-cluster.ps1"
    goto end
)

:: Re-launch elevated if not already admin
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"D:\CODE\Multip VPN\connect-cluster.ps1\"\"'"

:end
