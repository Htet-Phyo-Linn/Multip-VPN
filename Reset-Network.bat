@echo off
title Multip VPN - Deep Network Clean & Factory Restoration Tool

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    cd /d "%~dp0"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0reset-network.ps1"
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 0
)

:: Re-launch elevated if not already admin
echo [*] Requesting Administrator privileges to reset network routes and adapters...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0reset-network.ps1\"\"'"
