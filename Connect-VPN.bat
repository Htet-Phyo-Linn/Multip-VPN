@echo off
title Multip VPN Launcher

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    cd /d "D:\CODE\Multip VPN"
    if "%~1"=="" (
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\connect-hiddify.ps1"
    ) else (
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\connect-hiddify.ps1" -ConfigPath "%~1"
    )
    goto end
)

:: Re-launch elevated if not already admin
if "%~1"=="" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"D:\CODE\Multip VPN\connect-hiddify.ps1\"\"'"
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"D:\CODE\Multip VPN\connect-hiddify.ps1\"\" -ConfigPath \"\"%~1\"\"'"
)

:end
