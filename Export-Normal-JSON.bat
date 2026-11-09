@echo off
title Multip VPN - Extract Normal Clean JSON
cd /d "D:\CODE\Multip VPN"

echo ================================================================
echo    Multip VPN - Sing-box Config to Normal Clean JSON
echo ================================================================
echo.

set "INPUT=%~1"
if not "%INPUT%"=="" (
    echo Input File: %INPUT%
    echo.
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\export-normal-json.ps1" -InputFile "%INPUT%"
    goto finish
)

echo Choose destination:
echo   [1] Save to 'normal_config.json' (Recommended) [Press Enter]
echo   [2] Save directly to 'config.json' (Safety backup created first)
echo.
set "CHOICE=1"
set /p CHOICE="Select option [1 or 2, default is 1]: "

echo.
if "%CHOICE%"=="2" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\export-normal-json.ps1" -OverwriteMaster
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\export-normal-json.ps1"
)

:finish
echo.
echo ================================================================
echo   Export finished. Press any key to exit.
echo ================================================================
pause >nul
