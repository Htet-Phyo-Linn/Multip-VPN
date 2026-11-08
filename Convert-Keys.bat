@echo off
title Multip VPN - Key to Config JSON Converter
cd /d "D:\CODE\Multip VPN"

echo ================================================================
echo    Multip VPN - Key to sing-box JSON Converter
echo ================================================================
echo.

set "INPUT=%~1"
if "%INPUT%"=="" set "INPUT=key.txt"

echo Target Input File : %INPUT%
echo.
echo Choose output mode:
echo   [1] Bundle ALL keys into ONE file (e.g. config05.json) [Press Enter]
echo   [2] Split into SEPARATE files (1 key per file: config05.json, config06.json...)
echo.
set "MODE=1"
set /p MODE="Select mode [1 or 2, default is 1]: "

echo.
if "%MODE%"=="2" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\convert-keys.ps1" -InputFile "%INPUT%" -Split
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\convert-keys.ps1" -InputFile "%INPUT%"
)

echo.
echo ================================================================
echo   Conversion finished. Press any key to exit.
echo ================================================================
pause >nul
