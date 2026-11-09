@echo off
title Multip VPN - Per-Connection Round-Robin Rotator (Full Randomizer)
cd /d "D:\CODE\Multip VPN"

echo ================================================================
echo    Multip VPN - True Per-Connection Round-Robin Rotator
echo    Full Randomizer * Kernel Modulo * Tor-Style Hops
echo ================================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\connect-rotator.ps1"

echo.
echo ================================================================
echo   Rotator disconnected. Network restored.
echo ================================================================
pause
