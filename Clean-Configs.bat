@echo off
title Multip VPN - Config Health Cleaner and Pruner
cd /d "D:\CODE\Multip VPN"

echo ================================================================
echo    Multip VPN - Config Cleaner ^& Antigravity Health Pruner
echo ================================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\clean-configs.ps1" %*

echo.
echo ================================================================
echo   Cleanup completed.
echo ================================================================
if "%~1"=="" pause
