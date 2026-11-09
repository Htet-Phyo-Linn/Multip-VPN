@echo off
title Multip VPN - Deploy to Termux
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy-termux.ps1"
echo.
pause
