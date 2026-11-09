@echo off
title Multip VPN - Verify IP Rotation
cd /d "D:\CODE\Multip VPN"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\CODE\Multip VPN\test-rotation.ps1"

echo.
pause
