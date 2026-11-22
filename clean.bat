@echo off
rem Shortcut allowing commands like "clean", "clean -gpc", "clean config -gpc", "clean configs -gpc"
cd /d "%~dp0"
call "%~dp0Clean-Configs.bat" %*
