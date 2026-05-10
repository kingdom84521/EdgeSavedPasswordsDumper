@echo off
REM Launches Dump-EdgePasswords.ps1 in current user context, bypassing ExecutionPolicy.
REM Will only see Edge processes owned by the current user.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Dump-EdgePasswords.ps1"
echo.
pause
