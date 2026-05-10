@echo off
REM Self-elevating launcher. Re-launches itself via UAC if not already admin,
REM then runs Dump-EdgePasswords.ps1 with ExecutionPolicy bypass so it can
REM see Edge processes owned by ALL users on the machine.

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Dump-EdgePasswords.ps1"
echo.
pause
