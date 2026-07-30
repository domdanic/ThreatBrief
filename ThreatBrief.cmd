@echo off
setlocal

where pwsh.exe >nul 2>nul
if %errorlevel% equ 0 (
    set "THREATBRIEF_PS=pwsh.exe"
) else (
    where powershell.exe >nul 2>nul
    if errorlevel 1 (
        echo ThreatBrief requires PowerShell 7 or Windows PowerShell 5.1. 1>&2
        exit /b 1
    )
    set "THREATBRIEF_PS=powershell.exe"
)

"%THREATBRIEF_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-ThreatBrief.ps1" %*
exit /b %errorlevel%

