@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title SNMK - Stop Server

echo ===================================================
echo   SNMK - Shutdown Server
echo ===================================================
echo.

set "STOPPED=0"

if exist ".swa.pid" (
    set /p SWA_PID=<.swa.pid
    rem Validate the recorded PID before killing it: .swa.pid can be stale.
    if defined SWA_PID (
        tasklist /FI "PID eq !SWA_PID!" /NH 2>nul | findstr /I "python" >nul
        if !errorlevel! equ 0 (
            taskkill /PID !SWA_PID! /F /T >nul 2>&1
            set "STOPPED=1"
            echo [+] Stopped SNMK server process !SWA_PID!
        )
    )
    del /f /q ".swa.pid" >nul 2>&1
)

rem Fallback: configured port and the automatic 8001 fallback used by run.py.
if "!STOPPED!"=="0" (
    for %%P in (8000 8001) do (
        if "!STOPPED!"=="0" (
            for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%%P " ^| findstr "LISTENING"') do (
                if "!STOPPED!"=="0" (
                    set "TARGET_PID=%%a"
                    tasklist /FI "PID eq !TARGET_PID!" /NH 2>nul | findstr /I "python" >nul
                    if !errorlevel! equ 0 (
                        taskkill /PID !TARGET_PID! /F /T >nul 2>&1
                        set "STOPPED=1"
                        echo [+] Stopped SNMK server process !TARGET_PID! on port %%P
                    )
                )
            )
        )
    )
)

if "!STOPPED!"=="1" (
    echo [OK] SNMK server stopped successfully.
) else (
    echo [i] No active SNMK server found.
)
echo.
