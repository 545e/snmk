@echo off
setlocal
cd /d "%~dp0"
title SWA AI - Cybersecurity Platform and Dashboard

echo ===================================================
echo   SWA AI - Security Operations Center and Cyber Hub
echo ===================================================
echo.

:: Detect Python executable (prefer local virtual environment if present)
set "PY_CMD="
if exist "venv\Scripts\python.exe" (
    set "PY_CMD=venv\Scripts\python.exe"
    goto :py_ready
)

python --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python"
    goto :py_ready
)

py -3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py -3"
    goto :py_ready
)

python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python3"
    goto :py_ready
)

:py_ready
if "%PY_CMD%"=="" (
    echo [-] Python 3 is not found in your Windows PATH!
    echo [!] Please install Python 3.10+ from https://www.python.org/downloads/
    echo [!] IMPORTANT: Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [+] Python environment detected:
%PY_CMD% --version
echo.

:: Auto check essential dependencies
%PY_CMD% -c "import fastapi, uvicorn, httpx, pydantic, bs4" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python dependencies missing. Installing now from requirements.txt...
    %PY_CMD% -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [-] Failed to install dependencies automatically.
        echo [!] Please run manually: %PY_CMD% -m pip install -r requirements.txt
        pause
        exit /b 1
    )
)

echo [+] Starting SNMK Web Server...
echo [+] run.py will select the first free port and open the dashboard there.
echo [+] IMPORTANT: Keep this command prompt window OPEN while using SWA.
echo.

rem Do not open a hard-coded URL: run.py falls back to 8001/8002 when busy
rem and opens the browser at the address it actually bound.
%PY_CMD% run.py
