@echo off
setlocal enabledelayedexpansion
echo =====================================================================
echo  SNMK C++ High-Speed Native Engine Build Script
echo =====================================================================

set SCRIPT_DIR=%~dp0
set SRC_FILE=%SCRIPT_DIR%src\fast_scanner.cpp
set OUT_DIR=%SCRIPT_DIR%bin
set OUT_EXE=%OUT_DIR%\snmk_fast_scan.exe

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

REM 1. Check for clang++ in PATH or AppData
where clang++ >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [+] Found clang++. Compiling with -O3 optimization...
    clang++ -O3 -std=c++17 -Wall -Wextra "%SRC_FILE%" -lws2_32 -o "%OUT_EXE%"
    goto CHECK_RESULT
)

REM 2. Check for g++ in PATH
where g++ >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [+] Found g++. Compiling with -O3 optimization...
    g++ -O3 -std=c++17 -Wall -Wextra "%SRC_FILE%" -lws2_32 -o "%OUT_EXE%"
    goto CHECK_RESULT
)

REM 3. Check for MSVC cl.exe
where cl >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [+] Found MSVC cl.exe. Compiling with /O2 optimization...
    cl /O2 /std:c++17 /EHsc "%SRC_FILE%" /Fe:"%OUT_EXE%" ws2_32.lib
    goto CHECK_RESULT
)

REM 4. Check for LLVM / MinGW in standard paths
for %%P in (
    "%LOCALAPPDATA%\Microsoft\WinGet\Packages"
    "%LOCALAPPDATA%\Programs\LLVM\bin"
    "C:\Program Files\LLVM\bin"
    "C:\msys64\ucrt64\bin"
    "C:\msys64\mingw64\bin"
    "C:\MinGW\bin"
) do (
    if exist "%%~P\clang++.exe" (
        echo [+] Found clang++ in %%~P
        "%%~P\clang++.exe" -O3 -std=c++17 "%SRC_FILE%" -lws2_32 -o "%OUT_EXE%"
        goto CHECK_RESULT
    )
    if exist "%%~P\g++.exe" (
        echo [+] Found g++ in %%~P
        "%%~P\g++.exe" -O3 -std=c++17 "%SRC_FILE%" -lws2_32 -o "%OUT_EXE%"
        goto CHECK_RESULT
    )
)

echo [!] No C++ compiler (clang++, g++, cl.exe) found in current PATH.
echo [i] You can install LLVM/MinGW or Visual Studio Build Tools to compile natively.
exit /b 1

:CHECK_RESULT
if exist "%OUT_EXE%" (
    echo [OK] Build Successful: %OUT_EXE%
    copy /Y "%OUT_EXE%" "%SCRIPT_DIR%..\tools\bin\snmk_fast_scan.exe" >nul 2>&1
    exit /b 0
) else (
    echo [ERROR] Build failed.
    exit /b 1
)
