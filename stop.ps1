<#
.SYNOPSIS
    SNMK - PowerShell Shutdown Script
.DESCRIPTION
    Cleanly shuts down the SNMK background server using .swa.pid and port
    inspection. Only processes that actually look like the SNMK server are
    terminated, so a stale PID file cannot kill an unrelated application.
#>

$ErrorActionPreference = "SilentlyContinue"
Set-Location -Path $PSScriptRoot

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  SNMK - Shutdown Server (PowerShell)" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

$candidates = New-Object System.Collections.Generic.List[int]

# 1. PID recorded by run.py (may be stale, so it is validated below).
$pidFile = Join-Path $PSScriptRoot ".swa.pid"
if (Test-Path $pidFile) {
    $procId = (Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($procId -match '^\d+$') { $candidates.Add([int]$procId) }
}

# 2. Listeners on the configured port plus the automatic 8001 fallback used by
#    run.py when 8000 is occupied (the common case on developer machines).
$configuredPort = if ($env:SWA_PORT -and $env:SWA_PORT -match '^\d+$') { [int]$env:SWA_PORT } else { 8000 }
$ports = @($configuredPort, 8000, 8001) | Sort-Object -Unique
foreach ($port in $ports) {
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        foreach ($owner in $conn.OwningProcess) { $candidates.Add([int]$owner) }
    }
}

$stopped = 0
foreach ($procId in ($candidates | Sort-Object -Unique)) {
    if ($procId -le 0) { continue }
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $procId" -ErrorAction SilentlyContinue
    if (-not $proc) { continue }
    $cmd = [string]$proc.CommandLine
    if ($cmd -match 'run\.py|web\.server|uvicorn') {
        Write-Host "[+] Stopping SNMK server process (PID $procId)..." -ForegroundColor Yellow
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        $stopped += 1
    }
}

Remove-Item $pidFile -Force -ErrorAction SilentlyContinue

if ($stopped -gt 0) {
    Write-Host "[OK] SNMK server stopped ($stopped process(es))." -ForegroundColor Green
} else {
    Write-Host "[i] No active SNMK server process detected." -ForegroundColor Gray
}
