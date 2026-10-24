@echo off
title PhishShield Secure Browser Launcher
cd /d "%~dp0"

echo [PhishShield] Checking backend status on http://127.0.0.1:8000...
powershell -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/health' -UseBasicParsing -TimeoutSec 2; exit 0 } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [PhishShield] Backend not detected. Starting FastAPI security backend...
    start /min "PhishShield Backend" python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
    timeout /t 3 /nobreak >nul
) else (
    echo [PhishShield] Backend is active and connected.
)

echo [PhishShield] Starting Secure Browser...
cd /d "%~dp0browser"
start "" "electron-bin\electron.exe" .



