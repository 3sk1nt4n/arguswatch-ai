@echo off
echo ===================================================
echo   ArgusWatch AI v16.4.6 - UP
echo   Solvent CyberSecurity LLC
echo ===================================================
echo.

REM Check Docker
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker/Rancher Desktop is not running.
    echo         Start Rancher Desktop first, then try again.
    pause
    exit /b 1
)

echo [1/3] Building + starting all services...
docker compose up -d --build
if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo [2/3] Waiting for backend health...
:WAIT
timeout /t 5 /nobreak >nul
curl -sf http://localhost:7777/health >nul 2>&1
if errorlevel 1 (
    echo       Still waiting...
    goto WAIT
)
echo       Backend healthy.

echo [3/3] All services:
docker ps --format "table {{.Names}}\t{{.Status}}" | findstr arguswatch

echo.
echo ===================================================
echo   ArgusWatch AI v16.4.6 is RUNNING
echo.
echo   Dashboard:  http://localhost:7777
echo   API Docs:   http://localhost:7777/docs
echo   HTTPS:      https://localhost:9443
echo.
echo   Test:   TEST.bat
echo   Logs:   docker compose logs -f backend
echo   Stop:   docker compose down
echo   Nuke:   FRESH-START.bat
echo ===================================================
echo.

start http://localhost:7777
pause
