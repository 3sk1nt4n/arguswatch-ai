@echo off
echo =========================================
echo   ArgusWatch AI-Agentic Threat Intelligence v16.4.6 - One Click Start
echo   Solvent CyberSecurity LLC
echo =========================================
echo.

:: Check Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running. Start Docker Desktop first.
    pause
    exit /b 1
)

echo [1/4] Building and starting 10 services...
docker compose up -d --build

echo [2/4] Waiting for database...
:WAIT_DB
timeout /t 3 /nobreak >nul
docker exec arguswatch-postgres pg_isready -U arguswatch >nul 2>&1
if %errorlevel% neq 0 (
    echo     Still waiting for PostgreSQL...
    goto WAIT_DB
)
echo     PostgreSQL ready.

echo [3/4] Waiting for backend...
:WAIT_BACKEND
timeout /t 3 /nobreak >nul
curl -sf http://localhost:7777/health >nul 2>&1
if %errorlevel% neq 0 (
    echo     Still waiting for backend...
    goto WAIT_BACKEND
)
echo     Backend healthy.

echo [4/4] All services:
timeout /t 2 /nobreak >nul
docker ps --format "table {{.Names}}\t{{.Status}}" | findstr arguswatch

echo.
echo =========================================
echo   ArgusWatch AI is RUNNING
echo.
echo   Dashboard:  http://localhost:7777
echo   HTTPS:      https://localhost
echo   API Docs:   http://localhost:7777/docs
echo   Prometheus: http://localhost:9090
echo.
echo   Logs: docker compose logs -f backend
echo   Stop: docker compose down
echo =========================================
echo.

:: Auto-open browser
start http://localhost:7777

pause
