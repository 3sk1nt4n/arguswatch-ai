@echo off
echo ===================================================
echo   ArgusWatch AI v16.4.6 - TEST SUITE
echo   Solvent CyberSecurity LLC
echo ===================================================
echo.

REM Check backend is running
docker ps --format "{{.Names}}" | findstr arguswatch-backend >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Backend container not running. Run UP.bat first.
    pause
    exit /b 1
)

echo [1/4] Pattern Matcher Tests (12 tests)...
echo -----------------------------------------------
docker exec arguswatch-backend python -m pytest tests/test_pattern_matcher.py -v --tb=short
echo.

echo [2/4] CSS Fix + Sanitizer + Onboard Validation Tests (32 tests)...
echo -----------------------------------------------
docker exec arguswatch-backend python -m pytest tests/test_v16_4_6_css_fix.py tests/test_onboard_validation.py -v --tb=short
echo.

echo [3/4] Matching Strategy Tests (35 tests)...
echo -----------------------------------------------
docker exec arguswatch-backend python -m pytest tests/test_matching_strategies.py -v --tb=short
echo.

echo [4/4] Health + DB Check...
echo -----------------------------------------------
curl -sf http://localhost:7777/health
echo.
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Customers: ' || COUNT(*) FROM customers;"
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Assets:    ' || COUNT(*) FROM customer_assets;"
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Findings:  ' || COUNT(*) FROM findings;"
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -t -c "SELECT 'Detections:' || COUNT(*) FROM detections;"

echo.
echo ===================================================
echo   TEST SUITE COMPLETE
echo ===================================================
pause
