@echo off
setlocal

echo Starting Vulnerable E-Commerce Application...
echo.

cd /d "%~dp0.."

docker-compose down 2>nul

echo Building and starting services...
docker-compose up -d --build
if %errorlevel% neq 0 (
    echo Failed to start services
    exit /b 1
)

echo.
echo Waiting for services to be ready...
timeout /t 10 /nobreak >nul

echo.
echo Services started successfully!
echo.
echo Access the application:
echo   Frontend:      http://localhost
echo   Backend API:   http://localhost:8081/api
echo   Log4Shell:     http://localhost:8083
echo.
echo View logs:
echo   docker-compose logs -f
echo.
echo Stop services:
echo   docker-compose down

endlocal
