@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
set REPORTS_DIR=%PROJECT_ROOT%\sonar-reports
set SONAR_URL=http://localhost:9000
set SONAR_CONTAINER=owasp-sonarqube

if "%1"=="" goto :show_help
if "%1"=="--help" goto :show_help
if "%1"=="-h" goto :show_help
if "%1"=="help" goto :show_help
if "%1"=="start" goto :start_sonarqube
if "%1"=="stop" goto :stop_sonarqube
if "%1"=="status" goto :check_status
if "%1"=="logs" goto :show_logs
if "%1"=="scan" goto :run_scanœ
if "%1"=="report" goto :generate_report

goto :show_help

:show_banner
echo.
echo ===========================================================
echo      OWASP Teaching - SonarQube Source Code Analysis
echo               Static Application Security Testing
echo ===========================================================
echo.
goto :eof

:show_help
call :show_banner
echo Usage:
echo   %~nx0 ^<command^>
echo.
echo Service Management:
echo   start    Start SonarQube service (first start takes 2-3 minutes)
echo   stop     Stop SonarQube service
echo   status   Check service status
echo   logs     View SonarQube logs
echo.
echo Scan Analysis:
echo   scan     Compile project and run SonarQube analysis
echo   report   Generate HTML/JSON reports from SonarQube API
echo.
echo Other:
echo   --help   Show this help
echo.
goto :eof

:check_docker
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Docker is not running. Please start Docker first.
    exit /b 1
)
goto :eof

:start_sonarqube
call :show_banner
echo [*] Starting SonarQube service...

call :check_docker
if %errorlevel% neq 0 exit /b 1

cd /d "%PROJECT_ROOT%"
docker compose --profile sonar up -d sonarqube

echo [*] Waiting for SonarQube to start (about 2-3 minutes)...

set attempts=0
:wait_loop
if %attempts% geq 60 goto :timeout

curl -s "%SONAR_URL%/api/system/status" 2>nul | findstr /C:"\"status\":\"UP\"" >nul
if %errorlevel%==0 goto :sonar_ready

set /a attempts+=1
echo Waiting... (%attempts%/60)
timeout /t 5 /nobreak >nul
goto :wait_loop

:sonar_ready
echo.
echo [OK] SonarQube is ready!
echo [*] Web UI: %SONAR_URL%
echo [*] Default account: admin / admin
goto :eof

:timeout
echo [!] SonarQube startup timeout
exit /b 1

:stop_sonarqube
call :show_banner
echo [*] Stopping SonarQube service...

cd /d "%PROJECT_ROOT%"
docker compose --profile sonar stop sonarqube

echo [OK] SonarQube stopped
goto :eof

:check_status
call :show_banner
echo ===========================================================
echo   SonarQube Service Status
echo ===========================================================
echo.

curl -s "%SONAR_URL%/api/system/status" 2>nul | findstr /C:"\"status\":\"UP\"" >nul
if %errorlevel%==0 (
    echo [OK] SonarQube is running
    echo     URL: %SONAR_URL%
) else (
    echo [X] SonarQube is not running
    echo [*] Run '%~nx0 start' to start the service
)
echo.
goto :eof

:show_logs
echo [*] SonarQube logs (press Ctrl+C to exit)
docker logs -f "%SONAR_CONTAINER%"
goto :eof

:build_projects
echo [*] Compiling Java projects (using Docker)...

cd /d "%PROJECT_ROOT%"

echo [1/2] Compiling common module...
docker run --rm -v "%PROJECT_ROOT%:/workspace" -v "%USERPROFILE%\.m2:/root/.m2" -w /workspace maven:3.9-eclipse-temurin-21 /bin/bash -c "cd common && mvn clean compile install -q -DskipTests"
if %errorlevel% neq 0 (
    echo [!] common module compilation failed
    exit /b 1
)

echo [2/2] Compiling backend module...
docker run --rm -v "%PROJECT_ROOT%:/workspace" -v "%USERPROFILE%\.m2:/root/.m2" -w /workspace maven:3.9-eclipse-temurin-21 /bin/bash -c "cd backend && mvn clean compile -q -DskipTests"
if %errorlevel% neq 0 (
    echo [!] backend module compilation failed
    exit /b 1
)

if exist "%PROJECT_ROOT%\backend-log4shell" (
    echo [*] Compiling backend-log4shell module...
    docker run --rm -v "%PROJECT_ROOT%:/workspace" -v "%USERPROFILE%\.m2:/root/.m2" -w /workspace/backend-log4shell maven:3.9-eclipse-temurin-8 mvn clean compile -q -DskipTests
    if %errorlevel% neq 0 (
        echo [!] backend-log4shell module compilation failed (non-critical)
    )
)

echo [OK] All modules compiled
goto :eof

:load_token
set SONAR_TOKEN=
if exist "%SCRIPT_DIR%.sonar-config" (
    for /f "delims=" %%i in ('python -c "import json; print(json.load(open('%SCRIPT_DIR%.sonar-config')).get('token', ''))" 2^>nul') do set SONAR_TOKEN=%%i
)
goto :eof

:run_scan
call :show_banner
echo ===========================================================
echo   Running SonarQube Source Code Analysis
echo ===========================================================
echo.

curl -s "%SONAR_URL%/api/system/status" 2>nul | findstr /C:"\"status\":\"UP\"" >nul
if %errorlevel% neq 0 (
    echo [!] SonarQube is not running. Run: %~nx0 start
    exit /b 1
)

echo [*] Checking project and token configuration...
python "%SCRIPT_DIR%sonar-setup.py"
if %errorlevel% neq 0 (
    echo [!] Setup failed
    exit /b 1
)

call :load_token
if "%SONAR_TOKEN%"=="" (
    echo [!] Cannot get token. Run: python scripts\sonar-setup.py
    exit /b 1
)
echo [OK] Token loaded

call :build_projects
if %errorlevel% neq 0 exit /b 1

echo.
echo [*] Starting SonarQube analysis...
echo [*] This may take 3-5 minutes
echo.

cd /d "%PROJECT_ROOT%"

docker run --rm --network host -v "%PROJECT_ROOT%:/usr/src" -w /usr/src sonarsource/sonar-scanner-cli:latest sonar-scanner -Dsonar.host.url="%SONAR_URL%" -Dsonar.login="%SONAR_TOKEN%" -Dsonar.projectKey=owasp-teaching -Dsonar.projectName="OWASP Teaching Application" -Dsonar.java.source=21
if %errorlevel% neq 0 (
    echo [!] SonarQube analysis failed
    exit /b 1
)

echo.
echo [OK] SonarQube analysis completed!
echo [*] View results: %SONAR_URL%/dashboard?id=owasp-teaching
echo.
echo [*] Generate report: %~nx0 report
goto :eof

:generate_report
call :show_banner
echo ===========================================================
echo   Generating SonarQube Analysis Report
echo ===========================================================
echo.

if not exist "%REPORTS_DIR%" mkdir "%REPORTS_DIR%"

python "%SCRIPT_DIR%sonar-report.py"
if %errorlevel% neq 0 (
    echo [!] Report generation failed
    exit /b 1
)

echo.
echo [OK] Report generated!
echo [*] Report directory: %REPORTS_DIR%
goto :eof

endlocal
