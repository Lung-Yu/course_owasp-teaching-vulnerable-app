@echo off
REM =====================================================
REM OWASP ZAP 安全掃描腳本 (Windows)
REM =====================================================
REM 使用方式：
REM   scripts\zap-scan.bat scan       - 基本掃描後端
REM   scripts\zap-scan.bat auto       - 進階掃描 (Automation Framework)
REM   scripts\zap-scan.bat help       - 顯示說明
REM =====================================================

setlocal enabledelayedexpansion

REM 專案根目錄
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
cd /d "%PROJECT_ROOT%"
set "REPORTS_DIR=%PROJECT_ROOT%\zap-reports"

REM 命令處理
if "%1"=="" goto :show_help
if "%1"=="scan" goto :run_basic_scan
if "%1"=="auto" goto :run_auto_scan
if "%1"=="help" goto :show_help
if "%1"=="--help" goto :show_help
if "%1"=="-h" goto :show_help
goto :show_help

:show_banner
echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║              OWASP ZAP 安全掃描工具                       ║
echo ║         Full Scan + Automation Framework                  ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.
goto :eof

:show_help
call :show_banner
echo 使用方式：
echo   %~nx0 ^<command^>
echo.
echo 基本掃描 (zap-full-scan.py)：
echo   scan             掃描漏洞版本後端
echo.
echo 進階掃描 (Automation Framework + URL 清單)：
echo   auto             進階掃描 (包含 100+ API 端點)
echo.
echo 其他命令：
echo   help             顯示此說明
echo.
echo 報告輸出：
echo   %REPORTS_DIR%\
echo     ├── report.html           (HTML 報告)
echo     ├── report.json           (JSON 報告)
echo     ├── zap-auto-report.html  (進階掃描 HTML 報告)
echo     └── zap-auto-report.json  (進階掃描 JSON 報告)
echo.
echo 注意事項：
echo   - 掃描前請確保服務已啟動：docker compose up -d
echo   - 基本掃描約需 5-10 分鐘
echo   - 進階掃描約需 30-60 分鐘 (掃描更多端點)
echo   - 掃描過程中會對目標發送大量請求
echo.
echo 建議：
echo   首次使用建議先執行基本掃描確認環境正常
echo   然後使用進階掃描 (auto) 獲得更完整的結果
echo.
goto :eof

:check_services
echo [*] 檢查服務狀態...
docker compose -f "%PROJECT_ROOT%\docker-compose.yml" ps --status running | findstr /i "backend" >nul 2>&1
if errorlevel 1 (
    echo [!] backend 服務未運行
    echo [*] 請先執行: docker compose up -d
    exit /b 1
)
echo [✓] backend 運行中
goto :eof

:setup_reports_dir
if not exist "%REPORTS_DIR%" (
    echo [*] 建立報告目錄: %REPORTS_DIR%
    mkdir "%REPORTS_DIR%"
)
goto :eof

:run_basic_scan
call :show_banner
call :check_services
if errorlevel 1 exit /b 1
call :setup_reports_dir

echo ═══════════════════════════════════════════════════════════
echo   開始掃描: 漏洞版本後端
echo ═══════════════════════════════════════════════════════════
echo.
echo [*] 掃描目標: http://backend:8081
echo [*] 掃描模式: Full Scan (基本)
echo [*] 預計時間: 5-10 分鐘
echo.

REM 記錄開始時間
set "START_TIME=%TIME%"

REM 執行 ZAP 掃描
docker compose -f "%PROJECT_ROOT%\docker-compose.yml" --profile scan run --rm zap-scan

echo.
echo [✓] 掃描完成！
echo [✓] HTML 報告: %REPORTS_DIR%\report.html
echo [✓] JSON 報告: %REPORTS_DIR%\report.json
echo.

REM 顯示摘要
call :show_summary "report.json"
goto :eof

:run_auto_scan
call :show_banner
call :check_services
if errorlevel 1 exit /b 1
call :setup_reports_dir

echo [*] 使用 Automation Framework 進階掃描模式
echo.
echo ═══════════════════════════════════════════════════════════
echo   開始掃描: 漏洞版本後端
echo ═══════════════════════════════════════════════════════════
echo.
echo [*] 掃描目標: http://backend:8081
echo [*] 掃描模式: Automation Framework (進階)
echo [*] 使用 URL 清單: docker\zap\urls.txt
echo [*] 設定檔: docker\zap\automation.yaml
echo [*] 預計時間: 30-60 分鐘
echo.

REM 執行 ZAP 掃描
docker compose -f "%PROJECT_ROOT%\docker-compose.yml" --profile scan-auto run --rm zap-auto

echo.
echo [✓] 掃描完成！
echo [✓] HTML 報告: %REPORTS_DIR%\zap-auto-report.html
echo [✓] JSON 報告: %REPORTS_DIR%\zap-auto-report.json
echo.

REM 顯示摘要
call :show_summary "zap-auto-report.json"
goto :eof

:show_summary
set "REPORT_FILE=%~1"
if exist "%REPORTS_DIR%\%REPORT_FILE%" (
    echo [*] 掃描摘要:
    python -c "import json; f=open('%REPORTS_DIR:\=/%/%REPORT_FILE%','r'); data=json.load(f); alerts=data.get('site',[{}])[0].get('alerts',[]) if data.get('site') else []; high=sum(1 for a in alerts if a.get('riskcode')=='3'); medium=sum(1 for a in alerts if a.get('riskcode')=='2'); low=sum(1 for a in alerts if a.get('riskcode')=='1'); info=sum(1 for a in alerts if a.get('riskcode')=='0'); print(f'  High: {high}, Medium: {medium}, Low: {low}, Informational: {info}')" 2>nul || echo   (無法解析報告)
)
goto :eof

:end
endlocal
