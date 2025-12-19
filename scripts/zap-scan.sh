#!/bin/bash
# =====================================================
# OWASP ZAP 安全掃描腳本
# =====================================================
# 使用方式：
#   ./scripts/zap-scan.sh scan       - 基本掃描後端
#   ./scripts/zap-scan.sh auto       - 進階掃描 (Automation Framework)
#   ./scripts/zap-scan.sh --help     - 顯示說明
# =====================================================

set -e

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# 專案根目錄
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/zap-reports"

# 顯示標題
show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              OWASP ZAP 安全掃描工具                       ║"
    echo "║         Full Scan + Automation Framework                  ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# 顯示說明
show_help() {
    show_banner
    echo -e "${GREEN}使用方式：${NC}"
    echo "  $0 <command>"
    echo ""
    echo -e "${GREEN}基本掃描 (zap-full-scan.py)：${NC}"
    echo -e "  ${YELLOW}scan${NC}             掃描漏洞版本後端"
    echo ""
    echo -e "${GREEN}進階掃描 (Automation Framework + URL 清單)：${NC}"
    echo -e "  ${MAGENTA}auto${NC}             進階掃描 (包含 100+ API 端點)"
    echo ""
    echo -e "${GREEN}其他命令：${NC}"
    echo -e "  ${YELLOW}--help${NC}           顯示此說明"
    echo ""
    echo -e "${GREEN}報告輸出：${NC}"
    echo "  $REPORTS_DIR/"
    echo "    ├── report.html       (HTML 報告)"
    echo "    ├── report.json       (JSON 報告)"
    echo "    ├── zap-auto-report.html  (進階掃描 HTML 報告)"
    echo "    └── zap-auto-report.json  (進階掃描 JSON 報告)"
    echo ""
    echo -e "${YELLOW}注意事項：${NC}"
    echo "  - 掃描前請確保服務已啟動：docker compose up -d"
    echo "  - 基本掃描約需 5-10 分鐘"
    echo "  - 進階掃描約需 30-60 分鐘 (掃描更多端點)"
    echo "  - 掃描過程中會對目標發送大量請求"
    echo ""
    echo -e "${GREEN}建議：${NC}"
    echo "  首次使用建議先執行基本掃描確認環境正常"
    echo "  然後使用進階掃描 (auto) 獲得更完整的結果"
    echo ""
}

# 檢查服務是否運行
check_services() {
    echo -e "${BLUE}[*] 檢查服務狀態...${NC}"
    
    if ! docker compose -f "$PROJECT_ROOT/docker-compose.yml" ps --status running | grep -q "backend"; then
        echo -e "${RED}[!] backend 服務未運行${NC}"
        echo -e "${YELLOW}[*] 請先執行: docker compose up -d${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] backend 運行中${NC}"
}

# 建立報告目錄
setup_reports_dir() {
    if [ ! -d "$REPORTS_DIR" ]; then
        echo -e "${BLUE}[*] 建立報告目錄: $REPORTS_DIR${NC}"
        mkdir -p "$REPORTS_DIR"
    fi
    # 確保目錄可寫入 (ZAP 容器使用 zap 用戶)
    chmod 777 "$REPORTS_DIR"
}

# 執行掃描
run_scan() {
    local mode=${1:-basic}  # basic 或 auto
    local start_time=$(date +%s)
    
    local profile=$( [ "$mode" = "auto" ] && echo "scan-auto" || echo "scan" )
    local service=$( [ "$mode" = "auto" ] && echo "zap-auto" || echo "zap-scan" )
    local mode_name=$( [ "$mode" = "auto" ] && echo "Automation Framework (進階)" || echo "Full Scan (基本)" )
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  開始掃描: 漏洞版本後端${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}[*] 掃描目標: http://backend:8081${NC}"
    echo -e "${BLUE}[*] 掃描模式: $mode_name${NC}"
    
    if [ "$mode" = "auto" ]; then
        echo -e "${MAGENTA}[*] 使用 URL 清單: docker/zap/urls.txt${NC}"
        echo -e "${MAGENTA}[*] 設定檔: docker/zap/automation.yaml${NC}"
        echo -e "${YELLOW}[*] 預計時間: 30-60 分鐘${NC}"
    else
        echo -e "${YELLOW}[*] 預計時間: 5-10 分鐘${NC}"
    fi
    echo ""
    
    # 執行 ZAP 掃描
    docker compose -f "$PROJECT_ROOT/docker-compose.yml" --profile "$profile" run --rm "$service"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    echo ""
    echo -e "${GREEN}[✓] 掃描完成！耗時: ${minutes}m ${seconds}s${NC}"
    
    if [ "$mode" = "auto" ]; then
        echo -e "${GREEN}[✓] HTML 報告: $REPORTS_DIR/zap-auto-report.html${NC}"
        echo -e "${GREEN}[✓] JSON 報告: $REPORTS_DIR/zap-auto-report.json${NC}"
    else
        echo -e "${GREEN}[✓] HTML 報告: $REPORTS_DIR/report.html${NC}"
        echo -e "${GREEN}[✓] JSON 報告: $REPORTS_DIR/report.json${NC}"
    fi
    echo ""
}

# 快速摘要
show_summary() {
    local report_file=$1
    if [ -f "$REPORTS_DIR/$report_file" ]; then
        echo -e "${BLUE}[*] 掃描摘要:${NC}"
        python3 -c "
import json
with open('$REPORTS_DIR/$report_file', 'r') as f:
    data = json.load(f)
    alerts = data.get('site', [{}])[0].get('alerts', []) if data.get('site') else []
    high = sum(1 for a in alerts if a.get('riskcode') == '3')
    medium = sum(1 for a in alerts if a.get('riskcode') == '2')
    low = sum(1 for a in alerts if a.get('riskcode') == '1')
    info = sum(1 for a in alerts if a.get('riskcode') == '0')
    print(f'  High: {high}, Medium: {medium}, Low: {low}, Informational: {info}')
" 2>/dev/null || echo "  (無法解析報告)"
    fi
}

# 主程式
main() {
    cd "$PROJECT_ROOT"
    
    case "${1:-}" in
        scan)
            show_banner
            check_services
            setup_reports_dir
            run_scan "basic"
            show_summary "report.json"
            ;;
        auto)
            show_banner
            check_services
            setup_reports_dir
            echo -e "${MAGENTA}[*] 使用 Automation Framework 進階掃描模式${NC}"
            echo ""
            run_scan "auto"
            show_summary "zap-auto-report.json"
            ;;
        --help|-h|help)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

main "$@"
