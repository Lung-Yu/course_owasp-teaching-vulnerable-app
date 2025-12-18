#!/bin/bash
# =====================================================
# OWASP Teaching Version - SonarQube 原始碼掃描腳本
# =====================================================
# 使用方式：
#   ./scripts/sonar-scan.sh start    - 啟動 SonarQube 服務
#   ./scripts/sonar-scan.sh stop     - 停止 SonarQube 服務
#   ./scripts/sonar-scan.sh status   - 檢查服務狀態
#   ./scripts/sonar-scan.sh scan     - 執行程式碼分析
#   ./scripts/sonar-scan.sh report   - 產生 HTML 報告
#   ./scripts/sonar-scan.sh --help   - 顯示說明
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
REPORTS_DIR="$PROJECT_ROOT/sonar-reports"

# SonarQube 設定
SONAR_URL="http://localhost:9000"
SONAR_CONTAINER="owasp-sonarqube"

# 顯示標題
show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     OWASP Teaching - SonarQube 原始碼分析工具             ║"
    echo "║              靜態程式碼安全掃描 (SAST)                    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# 顯示說明
show_help() {
    show_banner
    echo -e "${GREEN}使用方式：${NC}"
    echo "  $0 <command>"
    echo ""
    echo -e "${GREEN}服務管理：${NC}"
    echo -e "  ${YELLOW}start${NC}    啟動 SonarQube 服務 (首次啟動約需 2-3 分鐘)"
    echo -e "  ${YELLOW}stop${NC}     停止 SonarQube 服務"
    echo -e "  ${YELLOW}status${NC}   檢查服務狀態與健康度"
    echo -e "  ${YELLOW}logs${NC}     查看 SonarQube 日誌"
    echo ""
    echo -e "${GREEN}掃描分析：${NC}"
    echo -e "  ${MAGENTA}scan${NC}     編譯專案並執行 SonarQube 分析"
    echo -e "  ${MAGENTA}report${NC}   從 SonarQube API 產生 HTML/JSON 報告"
    echo ""
    echo -e "${GREEN}其他命令：${NC}"
    echo -e "  ${YELLOW}--help${NC}   顯示此說明"
    echo ""
}

# 檢查 Docker 是否運行
check_docker() {
    if ! docker info &> /dev/null; then
        echo -e "${RED}[!] Docker 未運行，請先啟動 Docker${NC}"
        exit 1
    fi
}

# 啟動 SonarQube
start_sonarqube() {
    echo -e "${BLUE}[*] 啟動 SonarQube 服務...${NC}"
    
    check_docker
    
    cd "$PROJECT_ROOT"
    docker compose --profile sonar up -d sonarqube
    
    echo -e "${BLUE}[*] 等待 SonarQube 啟動 (約 2-3 分鐘)...${NC}"
    
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s "$SONAR_URL/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
            echo -e "${GREEN}[✓] SonarQube 已就緒！${NC}"
            echo -e "${GREEN}[*] Web UI: $SONAR_URL${NC}"
            echo -e "${YELLOW}[*] 預設帳號: admin / admin${NC}"
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo -ne "\r[*] 等待中... ($attempt/$max_attempts)"
        sleep 5
    done
    
    echo -e "${RED}[!] SonarQube 啟動逾時${NC}"
    exit 1
}

# 停止 SonarQube
stop_sonarqube() {
    echo -e "${BLUE}[*] 停止 SonarQube 服務...${NC}"
    
    cd "$PROJECT_ROOT"
    docker compose --profile sonar stop sonarqube
    
    echo -e "${GREEN}[✓] SonarQube 已停止${NC}"
}

# 檢查狀態
check_status() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  SonarQube 服務狀態${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if curl -s "$SONAR_URL/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
        local version=$(curl -s "$SONAR_URL/api/system/status" | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','unknown'))" 2>/dev/null)
        echo -e "${GREEN}[✓] SonarQube 運行中${NC}"
        echo -e "    版本: $version"
        echo -e "    URL:  $SONAR_URL"
    else
        echo -e "${RED}[✗] SonarQube 未運行${NC}"
        echo -e "${YELLOW}[*] 執行 '$0 start' 啟動服務${NC}"
    fi
    echo ""
}

# 查看日誌
show_logs() {
    echo -e "${BLUE}[*] SonarQube 日誌 (按 Ctrl+C 退出)${NC}"
    docker logs -f "$SONAR_CONTAINER" 2>&1 | head -100
}

# 編譯 Java 專案 (使用 Docker 確保環境一致性)
build_projects() {
    echo -e "${BLUE}[*] 編譯 Java 專案 (使用 Docker)...${NC}"
    
    cd "$PROJECT_ROOT"
    
    # Teaching 版本只有 common 和 backend
    echo -e "${CYAN}[1/2] 編譯 common 模組...${NC}"
    
    docker run --rm \
        -v "$PROJECT_ROOT:/workspace" \
        -v "$HOME/.m2:/root/.m2" \
        -w /workspace \
        maven:3.9-eclipse-temurin-21 \
        /bin/bash -c "
            cd common && mvn clean compile install -q -DskipTests
        " || {
            echo -e "${RED}[!] common 模組編譯失敗${NC}"
            exit 1
        }
    
    echo -e "${CYAN}[2/2] 編譯 backend 模組...${NC}"
    
    docker run --rm \
        -v "$PROJECT_ROOT:/workspace" \
        -v "$HOME/.m2:/root/.m2" \
        -w /workspace \
        maven:3.9-eclipse-temurin-21 \
        /bin/bash -c "
            cd backend && mvn clean compile -q -DskipTests
        " || {
            echo -e "${RED}[!] backend 模組編譯失敗${NC}"
            exit 1
        }
    
    # 檢查是否有 backend-log4shell
    if [ -d "$PROJECT_ROOT/backend-log4shell" ]; then
        echo -e "${CYAN}[*] 編譯 backend-log4shell 模組...${NC}"
        
        docker run --rm \
            -v "$PROJECT_ROOT:/workspace" \
            -v "$HOME/.m2:/root/.m2" \
            -w /workspace/backend-log4shell \
            maven:3.9-eclipse-temurin-8 \
            mvn clean compile -q -DskipTests || {
                echo -e "${YELLOW}[!] backend-log4shell 模組編譯失敗 (非關鍵)${NC}"
            }
    fi
    
    echo -e "${GREEN}[✓] 所有模組編譯完成${NC}"
}

# 載入 Token 設定
load_token() {
    local config_file="$SCRIPT_DIR/.sonar-config"
    if [ -f "$config_file" ]; then
        SONAR_TOKEN=$(python3 -c "import json; print(json.load(open('$config_file')).get('token', ''))" 2>/dev/null)
        export SONAR_TOKEN
    fi
}

# 執行 SonarQube 掃描
run_scan() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  執行 SonarQube 原始碼分析${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # 檢查 SonarQube 是否運行
    if ! curl -s "$SONAR_URL/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
        echo -e "${RED}[!] SonarQube 未運行，請先執行: $0 start${NC}"
        exit 1
    fi
    
    # 執行設定（建立專案和 Token）
    echo -e "${BLUE}[*] 檢查專案和 Token 設定...${NC}"
    python3 "$SCRIPT_DIR/sonar-setup.py" || {
        echo -e "${RED}[!] 設定失敗${NC}"
        exit 1
    }
    
    # 載入 Token
    load_token
    if [ -z "$SONAR_TOKEN" ]; then
        echo -e "${RED}[!] 無法取得 Token，請執行: python3 scripts/sonar-setup.py${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] Token 已載入${NC}"
    
    # 編譯專案
    build_projects
    
    echo ""
    echo -e "${MAGENTA}[*] 開始 SonarQube 分析...${NC}"
    echo -e "${YELLOW}[*] 這可能需要 3-5 分鐘${NC}"
    echo ""
    
    local start_time=$(date +%s)
    
    # 建立 sonar-project.properties (如果不存在)
    if [ ! -f "$PROJECT_ROOT/sonar-project.properties" ]; then
        cat > "$PROJECT_ROOT/sonar-project.properties" << 'EOF'
sonar.projectKey=owasp-teaching
sonar.projectName=OWASP Teaching Application
sonar.projectVersion=1.0

# 模組設定
sonar.modules=common,backend

# Common 模組
common.sonar.projectBaseDir=common
common.sonar.sources=src/main/java
common.sonar.java.binaries=target/classes

# Backend 模組
backend.sonar.projectBaseDir=backend
backend.sonar.sources=src/main/java
backend.sonar.java.binaries=target/classes

# 編碼
sonar.sourceEncoding=UTF-8

# 排除檔案
sonar.exclusions=**/node_modules/**,**/target/**,**/*.min.js,**/frontend/**
EOF
    fi
    
    # 使用 Docker 執行 SonarScanner
    cd "$PROJECT_ROOT"
    
    docker run --rm \
        --network host \
        -v "$PROJECT_ROOT:/usr/src" \
        -w /usr/src \
        sonarsource/sonar-scanner-cli:latest \
        sonar-scanner \
        -Dsonar.host.url="$SONAR_URL" \
        -Dsonar.login="$SONAR_TOKEN" \
        -Dsonar.projectKey=owasp-teaching \
        -Dsonar.projectName="OWASP Teaching Application" \
        -Dsonar.java.source=21 || {
            echo -e "${RED}[!] SonarQube 分析失敗${NC}"
            exit 1
        }
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo -e "${GREEN}[✓] SonarQube 分析完成！${NC}"
    echo -e "${BLUE}[*] 耗時: ${duration} 秒${NC}"
    echo -e "${GREEN}[*] 查看結果: $SONAR_URL/dashboard?id=owasp-teaching${NC}"
    echo ""
    echo -e "${YELLOW}[*] 產生報告: $0 report${NC}"
}

# 產生報告
generate_report() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  產生 SonarQube 分析報告${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    mkdir -p "$REPORTS_DIR"
    
    python3 "$SCRIPT_DIR/sonar-report.py" || {
        echo -e "${RED}[!] 報告產生失敗${NC}"
        exit 1
    }
    
    echo ""
    echo -e "${GREEN}[✓] 報告已產生！${NC}"
    echo -e "${BLUE}[*] 報告目錄: $REPORTS_DIR${NC}"
}

# 主程式
main() {
    case "${1:-}" in
        start)
            show_banner
            start_sonarqube
            ;;
        stop)
            show_banner
            stop_sonarqube
            ;;
        status)
            show_banner
            check_status
            ;;
        logs)
            show_logs
            ;;
        scan)
            show_banner
            run_scan
            ;;
        report)
            show_banner
            generate_report
            ;;
        --help|-h|help)
            show_help
            ;;
        *)
            show_help
            ;;
    esac
}

main "$@"
