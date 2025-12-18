#!/usr/bin/env python3
# =====================================================
# OWASP SonarQube 專案設定工具
# =====================================================
# 功能：
#   1. 建立 SonarQube 專案（如已存在則跳過）
#   2. 建立/取得 Token
#   3. 輸出設定供掃描腳本使用
#
# 使用方式：
#   python3 scripts/sonar-setup.py           # 互動模式
#   python3 scripts/sonar-setup.py --export  # 輸出環境變數
# =====================================================

import json
import os
import sys
import urllib.request
import urllib.error
import base64
from pathlib import Path

# 顏色定義
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

# 設定
SONAR_URL = os.environ.get('SONAR_URL', 'http://localhost:9000')
SONAR_USER = os.environ.get('SONAR_USER', 'admin')
SONAR_PASSWORD = os.environ.get('SONAR_PASSWORD', 'admin')

# 專案設定
PROJECT_KEY = 'owasp-demo'
PROJECT_NAME = 'OWASP Demo Application'
TOKEN_NAME = 'owasp-scanner-token'

# 設定檔路徑
SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / '.sonar-config'


def api_request(endpoint: str, method: str = 'GET', params: dict = None, 
                user: str = None, password: str = None) -> tuple:
    """發送 SonarQube API 請求，回傳 (success, data)"""
    url = f"{SONAR_URL}/api/{endpoint}"
    
    if params and method == 'GET':
        query_string = '&'.join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{query_string}"
    
    # 認證
    auth_user = user or SONAR_USER
    auth_pass = password or SONAR_PASSWORD
    credentials = f"{auth_user}:{auth_pass}"
    auth_header = base64.b64encode(credentials.encode()).decode()
    
    req = urllib.request.Request(url, method=method)
    req.add_header('Authorization', f'Basic {auth_header}')
    
    if params and method == 'POST':
        data = '&'.join(f"{k}={v}" for k, v in params.items()).encode()
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.data = data
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode()
            if content:
                return True, json.loads(content)
            return True, {}
    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode()
            error_data = json.loads(error_body) if error_body else {}
        except:
            error_data = {'error': str(e)}
        return False, {'status': e.code, 'error': error_data}
    except Exception as e:
        return False, {'error': str(e)}


def check_sonarqube_status() -> bool:
    """檢查 SonarQube 是否運行"""
    print(f"{Colors.BLUE}[*] 檢查 SonarQube 狀態...{Colors.NC}")
    success, data = api_request('system/status')
    if success and data.get('status') == 'UP':
        print(f"{Colors.GREEN}[✓] SonarQube 運行中 (版本: {data.get('version', 'unknown')}){Colors.NC}")
        return True
    print(f"{Colors.RED}[✗] SonarQube 未運行或無法連線{Colors.NC}")
    return False


def check_project_exists() -> bool:
    """檢查專案是否存在"""
    success, data = api_request('projects/search', params={'projects': PROJECT_KEY})
    if success:
        components = data.get('components', [])
        return len(components) > 0
    return False


def create_project() -> bool:
    """建立專案"""
    print(f"{Colors.BLUE}[*] 檢查專案 '{PROJECT_KEY}'...{Colors.NC}")
    
    if check_project_exists():
        print(f"{Colors.GREEN}[✓] 專案已存在，跳過建立{Colors.NC}")
        return True
    
    print(f"{Colors.YELLOW}[*] 建立新專案...{Colors.NC}")
    success, data = api_request('projects/create', method='POST', params={
        'project': PROJECT_KEY,
        'name': PROJECT_NAME
    })
    
    if success:
        print(f"{Colors.GREEN}[✓] 專案建立成功{Colors.NC}")
        return True
    else:
        # 檢查是否因為已存在而失敗
        error_msg = str(data.get('error', ''))
        if 'already exists' in error_msg.lower() or 'key already exists' in error_msg.lower():
            print(f"{Colors.GREEN}[✓] 專案已存在{Colors.NC}")
            return True
        print(f"{Colors.RED}[✗] 專案建立失敗: {data}{Colors.NC}")
        return False


def get_existing_token() -> str:
    """從設定檔讀取已存在的 token"""
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
            token = config.get('token')
            if token:
                # 驗證 token 是否有效
                success, _ = api_request('authentication/validate', 
                                        user=token, password='')
                if success:
                    return token
        except:
            pass
    return None


def create_token() -> str:
    """建立新 token"""
    print(f"{Colors.BLUE}[*] 檢查/建立 Token...{Colors.NC}")
    
    # 先檢查已存在的 token
    existing_token = get_existing_token()
    if existing_token:
        print(f"{Colors.GREEN}[✓] 使用已存在的 Token{Colors.NC}")
        return existing_token
    
    # 先嘗試撤銷舊 token
    api_request('user_tokens/revoke', method='POST', params={'name': TOKEN_NAME})
    
    # 建立新 token
    success, data = api_request('user_tokens/generate', method='POST', params={
        'name': TOKEN_NAME
    })
    
    if success and 'token' in data:
        token = data['token']
        print(f"{Colors.GREEN}[✓] Token 建立成功{Colors.NC}")
        
        # 儲存 token 到設定檔
        save_config(token)
        return token
    else:
        print(f"{Colors.RED}[✗] Token 建立失敗: {data}{Colors.NC}")
        return None


def save_config(token: str):
    """儲存設定到檔案"""
    config = {
        'sonar_url': SONAR_URL,
        'project_key': PROJECT_KEY,
        'token': token
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    # 設定檔案權限為僅擁有者可讀寫
    os.chmod(CONFIG_FILE, 0o600)
    print(f"{Colors.BLUE}[*] 設定已儲存至 {CONFIG_FILE}{Colors.NC}")


def load_config() -> dict:
    """讀取設定"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return {}


def export_env():
    """輸出環境變數設定（供 shell 腳本使用）"""
    config = load_config()
    if config.get('token'):
        print(f"export SONAR_TOKEN='{config['token']}'")
        print(f"export SONAR_URL='{config.get('sonar_url', SONAR_URL)}'")
        print(f"export SONAR_PROJECT_KEY='{config.get('project_key', PROJECT_KEY)}'")
    else:
        print("# No token found. Run: python3 scripts/sonar-setup.py", file=sys.stderr)
        sys.exit(1)


def show_config():
    """顯示目前設定"""
    config = load_config()
    print(f"\n{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}  SonarQube 設定摘要{Colors.NC}")
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  SonarQube URL:  {config.get('sonar_url', SONAR_URL)}")
    print(f"  專案 Key:       {config.get('project_key', PROJECT_KEY)}")
    print(f"  Token:          {'***' + config.get('token', '')[-8:] if config.get('token') else '(未設定)'}")
    print(f"  設定檔:         {CONFIG_FILE}")
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.NC}")
    print()
    print(f"{Colors.GREEN}下一步：{Colors.NC}")
    print(f"  執行掃描:  ./scripts/sonar-scan.sh scan")
    print(f"  產生報告:  python3 scripts/sonar-report.py")
    print()


def main():
    # 處理命令列參數
    if len(sys.argv) > 1:
        if sys.argv[1] == '--export':
            export_env()
            return
        elif sys.argv[1] == '--show':
            show_config()
            return
        elif sys.argv[1] == '--help':
            print("使用方式:")
            print("  python3 sonar-setup.py          # 設定專案和 Token")
            print("  python3 sonar-setup.py --export # 輸出環境變數")
            print("  python3 sonar-setup.py --show   # 顯示目前設定")
            return
    
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}  OWASP SonarQube 專案設定{Colors.NC}")
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.NC}")
    print()
    
    # 1. 檢查 SonarQube 狀態
    if not check_sonarqube_status():
        print(f"\n{Colors.YELLOW}請先啟動 SonarQube:{Colors.NC}")
        print("  ./scripts/sonar-scan.sh start")
        sys.exit(1)
    
    # 2. 建立專案
    if not create_project():
        sys.exit(1)
    
    # 3. 建立 Token
    token = create_token()
    if not token:
        sys.exit(1)
    
    # 4. 顯示設定摘要
    show_config()


if __name__ == '__main__':
    main()
