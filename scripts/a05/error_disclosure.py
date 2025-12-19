#!/usr/bin/env python3
"""
A05:2021 - Security Misconfiguration
錯誤訊息洩露測試

此腳本展示錯誤訊息洩露的風險：
1. 堆疊追蹤洩露
2. 資料庫結構洩露
3. 敏感資訊洩露
4. 內部路徑洩露

CWE-209: Generation of Error Message Containing Sensitive Information
CWE-537: Java Runtime Error Message Containing Sensitive Information
"""

import requests
import argparse
import re

# ANSI 顏色
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def print_banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════════════════╗
║  A05 - Error Message Disclosure Analysis Tool                ║
║  錯誤訊息洩露分析工具                                          ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def analyze_error_response(response, endpoint_name):
    """分析錯誤回應中的敏感資訊"""
    findings = []
    text = response.text
    
    # 檢查堆疊追蹤
    stack_trace_patterns = [
        r"at [a-zA-Z0-9_$.]+\([a-zA-Z0-9_]+\.java:\d+\)",
        r"java\.\w+Exception",
        r"org\.springframework\.\w+",
        r"com\.owasp\.\w+",
    ]
    
    for pattern in stack_trace_patterns:
        if re.search(pattern, text):
            findings.append(("堆疊追蹤", "發現 Java 堆疊追蹤資訊"))
            break
    
    # 檢查資料庫資訊
    db_patterns = [
        (r"(mysql|postgres|oracle|sqlite)", "資料庫類型"),
        (r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s", "SQL 語句"),
        (r"table\s+\w+", "資料表名稱"),
        (r"column\s+\w+", "欄位名稱"),
    ]
    
    for pattern, desc in db_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(("資料庫資訊", desc))
    
    # 檢查路徑洩露
    path_patterns = [
        (r"/home/\w+/", "Linux 家目錄路徑"),
        (r"/var/\w+/", "Linux 系統路徑"),
        (r"/opt/\w+/", "應用程式路徑"),
        (r"[A-Z]:\\[\w\\]+", "Windows 路徑"),
        (r"/app/[\w/]+", "容器內路徑"),
    ]
    
    for pattern, desc in path_patterns:
        if re.search(pattern, text):
            findings.append(("路徑洩露", desc))
    
    # 檢查敏感資訊
    sensitive_patterns = [
        (r"password\s*[=:]\s*\S+", "密碼資訊"),
        (r"secret\s*[=:]\s*\S+", "密鑰資訊"),
        (r"token\s*[=:]\s*\S+", "Token 資訊"),
        (r"api[_-]?key\s*[=:]\s*\S+", "API Key"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP 地址"),
    ]
    
    for pattern, desc in sensitive_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(("敏感資訊", desc))
    
    # 檢查類別名稱
    if re.search(r"com\.owasp\.(vulnerable|secure)\.\w+", text):
        findings.append(("內部結構", "內部套件名稱"))
    
    return findings


def trigger_null_pointer(base_url, session):
    """觸發 NullPointerException"""
    print(f"\n{BLUE}[*] 觸發 NullPointerException...{RESET}")
    
    url = f"{base_url}/api/error/null"
    response = session.get(url, timeout=10)
    
    print(f"    狀態碼: {response.status_code}")
    
    findings = analyze_error_response(response, "NullPointerException")
    
    if findings:
        print(f"    {RED}[!] 發現洩露的資訊:{RESET}")
        for category, desc in findings:
            print(f"        - {category}: {desc}")
        
        # 顯示部分回應
        print(f"\n    {YELLOW}回應摘要:{RESET}")
        lines = response.text.split("\n")[:10]
        for line in lines:
            if line.strip():
                print(f"        {line[:100]}")
    else:
        print(f"    {GREEN}[+] 未發現敏感資訊洩露{RESET}")
    
    return findings


def trigger_sql_error(base_url, session):
    """觸發 SQLException"""
    print(f"\n{BLUE}[*] 觸發 SQL 錯誤...{RESET}")
    
    url = f"{base_url}/api/error/sql"
    response = session.get(url, timeout=10)
    
    print(f"    狀態碼: {response.status_code}")
    
    findings = analyze_error_response(response, "SQLException")
    
    if findings:
        print(f"    {RED}[!] 發現洩露的資訊:{RESET}")
        for category, desc in findings:
            print(f"        - {category}: {desc}")
        
        # 特別檢查 SQL 相關資訊
        if "users" in response.text.lower() or "password" in response.text.lower():
            print(f"    {RED}[!] 可能洩露了資料表結構！{RESET}")
    else:
        print(f"    {GREEN}[+] 未發現敏感資訊洩露{RESET}")
    
    return findings


def trigger_sensitive_error(base_url, session):
    """觸發包含敏感資訊的錯誤"""
    print(f"\n{BLUE}[*] 觸發敏感錯誤訊息...{RESET}")
    
    url = f"{base_url}/api/error/sensitive"
    response = session.get(url, timeout=10)
    
    print(f"    狀態碼: {response.status_code}")
    
    findings = analyze_error_response(response, "SensitiveError")
    
    # 特別檢查密碼洩露
    text = response.text.lower()
    if "password" in text and any(c.isalnum() for c in text[text.find("password"):text.find("password")+30]):
        print(f"    {RED}[!] 嚴重：錯誤訊息中包含密碼！{RESET}")
        findings.append(("嚴重", "密碼明文洩露"))
    
    if findings:
        print(f"    {RED}[!] 發現洩露的資訊:{RESET}")
        for category, desc in findings:
            print(f"        - {category}: {desc}")
    else:
        print(f"    {GREEN}[+] 未發現敏感資訊洩露{RESET}")
    
    return findings


def trigger_nested_error(base_url, session):
    """觸發深層巢狀例外"""
    print(f"\n{BLUE}[*] 觸發深層巢狀例外...{RESET}")
    
    url = f"{base_url}/api/error/nested"
    response = session.get(url, timeout=10)
    
    print(f"    狀態碼: {response.status_code}")
    
    findings = analyze_error_response(response, "NestedException")
    
    # 計算堆疊追蹤深度
    at_count = response.text.count("at ")
    if at_count > 10:
        print(f"    {YELLOW}[!] 堆疊追蹤包含 {at_count} 個呼叫點{RESET}")
        findings.append(("堆疊深度", f"{at_count} 個呼叫點"))
    
    if findings:
        print(f"    {RED}[!] 發現洩露的資訊:{RESET}")
        for category, desc in findings:
            print(f"        - {category}: {desc}")
    else:
        print(f"    {GREEN}[+] 未發現敏感資訊洩露{RESET}")
    
    return findings


def trigger_config_error(base_url, session):
    """觸發配置相關錯誤"""
    print(f"\n{BLUE}[*] 觸發配置錯誤...{RESET}")
    
    url = f"{base_url}/api/error/config"
    response = session.get(url, timeout=10)
    
    print(f"    狀態碼: {response.status_code}")
    
    findings = analyze_error_response(response, "ConfigError")
    
    # 特別檢查路徑洩露
    path_matches = re.findall(r"/[\w/.-]+", response.text)
    if path_matches:
        print(f"    {YELLOW}[!] 發現檔案路徑:{RESET}")
        for path in set(path_matches[:5]):
            print(f"        - {path}")
    
    if findings:
        print(f"    {RED}[!] 發現洩露的資訊:{RESET}")
        for category, desc in findings:
            print(f"        - {category}: {desc}")
    else:
        print(f"    {GREEN}[+] 未發現敏感資訊洩露{RESET}")
    
    return findings


def test_invalid_input(base_url, session):
    """測試無效輸入的錯誤處理"""
    print(f"\n{BLUE}[*] 測試無效輸入處理...{RESET}")
    
    test_cases = [
        ("/api/users/abc", "無效 ID 格式"),
        ("/api/users/-1", "負數 ID"),
        ("/api/users/999999", "不存在的 ID"),
        ("/api/nonexistent", "不存在的端點"),
    ]
    
    all_findings = []
    
    for path, desc in test_cases:
        url = f"{base_url}{path}"
        try:
            response = session.get(url, timeout=5)
            findings = analyze_error_response(response, desc)
            
            status = f"{GREEN}安全{RESET}" if not findings else f"{RED}有洩露{RESET}"
            print(f"    {path}: {response.status_code} - {status}")
            
            all_findings.extend(findings)
        except Exception as e:
            print(f"    {path}: {YELLOW}請求失敗{RESET}")
    
    return all_findings


def test_secure_version(base_url, session):
    """測試安全版本的錯誤處理"""
    print(f"\n{BLUE}[*] 測試安全版本的錯誤處理...{RESET}")
    
    endpoints = [
        "/api/error/null",
        "/api/error/array",
        "/api/error/parse",
    ]
    
    all_secure = True
    
    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        try:
            response = session.get(url, timeout=5)
            findings = analyze_error_response(response, endpoint)
            
            if findings:
                print(f"  {RED}[-] {endpoint}: 仍有資訊洩露{RESET}")
                all_secure = False
            else:
                # 檢查是否有 errorId
                try:
                    data = response.json()
                    if "errorId" in data:
                        print(f"  {GREEN}[+] {endpoint}: 安全（有 errorId）{RESET}")
                    else:
                        print(f"  {GREEN}[+] {endpoint}: 安全{RESET}")
                except:
                    print(f"  {GREEN}[+] {endpoint}: 安全{RESET}")
        except Exception as e:
            print(f"  {YELLOW}[?] {endpoint}: 請求失敗{RESET}")
    
    if all_secure:
        print(f"\n  {GREEN}[+] 安全版本正確處理了錯誤訊息！{RESET}")
    
    return all_secure


def main():
    parser = argparse.ArgumentParser(
        description="A05 - 錯誤訊息洩露分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例:
  %(prog)s                    # 完整測試
  %(prog)s --compare          # 比較安全與漏洞版本
  %(prog)s --endpoint /api/error/sql  # 測試特定端點
        """
    )
    parser.add_argument("--vulnerable-url", default="http://localhost:8081",
                        help="漏洞版本 URL")
    parser.add_argument("--secure-url", default="http://localhost:8082",
                        help="安全版本 URL")
    parser.add_argument("--compare", action="store_true",
                        help="比較安全版本與漏洞版本")
    parser.add_argument("--endpoint", help="測試特定端點")
    
    args = parser.parse_args()
    
    print_banner()
    
    session = requests.Session()
    
    print(f"{YELLOW}[*] 目標: {args.vulnerable_url}{RESET}")
    
    all_findings = []
    
    if args.endpoint:
        # 測試特定端點
        url = f"{args.vulnerable_url}{args.endpoint}"
        response = session.get(url, timeout=10)
        findings = analyze_error_response(response, args.endpoint)
        
        print(f"\n{BLUE}[*] 測試 {args.endpoint}{RESET}")
        print(f"    狀態碼: {response.status_code}")
        
        if findings:
            print(f"    {RED}[!] 發現洩露:{RESET}")
            for category, desc in findings:
                print(f"        - {category}: {desc}")
        
        print(f"\n{YELLOW}完整回應:{RESET}")
        print(response.text[:2000])
        
        all_findings = findings
    else:
        # 完整測試
        all_findings.extend(trigger_null_pointer(args.vulnerable_url, session))
        all_findings.extend(trigger_sql_error(args.vulnerable_url, session))
        all_findings.extend(trigger_sensitive_error(args.vulnerable_url, session))
        all_findings.extend(trigger_nested_error(args.vulnerable_url, session))
        all_findings.extend(trigger_config_error(args.vulnerable_url, session))
        all_findings.extend(test_invalid_input(args.vulnerable_url, session))
    
    # 比較模式
    if args.compare:
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}[*] 比較安全版本: {args.secure_url}{RESET}")
        test_secure_version(args.secure_url, session)
    
    # 總結
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{YELLOW}[*] 測試總結:{RESET}")
    print(f"    發現的問題: {len(all_findings)} 個")
    
    if all_findings:
        # 統計問題類型
        categories = {}
        for category, desc in all_findings:
            categories[category] = categories.get(category, 0) + 1
        
        print(f"    問題分類:")
        for category, count in categories.items():
            print(f"        - {category}: {count} 個")
    
    print(f"\n{YELLOW}[*] 防禦建議:{RESET}")
    print("    1. 設定 server.error.include-stacktrace=never")
    print("    2. 設定 server.error.include-exception=false")
    print("    3. 使用自訂錯誤處理器")
    print("    4. 記錄詳細錯誤到伺服器日誌")
    print("    5. 返回通用錯誤訊息給使用者")
    print("    6. 使用錯誤 ID 便於追蹤")


if __name__ == "__main__":
    main()
