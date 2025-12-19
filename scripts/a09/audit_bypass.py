#!/usr/bin/env python3
"""
A09:2021 - Audit Bypass / Missing Audit Trail
CWE-778: Insufficient Logging
CWE-223: Omission of Security-relevant Information

攻擊原理：
1. 漏洞版本的敏感操作沒有審計日誌
2. 攻擊者可以執行操作而不留下痕跡
3. 即使有日誌，也缺少重要的安全資訊
"""

import requests
import json
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


def demo_no_audit_vulnerable():
    """
    對漏洞版本進行無審計操作
    """
    print("\n" + "="*60)
    print("漏洞版本 - 敏感操作無審計 (CWE-778, CWE-223)")
    print("="*60)
    
    # 操作 1：刪除使用者（無審計）
    print("\n[1] 執行敏感操作：刪除使用者...")
    payload = {
        "action": "DELETE_USER",
        "targetUser": "victim_user"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/logging/demo/sensitive-action",
        json=payload,
        timeout=10
    )
    print_response(response)
    
    # 操作 2：變更使用者角色（無審計）
    print("\n[2] 執行敏感操作：變更使用者角色...")
    payload = {
        "action": "CHANGE_ROLE",
        "targetUser": "normal_user",
        "newRole": "ADMIN"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/logging/demo/sensitive-action",
        json=payload,
        timeout=10
    )
    print_response(response)
    
    # 操作 3：存取敏感資料（缺少上下文）
    print("\n[3] 存取敏感資料（日誌缺少上下文）...")
    payload = {
        "resourceId": "confidential-document-123"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/logging/demo/data-access",
        json=payload,
        timeout=10
    )
    print_response(response)
    
    print("\n[*] 檢查審計日誌...")
    check_audit_logs_vulnerable()


def check_audit_logs_vulnerable():
    """
    檢查漏洞版本的審計日誌
    """
    try:
        response = requests.get(
            f"{VULNERABLE_URL}/api/logging/view/audit?limit=20",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            logs = data.get("logs", [])
            
            print(f"\n[*] 審計日誌數量: {len(logs)}")
            
            # 檢查是否有相關操作的日誌
            delete_logs = [l for l in logs if "DELETE" in str(l)]
            role_logs = [l for l in logs if "ROLE" in str(l)]
            
            if len(delete_logs) == 0 and len(role_logs) == 0:
                print("\n[!] ⚠️ 沒有找到敏感操作的審計記錄！")
                print("[!] 漏洞：")
                print("    - 管理員操作沒有被記錄")
                print("    - 無法追蹤誰做了什麼")
                print("    - 無法進行合規審計")
                print("    - 事後鑑識困難")
            
    except Exception as e:
        print(f"[!] 無法檢查審計日誌: {e}")


def demo_missing_context_vulnerable():
    """
    展示日誌中缺少的安全上下文
    """
    print("\n" + "="*60)
    print("漏洞版本 - 日誌缺少安全上下文 (CWE-223)")
    print("="*60)
    
    print("""
[*] 漏洞版本的日誌範例：
    
    2024-01-01 10:00:00 INFO - Data accessed: confidential-document-123
    
[*] 缺少的重要資訊：
    ❌ 誰存取了資料（userId, username）
    ❌ 從哪裡存取（source IP）
    ❌ 使用什麼工具（User-Agent）
    ❌ 請求的關聯 ID（用於追蹤請求鏈）
    ❌ Session ID
    ❌ 操作結果（成功/失敗）
    
[*] 這導致的問題：
    - 無法確定誰進行了操作
    - 無法追蹤攻擊來源
    - 無法關聯多個相關事件
    - 鑑識調查無法進行
    """)


def demo_complete_audit_secure():
    """
    對安全版本進行操作並檢查完整審計
    """
    print("\n" + "="*60)
    print("安全版本 - 完整審計日誌")
    print("="*60)
    
    headers = {
        "X-User-Id": "1",
        "X-Username": "admin",
        "X-User-Role": "ADMIN"
    }
    
    # 操作 1：刪除使用者（有完整審計）
    print("\n[1] 執行敏感操作：刪除使用者...")
    payload = {
        "action": "DELETE_USER",
        "targetUser": "victim_user",
        "reason": "Test deletion for audit demo"
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/logging/demo/sensitive-action",
        json=payload,
        headers=headers,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get("auditLogged"):
            print("\n[+] ✓ 操作已被審計記錄")
            print(f"[+] Correlation ID: {data.get('correlationId')}")
    
    # 操作 2：存取敏感資料（有完整上下文）
    print("\n[2] 存取敏感資料（完整上下文記錄）...")
    payload = {
        "resourceId": "confidential-document-123",
        "resourceType": "document"
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/logging/demo/data-access",
        json=payload,
        headers=headers,
        timeout=10
    )
    print_response(response)
    
    # 檢查審計日誌
    print("\n[*] 檢查審計日誌...")
    check_audit_logs_secure()


def check_audit_logs_secure():
    """
    檢查安全版本的審計日誌
    """
    try:
        response = requests.get(
            f"{SECURE_URL}/api/logging/view/audit?page=0&size=10",
            headers={"X-User-Role": "ADMIN"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            logs = data.get("logs", [])
            
            print(f"\n[*] 審計日誌數量: {data.get('totalElements', len(logs))}")
            
            if len(logs) > 0:
                print("\n[+] ✓ 審計日誌包含完整資訊：")
                
                sample_log = logs[0]
                print(f"    - 事件類型: {sample_log.get('eventType')}")
                print(f"    - 使用者: {sample_log.get('username')} (ID: {sample_log.get('userId')})")
                print(f"    - 來源 IP: {sample_log.get('sourceIp')}")
                print(f"    - User-Agent: {sample_log.get('userAgent', 'N/A')[:50]}...")
                print(f"    - 資源: {sample_log.get('resource')}")
                print(f"    - 動作: {sample_log.get('action')}")
                print(f"    - 結果: {sample_log.get('outcome')}")
                print(f"    - 關聯 ID: {sample_log.get('correlationId')}")
                print(f"    - 時間: {sample_log.get('createdAt')}")
                
        elif response.status_code == 403:
            print("[*] 需要管理員權限才能查看審計日誌（這是正確的！）")
            
    except Exception as e:
        print(f"[!] 無法檢查審計日誌: {e}")


def demo_unauthenticated_log_access():
    """
    展示未經認證的日誌存取
    """
    print("\n" + "="*60)
    print("日誌存取權限比較")
    print("="*60)
    
    # 漏洞版本：任何人都可以存取
    print("\n[1] 漏洞版本 - 未經認證存取審計日誌...")
    response = requests.get(
        f"{VULNERABLE_URL}/api/logging/view/audit?limit=5",
        timeout=10
    )
    
    if response.status_code == 200:
        print("[!] ⚠️ 未經認證即可存取審計日誌！")
        print("[!] 這可能洩露敏感的安全資訊")
    else:
        print(f"[*] 狀態碼: {response.status_code}")
    
    # 安全版本：需要 ADMIN 權限
    print("\n[2] 安全版本 - 未經認證存取審計日誌...")
    response = requests.get(
        f"{SECURE_URL}/api/logging/view/audit",
        timeout=10
    )
    
    if response.status_code == 403:
        print("[+] ✓ 存取被拒絕（需要管理員權限）")
    else:
        print(f"[*] 狀態碼: {response.status_code}")
    
    # 使用 ADMIN 權限
    print("\n[3] 安全版本 - 使用管理員權限存取...")
    response = requests.get(
        f"{SECURE_URL}/api/logging/view/audit",
        headers={"X-User-Role": "ADMIN"},
        timeout=10
    )
    
    if response.status_code == 200:
        print("[+] ✓ 管理員可以存取審計日誌")
    else:
        print(f"[*] 狀態碼: {response.status_code}")


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A09:2021 - Audit Bypass / Missing Audit Trail               ║
║  CWE-778: Insufficient Logging                               ║
║  CWE-223: Omission of Security-relevant Information          ║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：執行敏感操作而不留下審計痕跡                      ║
║  防禦方式：完整記錄所有安全事件，包含完整上下文              ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            demo_no_audit_vulnerable()
            demo_missing_context_vulnerable()
        elif target == "secure":
            demo_complete_audit_secure()
        elif target == "access":
            demo_unauthenticated_log_access()
        elif target == "both":
            demo_no_audit_vulnerable()
            demo_missing_context_vulnerable()
            print("\n" + "-"*60 + "\n")
            demo_complete_audit_secure()
            demo_unauthenticated_log_access()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|access|both]")
    else:
        demo_no_audit_vulnerable()
        demo_missing_context_vulnerable()
        print("\n" + "-"*60 + "\n")
        demo_complete_audit_secure()
        print("\n" + "-"*60 + "\n")
        demo_unauthenticated_log_access()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
