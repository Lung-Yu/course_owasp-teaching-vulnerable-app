# A07:2021 - Identification and Authentication Failures
# 識別與驗證失敗

## 漏洞概述

A07 涵蓋與身份驗證和識別相關的安全問題。當應用程式無法正確驗證使用者身份或保護驗證機制時，攻擊者可以冒充其他使用者或繞過驗證。

## OWASP 官方說明

- **前身**：A02:2017 Broken Authentication
- **CWEs**：22 個相關 CWE
- **主要 CWE**：
  - CWE-297: Improper Validation of Certificate with Host Mismatch
  - CWE-287: Improper Authentication
  - CWE-384: Session Fixation

## 本專案實作的攻擊情境

### 1. 暴力破解攻擊（Brute Force）
**CWE-307: Improper Restriction of Excessive Authentication Attempts**

漏洞版本允許無限次登入嘗試，攻擊者可以使用字典攻擊破解密碼。

```bash
# 測試暴力破解
python scripts/a07/brute_force.py --attack alice

# 使用自定義密碼列表
python scripts/a07/brute_force.py --attack admin --wordlist passwords.txt
```

### 2. 使用者名稱列舉（Username Enumeration）
**CWE-204: Observable Response Discrepancy**

漏洞版本對不存在使用者回傳「使用者不存在」，對存在使用者回傳「密碼錯誤」，攻擊者可以藉此判斷帳號是否存在。

```bash
# 列舉有效使用者名稱
python scripts/a07/brute_force.py --enumerate

# 透過 check-username API 列舉
python scripts/a07/brute_force.py --check-api
```

### 3. 弱密碼允許（Weak Password）
**CWE-521: Weak Password Requirements**

漏洞版本沒有密碼強度驗證，允許使用 `123456` 等弱密碼。

```bash
# 測試弱密碼註冊
python scripts/a07/weak_password.py --register

# 測試密碼複雜度要求
python scripts/a07/weak_password.py --complexity
```

### 4. 密碼重設漏洞（Password Reset Flaws）
**CWE-640: Weak Password Recovery Mechanism**

漏洞版本使用可預測的 Token 生成方式：`MD5(username + "fixed-secret-2024")`

```bash
# 預測並利用重設 Token
python scripts/a07/password_reset.py --predict alice

# 測試 Token 重複使用
python scripts/a07/password_reset.py --reuse
```

### 5. JWT 安全問題
**CWE-347: Improper Verification of Cryptographic Signature**

漏洞版本的 JWT 實作存在多種問題。

```bash
# JWT 偽造攻擊
python scripts/a07/jwt_forge.py --demo

# 權限提升攻擊
python scripts/a07/privilege_escalation.py --demo
```

## 攻擊腳本清單

| 腳本 | 用途 | 主要功能 |
|------|------|----------|
| `brute_force.py` | 暴力破解 | 密碼字典攻擊、使用者列舉 |
| `weak_password.py` | 弱密碼測試 | 密碼強度驗證繞過 |
| `password_reset.py` | 密碼重設 | 可預測 Token、Token 重用 |
| `jwt_forge.py` | JWT 攻擊 | Algorithm None、弱金鑰 |
| `privilege_escalation.py` | 權限提升 | 透過 JWT 提升為 Admin |

## 漏洞版本 vs 安全版本

### 登入驗證

| 項目 | 漏洞版本 | 安全版本 |
|------|---------|---------|
| 暴力破解保護 | ❌ 無限制 | ✅ 5 次失敗後鎖定 15 分鐘 |
| 錯誤訊息 | ❌ 洩漏帳號存在資訊 | ✅ 統一「帳號或密碼錯誤」 |
| 時間攻擊 | ❌ 不同回應時間 | ✅ 固定延遲 |

### 密碼強度

| 項目 | 漏洞版本 | 安全版本 |
|------|---------|---------|
| 最低長度 | ❌ 無要求 | ✅ 8 字元 |
| 複雜度 | ❌ 無要求 | ✅ 大小寫+數字 |
| 常見密碼 | ❌ 不檢查 | ✅ 阻擋 Top 10000 |
| 修改密碼 | ❌ 不需舊密碼 | ✅ 驗證舊密碼 |

### 密碼重設

| 項目 | 漏洞版本 | 安全版本 |
|------|---------|---------|
| Token 生成 | ❌ MD5 可預測 | ✅ SecureRandom 32 bytes |
| Token 有效期 | ❌ 永不過期 | ✅ 15 分鐘 |
| Token 使用次數 | ❌ 可重複使用 | ✅ 一次性 |

## 快速測試

```bash
# 1. 啟動服務
docker-compose up -d

# 2. 執行完整演示
cd scripts/a07

# 暴力破解完整測試
python brute_force.py --all

# 弱密碼完整測試
python weak_password.py --all

# 密碼重設完整測試
python password_reset.py --all
```

## 漏洞程式碼位置

### 漏洞版本
- `backend-vulnerable/src/main/java/com/example/demo/controller/AuthController.java`

```java
// 無暴力破解保護
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // 直接驗證，無任何限制
}

// 使用者列舉漏洞
if (!userRepository.existsByUsername(username)) {
    return error("使用者不存在");  // 洩漏帳號存在資訊
}
return error("密碼錯誤");  // 不同的錯誤訊息

// 可預測的 Token
String token = md5(username + "fixed-secret-2024");
```

### 安全版本
- `backend-secure/src/main/java/com/example/demo/controller/AuthController.java`

```java
// 帳號鎖定機制
if (isAccountLocked(username)) {
    return error("帳號已被鎖定，請 15 分鐘後再試");
}

// 統一錯誤訊息
return error("帳號或密碼錯誤");

// 安全的 Token 生成
SecureRandom random = new SecureRandom();
byte[] bytes = new byte[32];
random.nextBytes(bytes);
String token = Base64.getUrlEncoder().encodeToString(bytes);
```

## 防護建議

1. **實施帳號鎖定**
   - 連續失敗 N 次後暫時鎖定
   - 使用漸進式延遲（1s, 2s, 4s, 8s...）
   - 加入 CAPTCHA

2. **統一錯誤訊息**
   - 不要區分「帳號不存在」和「密碼錯誤」
   - 所有驗證失敗都回傳相同訊息

3. **強制密碼強度**
   - 最少 8-12 字元
   - 需要大小寫、數字、特殊字元
   - 檢查常見弱密碼列表

4. **安全的密碼重設**
   - 使用密碼學安全的隨機 Token
   - Token 有效期限（15-30 分鐘）
   - Token 只能使用一次

5. **多因素驗證（MFA）**
   - 實施 TOTP/SMS/Email 二次驗證
   - 對敏感操作強制 MFA

## 相關資源

- [OWASP A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
