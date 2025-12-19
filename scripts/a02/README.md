# A02:2021 - Cryptographic Failures
# 密碼學失敗

## 漏洞概述

A02 涵蓋與密碼學相關的失敗，可能導致敏感資料曝露。這包括使用弱加密演算法、不安全的金鑰管理、以及敏感資料的不當處理。

## OWASP 官方說明

- **前身**：A03:2017 Sensitive Data Exposure
- **CWEs**：29 個相關 CWE
- **主要 CWE**：
  - CWE-259: Use of Hard-coded Password
  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  - CWE-331: Insufficient Entropy

## 本專案實作的攻擊情境

### 1. 弱雜湊演算法（MD5/SHA1）
**CWE-327, CWE-328, CWE-916**

漏洞版本使用 MD5 儲存密碼雜湊，可被彩虹表或暴力破解攻擊。

```bash
# 破解密碼雜湊
python scripts/a02/md5_crack.py --crack

# 彩虹表攻擊演示
python scripts/a02/md5_crack.py --rainbow
```

### 2. 弱加密演算法（DES/ECB）
**CWE-326, CWE-329**

漏洞版本使用 DES（56-bit 金鑰）和 ECB 模式加密信用卡號。

```bash
# 提取金鑰並解密
python scripts/a02/weak_encryption.py --decrypt

# ECB 模式分析
python scripts/a02/weak_encryption.py --ecb
```

### 3. 硬編碼密鑰曝露
**CWE-321, CWE-259**

漏洞版本在 `/api/debug/config` 曝露所有敏感設定。

```bash
# 提取敏感設定
python scripts/a02/secret_exposure.py --extract

# 使用洩露的 JWT secret 偽造 Token
python scripts/a02/secret_exposure.py --forge
```

### 4. 不安全的亂數產生器
**CWE-330, CWE-338**

漏洞版本使用 `java.util.Random` 產生可預測的 Token。

```bash
# 預測 Token
python scripts/a02/predict_token.py --predict

# 時間戳 Seed 攻擊
python scripts/a02/predict_token.py --timestamp
```

## 攻擊腳本清單

| 腳本 | 用途 | 主要功能 |
|------|------|----------|
| `md5_crack.py` | 雜湊破解 | 彩虹表查詢、暴力破解 |
| `weak_encryption.py` | 弱加密攻擊 | DES 解密、ECB 分析 |
| `secret_exposure.py` | 敏感資料萃取 | 提取金鑰、偽造 Token |
| `predict_token.py` | 亂數預測 | Seed 猜測、Token 預測 |

## 漏洞版本 vs 安全版本

### 密碼雜湊

| 項目 | 漏洞版本 | 安全版本 |
|------|---------|---------|
| 演算法 | ❌ MD5（已破解） | ✅ BCrypt |
| Salt | ❌ 無 | ✅ 自動包含 |
| Work Factor | ❌ 無 | ✅ 12（可調整） |
| 彩虹表攻擊 | ❌ 可被破解 | ✅ 無效 |

### 資料加密

| 項目 | 漏洞版本 | 安全版本 |
|------|---------|---------|
| 演算法 | ❌ DES（56-bit） | ✅ AES-256 |
| 模式 | ❌ ECB（不安全） | ✅ GCM（認證加密） |
| IV | ❌ 無 | ✅ 隨機 12 bytes |
| 金鑰管理 | ❌ 硬編碼 | ✅ 環境變數 |

### 亂數產生

| 項目 | 漏洞版本 | 安全版本 |
|------|---------|---------|
| 產生器 | ❌ java.util.Random | ✅ SecureRandom |
| 可預測性 | ❌ LCG 可逆推 | ✅ 密碼學安全 |
| Seed 控制 | ❌ 可被設定 | ✅ 不允許 |

## 快速測試

```bash
# 1. 啟動服務
docker-compose up -d

# 2. 安裝依賴
pip install pycryptodome

# 3. 執行完整演示
cd scripts/a02

# MD5 雜湊破解
python md5_crack.py --all

# 弱加密攻擊
python weak_encryption.py --all

# 敏感資料曝露
python secret_exposure.py --all

# 亂數預測
python predict_token.py --all
```

## 漏洞程式碼位置

### 漏洞版本
- `backend-vulnerable/src/main/java/com/owasp/vulnerable/controller/CryptoController.java`
- `backend-vulnerable/src/main/java/com/owasp/vulnerable/controller/ConfigController.java`
- `backend-vulnerable/src/main/java/com/owasp/vulnerable/controller/UserController.java`

```java
// 弱雜湊
MessageDigest md = MessageDigest.getInstance("MD5");

// 弱加密
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

// 不安全亂數
Random insecureRandom = new Random(System.currentTimeMillis());

// 硬編碼金鑰
private static final String DES_KEY = "12345678";
```

### 安全版本
- `backend-secure/src/main/java/com/owasp/secure/controller/CryptoController.java`

```java
// 強雜湊
BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

// 強加密
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

// 安全亂數
SecureRandom secureRandom = new SecureRandom();

// 環境變數金鑰
@Value("${app.encryption.key}")
private String encryptionKey;
```

## 防護建議

1. **使用現代加密演算法**
   - 對稱加密：AES-256-GCM
   - 雜湊：BCrypt, Argon2, scrypt
   - 非對稱：RSA-2048+, ECDSA

2. **安全的金鑰管理**
   - 從環境變數或 Secrets Manager 讀取
   - 定期輪換金鑰
   - 使用 HSM 保護關鍵金鑰

3. **使用安全亂數**
   - Java: `SecureRandom`
   - Python: `secrets` 模組
   - 不要用時間戳作為 seed

4. **保護敏感資料**
   - 生產環境禁用 debug 端點
   - 使用 DTO 過濾敏感欄位
   - 記錄敏感資料存取

5. **傳輸層安全**
   - 強制 HTTPS
   - 使用 HSTS
   - 安全的 TLS 配置

## 相關資源

- [OWASP A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
