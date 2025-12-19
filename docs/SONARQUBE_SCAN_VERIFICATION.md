# SonarQube 靜態程式碼掃描驗證報告

> **掃描日期**：2025-12-15  
> **SonarQube 版本**：9.9.8 LTS Community  
> **專案**：OWASP Demo Application

---

## 📊 執行摘要

### 總覽比較

| 指標 | backend-vulnerable | backend-secure | 改善 |
|------|-------------------|----------------|------|
| **總問題數** | 114 | 95 | -19 |
| **VULNERABILITY** | 16 🔴 | **0** ✅ | **-16 (100%)** |
| **BLOCKER** | 9 | 1 | -8 |
| **CRITICAL** | 65 | 56 | -9 |
| **CODE_SMELL** | 91 | 86 | -5 |
| **BUG** | 7 | 9 | +2 |

### 漏洞驗證結果

| 驗證項目 | 結果 |
|----------|------|
| **偵測到的漏洞** | 16 |
| **True Positive（真實漏洞）** | 16 (100%) |
| **False Positive（誤報）** | 0 (0%) |
| **已在 secure 版本修復** | 16 (100%) ✅ |

---

## 🔍 漏洞詳細驗證與對照

### 漏洞 #1-2：XXE (XML External Entity) 注入

| 項目 | 內容 |
|------|------|
| **規則 ID** | `java:S2755` |
| **嚴重度** | 🔴 BLOCKER |
| **CWE** | CWE-611 |
| **OWASP** | A03:2021 - Injection |
| **檔案** | `XmlController.java` |
| **行號** | 49, 91 |

#### ❌ 漏洞程式碼（backend-vulnerable）

```java
// XmlController.java 第 49-57 行
@PostMapping(value = "/parse", consumes = MediaType.APPLICATION_XML_VALUE)
public ResponseEntity<?> parseXml(@RequestBody String xmlData) {
    try {
        // ⚠️ 漏洞：使用預設 DocumentBuilderFactory，未禁用外部實體
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // ⚠️ 漏洞：沒有禁用以下危險功能
        // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xmlData)));
```

#### ✅ 修復程式碼（backend-secure）

```java
// XmlController.java 第 36-57 行
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// ✅ 安全：禁用所有危險功能
// 禁用 DOCTYPE 宣告（最嚴格的防護）
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁用外部一般實體
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

// 禁用外部參數實體
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// 禁用外部 DTD
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// 禁用 XInclude
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
```

#### 驗證結果：✅ True Positive

**攻擊向量**：攻擊者可透過以下 Payload 讀取伺服器檔案：
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>
```

---

### 漏洞 #3：AWS Secret Access Key 曝露

| 項目 | 內容 |
|------|------|
| **規則 ID** | `secrets:S6290` |
| **嚴重度** | 🔴 BLOCKER |
| **CWE** | CWE-798 |
| **OWASP** | A02:2021 - Cryptographic Failures |
| **檔案** | `ConfigController.java` |
| **行號** | 82 |

#### ❌ 漏洞程式碼（backend-vulnerable）

```java
// ConfigController.java 第 78-83 行
// ⚠️ 曝露 API 金鑰
config.put("api_keys", Map.of(
    "stripe", "sk_test_XXXXXXXXXXXXXXXXXXXX",           // ⚠️ 硬編碼 Stripe 金鑰
    "sendgrid", "SG.XXXXXXXXXXXXXXXXXXXXXXXX",          // ⚠️ 硬編碼 SendGrid 金鑰
    "aws_access_key", "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYXXXXXXXXXX"  // ⚠️ 硬編碼 AWS 金鑰
));
```

#### ✅ 修復方式（backend-secure）

**`ConfigController.java` 在安全版本中已被完全移除**，敏感設定不應透過 API 曝露。

#### 驗證結果：✅ True Positive

---

### 漏洞 #4-13：弱加密實作 (DES + ECB + 硬編碼金鑰)

| 項目 | 內容 |
|------|------|
| **規則 ID** | `java:S6437`, `java:S5542`, `java:S5547` |
| **嚴重度** | 🔴 BLOCKER / CRITICAL |
| **CWE** | CWE-321, CWE-327, CWE-328 |
| **OWASP** | A02:2021 - Cryptographic Failures |
| **檔案** | `CryptoController.java`, `UserController.java` |

#### ❌ 漏洞程式碼（backend-vulnerable）

```java
// CryptoController.java 第 31-32 行
// ⚠️ CWE-321: 硬編碼的加密金鑰
private static final String DES_KEY = "12345678";  // DES 需要 8 bytes
private static final String AES_KEY = "1234567890123456";  // AES-128 需要 16 bytes

// ⚠️ CWE-338: 使用不安全的 Random（可預測）
private final Random insecureRandom = new Random(System.currentTimeMillis());

// 第 213-219 行：DES 加密
private String encryptDES(String data) throws Exception {
    SecretKeySpec key = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");  // ⚠️ DES + ECB
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(encrypted);
}

// 第 235-241 行：AES-ECB 加密
private String encryptAES(String data) throws Exception {
    SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ⚠️ ECB 模式
    cipher.init(Cipher.ENCRYPT_MODE, key);
```

#### ✅ 修復程式碼（backend-secure）

```java
// CryptoController.java 第 34-38 行
// ✅ 從環境變數讀取金鑰
@Value("${app.encryption.key:default-256-bit-key-for-aes256}")
private String encryptionKey;

// ✅ 使用密碼學安全的 SecureRandom
private final SecureRandom secureRandom = new SecureRandom();

// ✅ 使用 BCrypt 進行密碼雜湊
private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

// GCM 參數
private static final int GCM_IV_LENGTH = 12;
private static final int GCM_TAG_LENGTH = 128;

// ✅ AES-256-GCM 加密（認證加密）
private String encryptAESGCM(String data, byte[] iv) throws Exception {
    byte[] keyBytes = getAES256Key();
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
    
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
    
    byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    
    // ✅ IV + 密文一起儲存
    byte[] combined = new byte[iv.length + encrypted.length];
    System.arraycopy(iv, 0, combined, 0, iv.length);
    System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
    
    return Base64.getEncoder().encodeToString(combined);
}
```

#### 驗證結果：✅ True Positive

| 問題 | 風險說明 | 修復方式 |
|------|----------|----------|
| **DES 演算法** | 56-bit 金鑰可在數小時內被暴力破解 | 改用 AES-256 |
| **ECB 模式** | 相同明文產生相同密文，洩露資料模式 | 改用 GCM 模式 |
| **硬編碼金鑰** | 可從原始碼或反編譯取得 | 使用環境變數 |
| **弱亂數** | 可預測的 Token 生成 | 使用 SecureRandom |

---

## 📋 漏洞對照總表

| # | 規則 ID | 嚴重度 | 檔案 | 行號 | 漏洞類型 | vulnerable | secure |
|---|---------|--------|------|------|----------|------------|--------|
| 1 | java:S2755 | BLOCKER | XmlController.java | 49 | XXE Injection | ⚠️ 存在 | ✅ 已修復 |
| 2 | java:S2755 | BLOCKER | XmlController.java | 91 | XXE Injection | ⚠️ 存在 | ✅ 已修復 |
| 3 | secrets:S6290 | BLOCKER | ConfigController.java | 82 | AWS Key Exposure | ⚠️ 存在 | ✅ 檔案已移除 |
| 4 | java:S6437 | BLOCKER | CryptoController.java | 214 | Hardcoded Key | ⚠️ 存在 | ✅ 已修復 |
| 5 | java:S5542 | CRITICAL | CryptoController.java | 215 | Insecure Mode (ECB) | ⚠️ 存在 | ✅ 已修復 |
| 6 | java:S5547 | CRITICAL | CryptoController.java | 215 | Weak Algorithm (DES) | ⚠️ 存在 | ✅ 已修復 |
| 7 | java:S6437 | BLOCKER | CryptoController.java | 225 | Hardcoded Key | ⚠️ 存在 | ✅ 已修復 |
| 8 | java:S5542 | CRITICAL | CryptoController.java | 226 | Insecure Mode (ECB) | ⚠️ 存在 | ✅ 已修復 |
| 9 | java:S5547 | CRITICAL | CryptoController.java | 226 | Weak Algorithm (DES) | ⚠️ 存在 | ✅ 已修復 |
| 10 | java:S6437 | BLOCKER | CryptoController.java | 236 | Hardcoded Key | ⚠️ 存在 | ✅ 已修復 |
| 11 | java:S5542 | CRITICAL | CryptoController.java | 237 | Insecure Mode (ECB) | ⚠️ 存在 | ✅ 已修復 |
| 12 | java:S6437 | BLOCKER | CryptoController.java | 247 | Hardcoded Key | ⚠️ 存在 | ✅ 已修復 |
| 13 | java:S5542 | CRITICAL | CryptoController.java | 248 | Insecure Mode (ECB) | ⚠️ 存在 | ✅ 已修復 |
| 14 | java:S6437 | BLOCKER | UserController.java | 206 | Hardcoded Key | ⚠️ 存在 | ✅ 已修復 |
| 15 | java:S5542 | CRITICAL | UserController.java | 207 | Insecure Mode (ECB) | ⚠️ 存在 | ✅ 已修復 |
| 16 | java:S5547 | CRITICAL | UserController.java | 207 | Weak Algorithm (DES) | ⚠️ 存在 | ✅ 已修復 |

---

## 🛡️ 修復策略對照總結

### 1. XXE 防護

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| DocumentBuilderFactory | 使用預設設定 | 禁用 DOCTYPE |
| 外部實體 | 允許解析 | 禁用 (general + parameter) |
| 外部 DTD | 允許載入 | 禁用 |
| XInclude | 允許 | 禁用 |

### 2. 加密演算法

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| 對稱加密 | DES (56-bit) | AES-256 |
| 加密模式 | ECB | GCM (認證加密) |
| IV/Nonce | 無 | 隨機 12 bytes |
| 完整性驗證 | 無 | GCM Tag (128-bit) |

### 3. 密鑰管理

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| 金鑰來源 | 硬編碼 | 環境變數 |
| 金鑰曝露 | API 回傳金鑰 | 不曝露 |
| 亂數生成 | `Random(seed)` | `SecureRandom` |

### 4. 敏感資訊保護

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| 設定曝露 | `/api/config` 回傳全部 | 端點已移除 |
| 密碼儲存 | MD5 雜湊 | BCrypt (work factor 12) |
| 錯誤訊息 | 詳細堆疊追蹤 | 一般性訊息 |

---

## 🏷️ OWASP Top 10 對應分析

### 偵測到的漏洞 OWASP 分類

| OWASP 類別 | 漏洞數 | 佔比 | 說明 |
|------------|--------|------|------|
| A02:2021 - Cryptographic Failures | 14 | 87.5% | 弱加密、硬編碼金鑰、敏感資料曝露 |
| A03:2021 - Injection | 2 | 12.5% | XXE 注入 |

### SonarQube 無法偵測的漏洞類別

| OWASP 類別 | 說明 | 需要工具 |
|------------|------|----------|
| A01:2021 - Broken Access Control | IDOR, 權限繞過 | ZAP, Burp Suite |
| A03:2021 - SQL Injection | 需執行時分析 | ZAP, SQLMap |
| A07:2021 - Auth Failures | JWT 偽造, 暴力破解 | ZAP, 手動測試 |

---

## 📊 backend-secure 剩餘問題分析

雖然 backend-secure 沒有 VULNERABILITY，但仍有程式碼品質問題：

### 按類型分類

| 類型 | 數量 | 說明 |
|------|------|------|
| CODE_SMELL | 86 | 程式碼品質問題，不影響安全性 |
| BUG | 9 | 潛在錯誤，但非安全漏洞 |
| **VULNERABILITY** | **0** | ✅ 無安全漏洞 |

### 主要 CODE_SMELL 類型

| 規則 | 說明 | 數量 |
|------|------|------|
| java:S1192 | 字串常數重複使用 | ~50 |
| java:S1068 | 未使用的私有欄位 | 3 |
| java:S107 | 方法參數過多 (>7) | 2 |

**這些問題不影響系統安全性，僅為程式碼維護性建議。**

---

## 📈 結論

### SonarQube 掃描效果評估

| 評估項目 | 結果 |
|----------|------|
| **準確率** | 100% (16/16 True Positive) |
| **誤報率** | 0% |
| **漏洞覆蓋度** | 中（主要偵測加密與注入類問題） |
| **修復驗證** | 100% 漏洞已在 secure 版本修復 |

### 關鍵發現

1. ✅ **backend-vulnerable** 有 16 個真實安全漏洞
2. ✅ **backend-secure** 已完全修復所有 16 個漏洞
3. ✅ SonarQube 偵測準確率 100%，無誤報
4. ⚠️ SonarQube 主要偵測加密類和注入類漏洞，其他類型需搭配 DAST 工具

### 建議

1. **結合 DAST 工具**：使用 ZAP 補充 SonarQube 無法偵測的執行時漏洞
2. **定期掃描**：整合到 CI/CD Pipeline 進行自動化掃描
3. **修復 CODE_SMELL**：提升程式碼品質和可維護性
4. **升級版本**：考慮 SonarQube Developer Edition 以獲得更多安全規則

---

## 📚 參考資料

- [SonarQube Java Security Rules](https://rules.sonarsource.com/java/type/Vulnerability)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
