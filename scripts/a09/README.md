# A09:2021 - Security Logging and Monitoring Failures

## 📋 概述

此模組展示 OWASP Top 10 2021 中的 **A09: 安全日誌與監控失敗** 漏洞類別。

### 涵蓋的 CWE
- **CWE-778**: Insufficient Logging（日誌記錄不足）
- **CWE-117**: Improper Output Neutralization for Logs（日誌注入）
- **CWE-223**: Omission of Security-relevant Information（缺少安全相關資訊）
- **CWE-532**: Insertion of Sensitive Information into Log File（敏感資料洩露到日誌）
- **CWE-779**: Logging of Excessive Data（過度日誌記錄）

## 🔥 漏洞演示

### 1. 日誌記錄不足 (CWE-778)

**攻擊原理：**
系統沒有記錄失敗的登入嘗試、敏感操作或安全事件，導致無法偵測攻擊行為。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：只記錄成功登入，不記錄失敗
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    if (authenticate(request)) {
        log.info("User logged in: {}", request.getUsername());
        return ResponseEntity.ok("Success");
    }
    // ⚠️ 登入失敗沒有任何日誌記錄
    return ResponseEntity.status(401).body("Failed");
}
```

**安全程式碼：**
```java
// ✅ 安全：記錄所有登入嘗試
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    if (authenticate(request)) {
        auditLogService.logLoginAttempt(username, request, true, null);
        return ResponseEntity.ok("Success");
    }
    // ✅ 記錄失敗嘗試並檢查暴力破解
    auditLogService.logLoginAttempt(username, request, false, "INVALID_CREDENTIALS");
    return ResponseEntity.status(401).body("Failed");
}
```

**攻擊腳本：**
```bash
python brute_force_undetected.py vulnerable
```

### 2. 日誌注入 (CWE-117)

**攻擊原理：**
攻擊者透過 CRLF (\\r\\n) 字元注入，偽造日誌條目以掩蓋攻擊或嫁禍他人。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：直接將使用者輸入寫入日誌
@PostMapping("/search")
public ResponseEntity<?> search(@RequestBody SearchRequest request) {
    log.info("User {} searched for: {}", request.getUsername(), request.getQuery());
    // 攻擊者輸入: "test\n2024-01-01 INFO - Admin granted SUPER_ADMIN role"
    return ResponseEntity.ok(results);
}
```

**安全程式碼：**
```java
// ✅ 安全：過濾 CRLF 字元
private static final Pattern CRLF_PATTERN = Pattern.compile("[\\r\\n]");

public String sanitize(String input) {
    return CRLF_PATTERN.matcher(input).replaceAll("_");
}

@PostMapping("/search")
public ResponseEntity<?> search(@RequestBody SearchRequest request) {
    log.info("User {} searched for: {}", 
            sanitize(request.getUsername()), 
            sanitize(request.getQuery()));
    return ResponseEntity.ok(results);
}
```

**攻擊腳本：**
```bash
python log_injection.py vulnerable
```

### 3. 缺少安全相關資訊 (CWE-223)

**攻擊原理：**
日誌缺少重要的安全上下文（如來源 IP、使用者資訊），導致無法進行有效的鑑識調查。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：日誌缺少上下文
log.info("Data accessed: {}", resourceId);
// 缺少：誰、從哪裡、何時、做了什麼、結果
```

**安全程式碼：**
```java
// ✅ 安全：包含完整的安全上下文
MDC.put("correlationId", correlationId);
MDC.put("userId", userId);
MDC.put("sourceIp", request.getRemoteAddr());
MDC.put("userAgent", request.getHeader("User-Agent"));

log.info("DATA_ACCESS: user={}, resource={}, action={}, outcome={}", 
        username, resourceId, "READ", "SUCCESS");
```

**攻擊腳本：**
```bash
python audit_bypass.py vulnerable
```

### 4. 敏感資料洩露到日誌 (CWE-532)

**攻擊原理：**
密碼、Token、信用卡號等敏感資料被記錄到日誌，攻擊者可透過存取日誌獲取這些資訊。

**漏洞程式碼：**
```java
// ⚠️ 嚴重漏洞：記錄密碼和信用卡號
log.debug("Registration - username: {}, password: {}, creditCard: {}",
        username, password, creditCard);

// ⚠️ 記錄認證 Token
log.info("API call with Authorization: {}", authHeader);
```

**安全程式碼：**
```java
// ✅ 安全：遮罩敏感資料
public Map<String, Object> maskSensitiveData(Map<String, Object> data) {
    Map<String, Object> masked = new HashMap<>();
    for (Map.Entry<String, Object> entry : data.entrySet()) {
        String key = entry.getKey().toLowerCase();
        if (key.contains("password") || key.contains("token") || 
            key.contains("credit") || key.contains("cvv")) {
            masked.put(entry.getKey(), "***MASKED***");
        } else {
            masked.put(entry.getKey(), entry.getValue());
        }
    }
    return masked;
}
```

**攻擊腳本：**
```bash
python sensitive_data_exposure.py vulnerable
```

### 5. 過度日誌記錄 (CWE-779)

**攻擊原理：**
記錄完整的請求體、所有 HTTP 標頭等，可能洩露敏感資訊並造成效能問題。

**漏洞程式碼：**
```java
// ⚠️ 漏洞：記錄完整請求體（可能包含密碼）
log.debug("Full request body: {}", objectMapper.writeValueAsString(requestData));

// ⚠️ 漏洞：記錄所有 HTTP Header（包含 Authorization）
request.getHeaderNames().asIterator().forEachRemaining(header -> {
    log.debug("Header {}: {}", header, request.getHeader(header));
});

// ⚠️ 漏洞：記錄所有 Cookie
for (Cookie cookie : request.getCookies()) {
    log.debug("Cookie {}: {}", cookie.getName(), cookie.getValue());
}
```

**安全程式碼：**
```java
// ✅ 安全：只記錄必要資訊，使用適當的日誌等級
log.info("Request processed: method={}, uri={}, status={}", 
        request.getMethod(), 
        request.getRequestURI(), 
        response.getStatus());

// ✅ 生產環境使用 INFO 等級，避免 DEBUG 洩露資訊
```

## 🛡️ 防禦措施

### 1. 完整的安全事件記錄
```java
// 使用專門的審計服務
@Service
public class AuditLogService {
    
    public void logSecurityEvent(String eventType, String severity,
                                  Long userId, String username,
                                  HttpServletRequest request,
                                  String resource, String action,
                                  String outcome, Map<String, Object> details) {
        
        SecurityAuditLog log = SecurityAuditLog.builder()
                .eventType(eventType)
                .severity(severity)
                .userId(userId)
                .username(sanitize(username))
                .sourceIp(getClientIp(request))
                .userAgent(sanitize(request.getHeader("User-Agent")))
                .resource(resource)
                .action(action)
                .outcome(outcome)
                .correlationId(MDC.get("correlationId"))
                .build();
        
        auditLogRepository.save(log);
    }
}
```

### 2. MDC 支援的結構化日誌
```xml
<!-- logback-spring.xml -->
<encoder class="net.logstash.logback.encoder.LogstashEncoder">
    <includeMdcKeyName>correlationId</includeMdcKeyName>
    <includeMdcKeyName>userId</includeMdcKeyName>
    <includeMdcKeyName>sourceIp</includeMdcKeyName>
</encoder>
```

### 3. 敏感資料遮罩
```java
// 在 logback 中使用 pattern 遮罩
<pattern>%replace(%msg){'(?i)(password|token)["\s:=]+[^"\s,}]+', '$1=***MASKED***'}%n</pattern>
```

### 4. 自動威脅偵測
```java
// 暴力破解偵測
private void checkBruteForceAlert(String username, String sourceIp) {
    LocalDateTime since = LocalDateTime.now().minusMinutes(5);
    long failures = loginAttemptRepository.countFailedAttemptsByUsernameSince(username, since);
    
    if (failures >= 5) {
        createAlert("BRUTE_FORCE", "MEDIUM",
                "偵測到暴力破解嘗試",
                String.format("使用者 %s 在 5 分鐘內登入失敗 %d 次", username, failures),
                null, username, sourceIp);
    }
}
```

### 5. 日誌存取控制
```java
// 只有管理員可以查看審計日誌
@GetMapping("/view/audit")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> viewAuditLogs() {
    // ...
}
```

## 📊 測試 API

### 漏洞版本端點 (Port 8081)

| 方法 | 端點 | 描述 |
|------|------|------|
| POST | `/api/logging/demo/login` | 登入（不記錄失敗） |
| POST | `/api/logging/demo/search` | 搜尋（CRLF 注入） |
| POST | `/api/logging/demo/sensitive-action` | 敏感操作（無審計） |
| POST | `/api/logging/demo/data-access` | 資料存取（缺少上下文） |
| POST | `/api/logging/demo/register` | 註冊（敏感資料洩露） |
| GET | `/api/logging/demo/api-call` | API 呼叫（Token 洩露） |
| POST | `/api/logging/demo/process` | 處理請求（過度日誌） |
| GET | `/api/logging/view/audit` | 查看審計日誌（無認證） |
| GET | `/api/logging/view/login-attempts` | 查看登入嘗試（無認證） |
| GET | `/api/logging/view/alerts` | 查看警報（無認證） |
| GET | `/api/logging/view/file` | 讀取日誌檔案（路徑遍歷風險） |
| GET | `/api/logging/alerts/poll` | 警報輪詢（無認證） |

### 安全版本端點 (Port 8082)

| 方法 | 端點 | 描述 |
|------|------|------|
| POST | `/api/logging/demo/login` | 安全登入（完整審計） |
| POST | `/api/logging/demo/search` | 安全搜尋（CRLF 過濾） |
| POST | `/api/logging/demo/sensitive-action` | 安全操作（完整審計） |
| POST | `/api/logging/demo/data-access` | 安全存取（完整上下文） |
| POST | `/api/logging/demo/register` | 安全註冊（資料遮罩） |
| GET | `/api/logging/view/audit` | 查看審計日誌（需 ADMIN） |
| GET | `/api/logging/view/login-attempts` | 查看登入嘗試（需 ADMIN） |
| GET | `/api/logging/view/alerts` | 查看警報（需 ADMIN） |
| GET | `/api/logging/alerts/poll` | 警報輪詢（需 ADMIN） |
| POST | `/api/logging/alerts/{id}/acknowledge` | 確認警報（需 ADMIN） |
| POST | `/api/logging/alerts/{id}/resolve` | 解決警報（需 ADMIN） |
| GET | `/api/logging/dashboard` | 安全儀表板（需 ADMIN） |

## 🧪 執行測試

```bash
# 進入 attacker 容器
docker exec -it attacker /bin/sh

# 安裝依賴
pip install -r /app/scripts/a09/requirements.txt

# 執行各種攻擊腳本
cd /app/scripts/a09

# 日誌注入攻擊
python log_injection.py both

# 暴力破解（無偵測）
python brute_force_undetected.py both

# 審計繞過
python audit_bypass.py both

# 敏感資料洩露
python sensitive_data_exposure.py both
```

## 📁 資料庫表格

### security_audit_logs
安全審計日誌，記錄所有安全相關事件。

| 欄位 | 類型 | 描述 |
|------|------|------|
| event_type | VARCHAR(50) | LOGIN, LOGOUT, ACCESS, MODIFY, DELETE |
| severity | VARCHAR(20) | DEBUG, INFO, WARN, ERROR, CRITICAL |
| user_id | INTEGER | 使用者 ID |
| source_ip | VARCHAR(45) | 來源 IP |
| correlation_id | VARCHAR(36) | 請求關聯 ID |
| details | JSONB | 額外詳情 |

### login_attempts
登入嘗試記錄，用於暴力破解偵測。

| 欄位 | 類型 | 描述 |
|------|------|------|
| username | VARCHAR(50) | 使用者名稱 |
| success | BOOLEAN | 是否成功 |
| failure_reason | VARCHAR(100) | 失敗原因 |
| source_ip | VARCHAR(45) | 來源 IP |

### security_alerts
安全警報，偵測到威脅時產生。

| 欄位 | 類型 | 描述 |
|------|------|------|
| alert_type | VARCHAR(50) | BRUTE_FORCE, SQL_INJECTION 等 |
| severity | VARCHAR(20) | LOW, MEDIUM, HIGH, CRITICAL |
| acknowledged | BOOLEAN | 是否已確認 |
| resolved | BOOLEAN | 是否已解決 |

## 🔗 相關資源

- [OWASP A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- [CWE-117: Log Injection](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-532: Sensitive Information in Logs](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Logback MDC](https://logback.qos.ch/manual/mdc.html)

## ⚠️ 警告

這些攻擊腳本僅供教育目的。請勿在未經授權的系統上使用這些技術。
