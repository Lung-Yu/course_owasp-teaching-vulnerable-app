# A05:2021 - Security Misconfiguration (安全配置錯誤)

## 概述

安全配置錯誤是最常見的 Web 應用程式漏洞之一。當應用程式、框架、應用伺服器、資料庫伺服器、網頁伺服器等未進行適當的安全加固，或使用預設配置時，就會發生此類漏洞。

## 本模組涵蓋的漏洞

### 1. Spring Boot Actuator 端點暴露
- **CWE-16**: Configuration
- **風險等級**: 高
- **描述**: Actuator 提供了生產級別的監控和管理功能，但若配置不當可能洩露敏感資訊

### 2. XXE (XML External Entity) 注入
- **CWE-611**: Improper Restriction of XML External Entity Reference
- **風險等級**: 高
- **描述**: 未正確配置 XML 解析器，允許處理外部實體，可能導致檔案讀取或 SSRF

### 3. 錯誤訊息洩露
- **CWE-209**: Generation of Error Message Containing Sensitive Information
- **CWE-537**: Java Runtime Error Message Containing Sensitive Information
- **風險等級**: 中
- **描述**: 詳細的錯誤訊息可能洩露系統內部結構、資料庫資訊等

### 4. 缺少安全標頭
- **CWE-693**: Protection Mechanism Failure
- **風險等級**: 中
- **描述**: HTTP 回應缺少必要的安全標頭，無法有效防禦各類攻擊

## 攻擊腳本

### actuator_exploit.py - Actuator 端點利用
```bash
# 基本探測
python actuator_exploit.py

# 下載 heapdump 進行分析
python actuator_exploit.py --download-heapdump

# 比較安全版本
python actuator_exploit.py --compare
```

**可利用的端點**:
- `/actuator/env` - 環境變數（可能包含密碼、API Key）
- `/actuator/heapdump` - JVM 堆轉儲（可用工具分析出敏感資訊）
- `/actuator/beans` - Spring Bean 配置
- `/actuator/configprops` - 配置屬性
- `/actuator/mappings` - API 路徑映射

### xxe_exploit.py - XXE 漏洞利用
```bash
# 讀取 /etc/passwd
python xxe_exploit.py --file /etc/passwd

# SSRF 攻擊
python xxe_exploit.py --ssrf http://localhost:8080/

# 枚舉敏感檔案
python xxe_exploit.py --enumerate

# 內部端口掃描
python xxe_exploit.py --port-scan

# 比較安全版本
python xxe_exploit.py --compare
```

**XXE Payload 範例**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

### error_disclosure.py - 錯誤訊息分析
```bash
# 完整測試
python error_disclosure.py

# 測試特定端點
python error_disclosure.py --endpoint /api/error/sql

# 比較安全版本
python error_disclosure.py --compare
```

**測試端點**:
- `/api/error/null` - NullPointerException
- `/api/error/sql` - SQLException（洩露資料庫結構）
- `/api/error/sensitive` - 包含敏感資訊的錯誤
- `/api/error/nested` - 深層堆疊追蹤
- `/api/error/config` - 配置路徑洩露

### security_headers.py - 安全標頭檢查
```bash
# 檢查安全標頭
python security_headers.py

# 比較兩個版本
python security_headers.py --compare

# 額外檢查 CORS 和 Cookie
python security_headers.py --check-cors --check-cookies
```

**檢查的標頭**:
| 標頭 | 用途 | 建議值 |
|------|------|--------|
| X-Content-Type-Options | 防止 MIME 嗅探 | nosniff |
| X-Frame-Options | 防止點擊劫持 | DENY |
| Content-Security-Policy | 限制資源載入 | default-src 'self' |
| Strict-Transport-Security | 強制 HTTPS | max-age=31536000 |
| Referrer-Policy | 控制 Referer 洩露 | strict-origin-when-cross-origin |

## 漏洞端點

### 漏洞版本 (Port 8081)

| 端點 | 方法 | 漏洞類型 |
|------|------|----------|
| /actuator/* | GET | Actuator 暴露 |
| /api/xml/parse | POST | XXE |
| /api/xml/import-settings | POST | XXE |
| /api/error/null | GET | 堆疊追蹤洩露 |
| /api/error/sql | GET | SQL 錯誤洩露 |
| /api/error/sensitive | GET | 敏感資訊洩露 |

### 安全版本 (Port 8082)

- Actuator 端點受保護（只暴露 health）
- XML 解析已禁用外部實體
- 錯誤訊息使用通用描述
- 添加了所有安全標頭

## 配置差異

### 漏洞版本配置 (application.yml)
```yaml
management:
  endpoints:
    web:
      exposure:
        include: "*"  # 暴露所有端點！
  endpoint:
    env:
      show-values: always  # 顯示所有值！

server:
  error:
    include-stacktrace: always  # 顯示堆疊追蹤！
    include-exception: true
    include-message: always
```

### 安全版本配置
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info  # 只暴露必要端點
  endpoint:
    env:
      show-values: never

server:
  error:
    include-stacktrace: never
    include-exception: false
    include-message: never
```

## 防禦措施

### 1. Actuator 安全配置
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
      base-path: /internal/management  # 修改預設路徑
  endpoint:
    health:
      show-details: never
    env:
      show-values: never
```

### 2. XXE 防禦
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// 禁用 DTD
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁用外部實體
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// 禁用外部 DTD
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// 禁用 XInclude
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

### 3. 錯誤處理
```java
@ControllerAdvice
public class GlobalExceptionHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e) {
        String errorId = UUID.randomUUID().toString().substring(0, 8);
        
        // 只記錄到日誌
        logger.error("Error ID: {} - {}", errorId, e.getMessage(), e);
        
        // 返回通用訊息
        return ResponseEntity.internalServerError().body(Map.of(
            "error", "發生內部錯誤",
            "errorId", errorId
        ));
    }
}
```

### 4. 安全標頭 Filter
```java
@Component
public class SecurityHeadersFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        HttpServletResponse response = (HttpServletResponse) res;
        
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Content-Security-Policy", "default-src 'self'");
        response.setHeader("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains");
        
        chain.doFilter(req, res);
    }
}
```

## Heapdump 分析

下載的 heapdump 可以使用以下工具分析：

```bash
# 使用 strings 快速搜尋
strings heapdump.hprof | grep -i password

# 使用 Eclipse MAT
# 下載: https://www.eclipse.org/mat/

# 使用 VisualVM
visualvm --openfile heapdump.hprof

# 使用 jhat（JDK 內建）
jhat heapdump.hprof
# 然後訪問 http://localhost:7000
```

## 參考資源

- [OWASP A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [Spring Boot Actuator Security](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Security Headers](https://securityheaders.com/)
