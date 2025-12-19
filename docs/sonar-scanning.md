# SonarQube 原始碼分析指南

## 快速開始

```bash
# 1. 啟動 SonarQube
./scripts/sonar-scan.sh start

# 2. 等待服務就緒後執行分析
./scripts/sonar-scan.sh scan

# 3. 產生報告
./scripts/sonar-scan.sh report
```

## SonarQube vs ZAP

| 特性 | SonarQube (SAST) | ZAP (DAST) |
|------|------------------|------------|
| 分析方式 | 靜態原始碼分析 | 動態運行時掃描 |
| 執行時機 | 開發階段 | 測試/部署階段 |
| 需要運行程式 | ❌ 不需要 | ✅ 需要 |
| 發現類型 | 程式碼缺陷、潛在漏洞 | 實際可利用漏洞 |
| 誤報率 | 較高 | 較低 |
| 涵蓋範圍 | 100% 程式碼 | 可達路徑 |

**互補使用**：SAST 在開發早期發現問題，DAST 在測試階段驗證實際風險。

## 架構說明

```
┌─────────────────────────────────────────────────────────────┐
│                    SonarQube 整合架構                        │
└─────────────────────────────────────────────────────────────┘

  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
  │   common    │    │ vulnerable  │    │   secure    │
  │  (共用模組)  │    │  (漏洞版)   │    │  (安全版)   │
  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
         │                  │                  │
         ▼                  ▼                  ▼
  ┌─────────────────────────────────────────────────────┐
  │              SonarScanner CLI (Docker)              │
  │         讀取 sonar-project.properties              │
  └─────────────────────────┬───────────────────────────┘
                            │
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │                   SonarQube Server                  │
  │                  localhost:9000                     │
  └─────────────────────────┬───────────────────────────┘
                            │
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │                    PostgreSQL                       │
  │                (共用 sonarqube 資料庫)              │
  └─────────────────────────────────────────────────────┘
```

## 命令說明

### 服務管理

```bash
# 啟動 SonarQube (首次約需 2-3 分鐘)
./scripts/sonar-scan.sh start

# 檢查狀態
./scripts/sonar-scan.sh status

# 查看日誌
./scripts/sonar-scan.sh logs

# 停止服務
./scripts/sonar-scan.sh stop
```

### 執行分析

```bash
# 編譯並分析所有模組
./scripts/sonar-scan.sh scan
```

分析過程：
1. 編譯 common 模組
2. 編譯 backend-vulnerable 模組
3. 編譯 backend-secure 模組
4. 編譯 backend-log4shell 模組
5. 執行 SonarScanner 上傳分析

### 產生報告

```bash
# 產生 HTML/JSON 報告
./scripts/sonar-scan.sh report
```

報告輸出：
```
sonar-reports/
├── backend-vulnerable-report.html
├── backend-vulnerable-report.json
├── backend-secure-report.html
├── backend-secure-report.json
├── backend-log4shell-report.html
├── backend-log4shell-report.json
└── comparison-report.html          # 比對報告
```

## OWASP Top 10 對應

SonarQube 內建規則可偵測多種 OWASP Top 10 類別的問題：

| OWASP | 類別 | SonarQube 規則範例 |
|-------|------|-------------------|
| A01 | Broken Access Control | S5144 (IDOR), S5131 (Path Traversal) |
| A02 | Cryptographic Failures | S2278 (Weak Hash), S4426 (Weak Crypto) |
| A03 | Injection | S3649 (SQL Injection), S2076 (Command Injection) |
| A05 | Security Misconfiguration | S4507 (Debug Mode), S5122 (CORS) |
| A07 | Auth Failures | S5344 (Password), S4834 (Session) |
| A08 | Data Integrity | S5135 (Deserialization) |
| A09 | Logging Failures | S5145 (Log Injection) |

## 預期發現

### backend-vulnerable 模組

預計發現大量問題：

- **SQL Injection**: 直接字串拼接 SQL
- **Command Injection**: Runtime.exec() 使用者輸入
- **XSS**: 未過濾輸出
- **Path Traversal**: 檔案路徑未驗證
- **Weak Cryptography**: MD5/DES 使用
- **Hardcoded Credentials**: 寫死的密碼
- **Log Injection**: 未過濾日誌輸入

### backend-secure 模組

預計發現較少問題：

- 使用 Prepared Statements
- 輸入驗證與過濾
- 安全的加密演算法
- 參數化查詢
- 適當的錯誤處理

### backend-log4shell 模組

特別標記：
- **CVE-2021-44228**: Log4Shell 漏洞相關程式碼
- JNDI Lookup 風險

## 首次登入設定

1. 訪問 http://localhost:9000
2. 使用預設帳密: `admin` / `admin`
3. 系統會要求更改密碼
4. 建議密碼: `admin123` (僅供測試)

## Quality Gate

SonarQube 預設 Quality Gate：
- 新增程式碼覆蓋率 > 80%
- 新增問題 < 預設門檻
- 無新增 Blocker/Critical 問題

可在 UI 中調整或停用。

## 常見問題

### Q: 掃描失敗顯示找不到 .class 檔案？
編譯專案後再執行掃描：
```bash
cd backend-vulnerable && mvn compile && cd ..
./scripts/sonar-scan.sh scan
```

### Q: SonarQube 啟動很慢？
首次啟動需要初始化資料庫，約需 2-3 分鐘。可用 `status` 命令檢查。

### Q: 如何只分析特定模組？
修改 `sonar-project.properties` 中的 `sonar.modules` 設定。

### Q: 報告中的 CWE 編號是什麼？
CWE (Common Weakness Enumeration) 是通用弱點列舉標準，用於分類安全問題。

## 進階設定

### 自訂規則集

在 SonarQube UI 中：
1. Administration → Quality Profiles
2. 複製預設 Java 規則集
3. 啟用/停用特定規則
4. 在專案設定中套用

### 排除特定檔案

編輯 `sonar-project.properties`：
```properties
sonar.exclusions=**/test/**,**/generated/**
```

### 設定 Issue 追蹤

整合 Jira/GitHub Issues：
1. Administration → Configuration → General Settings
2. 設定 Issue 追蹤連結

## 與 CI/CD 整合

雖然此專案暫不整合 CI/CD，但以下是常見整合方式：

### GitHub Actions
```yaml
- name: SonarQube Scan
  uses: sonarsource/sonarqube-scan-action@master
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
    SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
```

### Jenkins
```groovy
stage('SonarQube Analysis') {
    withSonarQubeEnv('SonarQube') {
        sh 'mvn sonar:sonar'
    }
}
```

## 參考資源

- [SonarQube 官方文件](https://docs.sonarsource.com/sonarqube/)
- [SonarQube Java 規則](https://rules.sonarsource.com/java)
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE 列表](https://cwe.mitre.org/)
