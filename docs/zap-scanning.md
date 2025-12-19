# OWASP ZAP 安全掃描筆記

> 📅 最後更新：2024-12-15

這份文件記錄 OWASP ZAP 掃描的設定、精進過程與學習筆記，作為日後教材整理的參考。

---

## 目錄

1. [快速開始](#快速開始)
2. [掃描模式比較](#掃描模式比較)
3. [精進歷程](#精進歷程)
4. [ZAP Automation Framework](#zap-automation-framework)
5. [常見問題與解決方案](#常見問題與解決方案)
6. [預期可偵測的漏洞](#預期可偵測的漏洞)
7. [進階調整建議](#進階調整建議)

---

## 快速開始

### 前置條件

```bash
# 1. 啟動所有服務
docker compose up -d

# 2. 確認服務狀態
docker compose ps
```

### 執行掃描

```bash
# 基本掃描 (快速，約 5-10 分鐘)
./scripts/zap-scan.sh vulnerable
./scripts/zap-scan.sh secure

# 進階掃描 (完整，約 30-60 分鐘)
./scripts/zap-scan.sh auto-vulnerable
./scripts/zap-scan.sh auto-secure

# 比對結果
./scripts/zap-scan.sh compare
```

### 查看報告

報告位於 `zap-reports/` 目錄：
- `vulnerable.html` - 漏洞版本 HTML 報告
- `vulnerable.json` - 漏洞版本 JSON 報告 (程式處理用)
- `secure.html` - 安全版本 HTML 報告
- `secure.json` - 安全版本 JSON 報告

---

## 掃描模式比較

| 特性 | 基本模式 | 進階模式 (Automation Framework) |
|------|----------|--------------------------------|
| 命令 | `vulnerable` | `auto-vulnerable` |
| 掃描時間 | 5-10 分鐘 | 30-60 分鐘 |
| 端點探索 | 自動爬取 (有限) | URL 清單 + Spider |
| API 覆蓋率 | 低 (~10 端點) | 高 (~100+ 端點) |
| 認證支援 | 無 | 支援 (待完善) |
| 自訂規則 | 預設 | 可調整強度/閾值 |
| 適用場景 | 快速檢查 | 完整安全評估 |

---

## 精進歷程

### 第一次掃描 (v1.0) - 問題發現

**問題：** 只掃描到根路徑，沒有發現 API 端點

**原因分析：**
1. ZAP 的 Spider 只能爬取 HTML 頁面中的連結
2. 後端只回傳 JSON，沒有 HTML 可供爬取
3. Ajax Spider 需要瀏覽器渲染，對純 API 無效
4. 沒有提供 API 端點清單

**掃描結果：**
```
Vulnerable: Medium 3, Low 1, Info 6
Secure:     Medium 0, Low 0, Info 5
```

只發現：
- CORS Misconfiguration
- CSP Header Not Set
- Spring Actuator 暴露
- 缺少安全標頭

### 第二次掃描 (v2.0) - 改進方案

**解決方案：** 使用 ZAP Automation Framework

1. **建立 URL 清單** (`docker/zap/urls-vulnerable.txt`)
   - 列出所有 100+ API 端點
   - 包含各種 OWASP Top 10 漏洞端點

2. **建立 Automation 設定** (`docker/zap/automation-vulnerable.yaml`)
   - 使用 `import` job 匯入 URL 清單
   - 設定 Spider 深度和範圍
   - 調整 Active Scan 規則強度
   - 自動產生 HTML + JSON 報告

3. **新增掃描模式**
   - `auto-vulnerable` - 進階掃描漏洞版本
   - `auto-secure` - 進階掃描安全版本
   - `auto-both` - 進階掃描兩個版本

---

## ZAP Automation Framework

### 設定檔結構

```yaml
env:
  contexts:
    - name: "Context Name"
      urls: ["http://target:port"]
      includePaths: [".*"]
      excludePaths: [".*\\.js$"]
      authentication: {...}
      users: [...]

jobs:
  - type: passiveScan-config
  - type: import           # 匯入 URL 清單
  - type: spider           # 爬取更多端點
  - type: spiderAjax       # JavaScript 應用爬取
  - type: passiveScan-wait # 等待被動掃描完成
  - type: activeScan       # 主動掃描 (攻擊測試)
  - type: report           # 產生報告
```

### Active Scan 規則設定

可調整每個掃描規則的：
- `strength`: low, medium, high, insane
- `threshold`: off, low, medium, high

```yaml
policyDefinition:
  defaultStrength: "medium"
  defaultThreshold: "medium"
  rules:
    - id: 40018  # SQL Injection
      strength: "high"
      threshold: "low"
```

### 重要規則 ID

| ID | 名稱 | 類別 |
|----|------|------|
| 40018-40022 | SQL Injection 系列 | A03 Injection |
| 40012, 40014 | Cross-Site Scripting | A03 Injection |
| 90020 | Remote OS Command Injection | A03 Injection |
| 6 | Path Traversal | A01 Broken Access |
| 90023 | XML External Entity (XXE) | A05 Misconfig |
| 40046 | Server Side Request Forgery | A10 SSRF |
| 90025 | Expression Language Injection | A03 Injection |

---

## 常見問題與解決方案

### Q1: ZAP 沒有掃描到 API 端點

**原因：** 純 API 應用沒有 HTML 頁面可供爬取

**解決：**
1. 提供 URL 清單 (`urls-vulnerable.txt`)
2. 使用 Automation Framework 的 `import` job
3. 如果有 OpenAPI Spec，使用 `openapi` job

### Q2: 掃描時間太長

**解決：**
1. 限制 Spider 深度：`maxDepth: 5`
2. 限制掃描時間：`maxScanDurationInMins: 30`
3. 減少規則數量：只啟用關鍵規則
4. 降低強度：`defaultStrength: "low"`

### Q3: 報告中有太多誤報

**解決：**
1. 提高閾值：`threshold: "high"`
2. 排除特定路徑：`excludePaths`
3. 使用 Context 設定正確的認證

### Q4: 認證後的端點掃不到

**解決：**
1. 設定 JSON 認證方式
2. 配置 Session 管理 (JWT Token)
3. 使用 ZAP 的 Authentication 設定

```yaml
authentication:
  method: "json"
  parameters:
    loginRequestUrl: "http://target/api/auth/login"
    loginRequestBody: '{"username":"{%username%}","password":"{%password%}"}'
```

---

## 預期可偵測的漏洞

### ZAP 能自動偵測

| 漏洞類型 | OWASP | ZAP 規則 | 預期發現 |
|----------|-------|----------|----------|
| SQL Injection | A03 | 40018-40022 | ✅ 高 |
| XSS | A03 | 40012, 40014 | ✅ 高 |
| Command Injection | A03 | 90020 | ✅ 中 |
| Path Traversal | A01 | 6 | ✅ 高 |
| XXE | A05 | 90023 | ✅ 中 |
| CORS Misconfiguration | A05 | 40040 | ✅ 高 |
| Missing Security Headers | A05 | 10038 等 | ✅ 高 |
| Spring Actuator 暴露 | A05 | 40042 | ✅ 高 |

### ZAP 難以偵測 (需手動驗證)

| 漏洞類型 | OWASP | 原因 |
|----------|-------|------|
| IDOR | A01 | 需要業務邏輯理解 |
| JWT Algorithm None | A02 | 需要特殊 payload |
| Insecure Deserialization | A08 | 需要特定序列化格式 |
| Race Condition | A04 | 需要並發測試 |
| SSRF (內網) | A10 | 需要特殊目標 |
| Log4Shell | A06 | 需要專用掃描器 |

---

## 進階調整建議

### 1. 增加 OpenAPI Spec 支援

如果專案有 Swagger/OpenAPI 文件：

```yaml
jobs:
  - type: openapi
    parameters:
      apiUrl: "http://target/v3/api-docs"
      targetUrl: "http://target"
```

### 2. 增加認證掃描

完善 JWT 認證設定：

```yaml
sessionManagement:
  method: "headers"
  parameters:
    Authorization: "Bearer {%token%}"
```

### 3. 整合 CI/CD

```yaml
# .github/workflows/security-scan.yml
jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start services
        run: docker compose up -d
      - name: Run ZAP scan
        run: ./scripts/zap-scan.sh auto-vulnerable
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: zap-reports/
```

### 4. 自訂報告模板

ZAP 支援自訂報告模板：

```yaml
- type: report
  parameters:
    template: "sarif-json"  # 或自訂模板
    reportDir: "/zap/wrk"
    reportFile: "report"
```

---

## 參考資源

- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [ZAP Docker](https://www.zaproxy.org/docs/docker/)
- [ZAP Scan Rules](https://www.zaproxy.org/docs/alerts/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)

---

## 版本歷程

| 版本 | 日期 | 變更 |
|------|------|------|
| v2.0 | 2024-12-15 | 新增 Automation Framework、URL 清單、進階掃描模式 |
| v1.0 | 2024-12-14 | 初始版本，基本 zap-full-scan.py |
