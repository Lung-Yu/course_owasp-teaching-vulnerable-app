# A01:2021 – Broken Access Control 攻擊演示

## 📋 概述

此目錄包含 OWASP Top 10 2021 A01:Broken Access Control（存取控制失效）的各種攻擊腳本。

**存取控制失效**在 2021 年版本中從第五名上升到第一名，顯示這類漏洞在現代應用程式中非常普遍且危險。

## 🎯 攻擊類型

### 1. IDOR - 不安全的直接物件參考 (`idor_exploit.py`)

**漏洞原理**：API 沒有驗證當前使用者是否為資源擁有者。

```bash
# 枚舉訂單 ID
python idor_exploit.py --enum-id

# 枚舉可預測的訂單編號
python idor_exploit.py --enum-number

# 修改其他使用者的訂單
python idor_exploit.py --modify 1

# 取消其他使用者的訂單
python idor_exploit.py --cancel 1

# 比較漏洞/安全版本
python idor_exploit.py --compare
```

**可預測的 ID 問題**：
- 漏洞版本：`ORD-00001`, `ORD-00002` ...
- 安全版本：`f8a3b2c1-4d5e-6f7a-8b9c-0d1e2f3a4b5c`

---

### 2. Path Traversal - 路徑穿越 (`path_traversal.py`)

**漏洞原理**：檔案下載 API 沒有驗證路徑，允許使用 `../` 存取任意檔案。

```bash
# 讀取 flag 檔案
python path_traversal.py --read /flag.txt

# 掃描敏感檔案
python path_traversal.py --scan

# 測試繞過技巧
python path_traversal.py --bypass

# 讀取應用程式原始碼
python path_traversal.py --source
```

**常見目標**：
- `/flag.txt` - CTF Flag
- `/etc/passwd` - 使用者列表
- `/etc/shadow` - 密碼雜湊
- `~/.ssh/id_rsa` - SSH 私鑰

---

### 3. SSRF - 伺服器端請求偽造 (`ssrf_exploit.py`)

> ⚠️ **注意**：SSRF 屬於 OWASP A10:2021，完整版本請見 [`scripts/a10/`](../a10/)
> 
> A10 包含更多進階內容：
> - `ssrf_exploit.py` - 基礎 SSRF 攻擊
> - `url_bypass.py` - URL 驗證繞過技術（Decimal IP、IPv6、開放重定向等）

**漏洞原理**：Webhook API 允許指定任意 URL，伺服器代替使用者發送請求。

```bash
# 存取內部服務
python ssrf_exploit.py --internal

# 掃描內部網路
python ssrf_exploit.py --scan

# 雲端 Metadata 攻擊（AWS/GCP/Azure）
python ssrf_exploit.py --cloud

# 測試 file:// 協定
python ssrf_exploit.py --file

# 測試指定 URL
python ssrf_exploit.py --url "http://internal-api:8080/secrets"
```

**內部服務端點**：
| 端點 | 說明 |
|------|------|
| `/secrets` | 資料庫密碼、API 金鑰 |
| `/admin/config` | 系統設定 |
| `/admin/users` | 內部使用者資料 |
| `/cloud-metadata` | 模擬雲端 IAM 憑證 |

---

### 📌 暫存腳本（將移至 A07）

以下腳本涉及身份驗證問題，將在 A07 分支中使用：

- `jwt_forge.py` - JWT Token 偽造
- `privilege_escalation.py` - 權限提升（部分功能）

---

## 🔧 安裝相依套件

```bash
pip install requests
```

---

## 🚀 快速開始

### 1. 啟動服務

```bash
# 在專案根目錄
docker-compose up -d --build
```

### 2. 等待服務啟動

```bash
# 確認服務運行中
docker-compose ps
```

### 3. 執行攻擊腳本

```bash
cd scripts/a01

# 執行所有 JWT 攻擊
python jwt_forge.py --all

# 執行所有 IDOR 攻擊
python idor_exploit.py --all

# 執行所有 SSRF 攻擊
python ssrf_exploit.py --all
```

---

## 📊 服務端口

| 服務 | 端口 | 說明 |
|------|------|------|
| backend-vulnerable | 8081 | 漏洞版本後端 |
| backend-secure | 8082 | 安全版本後端 |
| internal-api | 8080 (內部) | SSRF 目標服務（無外部端口）|
| frontend | 80 | Vue 前端 |

---

## 🔐 測試帳號

| 使用者 | 密碼 | 角色 | 用途 |
|--------|------|------|------|
| admin | admin123 | ADMIN | 管理員帳號 |
| user | user123 | USER | 一般使用者 |
| alice | alice123 | USER | 測試使用者 |
| bob | bob123 | USER | 測試使用者 |

---

## 🛡️ 漏洞與修復對照

### JWT 驗證

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| 簽名驗證 | ❌ 只解碼，不驗證 | ✅ HMAC-SHA256 驗證 |
| 過期檢查 | ❌ 不檢查 | ✅ 檢查 exp claim |
| 密鑰管理 | ❌ 無密鑰 | ✅ 環境變數設定 |

### IDOR 防護

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| 資源擁有者驗證 | ❌ 無驗證 | ✅ 檢查 user.id |
| ID 可預測性 | ❌ ORD-00001 | ✅ UUID |
| 存取控制 | ❌ 任何人可存取 | ✅ 只有擁有者可存取 |

### Path Traversal 防護

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| 路徑驗證 | ❌ 直接拼接 | ✅ 正規化 + 目錄檢查 |
| 檔案類型 | ❌ 無限制 | ✅ 白名單副檔名 |
| 檔案名稱 | ❌ 原始名稱 | ✅ UUID 重新命名 |

### SSRF 防護

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| URL 驗證 | ❌ 無驗證 | ✅ 白名單域名 |
| IP 過濾 | ❌ 無過濾 | ✅ 阻擋私有 IP |
| 協定限制 | ❌ 無限制 | ✅ 只允許 HTTPS |
| 權限要求 | ❌ 任何人可用 | ✅ 需要 ADMIN |

### 權限控制

| 項目 | 漏洞版本 | 安全版本 |
|------|----------|----------|
| 方法級權限 | ❌ 無檢查 | ✅ @PreAuthorize |
| 角色驗證 | ❌ 無驗證 | ✅ hasRole('ADMIN') |
| 審計日誌 | ❌ 無日誌 | ✅ 記錄存取 |

---

## 📚 參考資料

- [OWASP Top 10 2021 - A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [JWT Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

## ⚠️ 免責聲明

**此工具僅供教育和授權的安全測試目的使用。**

未經授權對系統進行滲透測試是違法的。請確保您只在：
1. 自己的系統上測試
2. 取得書面授權的系統上測試
3. 專門設計的練習環境中測試

使用者需自行承擔所有法律責任。
