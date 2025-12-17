# Vulnerable E-Commerce Application

> ⚠️ **免責聲明 / Disclaimer**
> 
> 本專案僅供**教育與資安研究用途**。請勿將本專案中的程式碼、技術或漏洞用於任何非法活動或未經授權的系統測試。
> 
> 使用本專案即表示您同意：
> - 僅在您有權測試的環境中使用
> - 不會將所學技術用於惡意目的
> - 對於任何濫用行為，開發者不承擔任何責任
> 
> This project is intended **solely for educational and security research purposes**. Do not use the code, techniques, or vulnerabilities in this project for any illegal activities or unauthorized system testing.
> 
> By using this project, you agree that:
> - You will only use it in environments you are authorized to test
> - You will not use the techniques learned for malicious purposes
> - The developers bear no responsibility for any misuse

---

A deliberately vulnerable e-commerce web application for security training purposes.

## Requirements

- Docker & Docker Compose
- 4GB+ RAM recommended

## Quick Start

```bash
# Start all services
./scripts/start.sh

# Or manually
docker-compose up -d --build
```

## Services

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost | Web UI |
| Backend API | http://localhost:8081 | REST API |
| Log4Shell Demo | http://localhost:8083 | CVE-2021-44228 |
| Database | localhost:5432 | PostgreSQL |
| Attacker Server | localhost:1389, 8888, 9999 | LDAP/HTTP |

## Test Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | ADMIN |
| manager | manager123 | MANAGER |
| vip | vip123 | VIP |
| user | user123 | USER |
| alice | alice123 | USER |
| bob | bob123 | USER |
| guest | guest123 | GUEST |
| locked | locked123 | USER (disabled) |

## API Endpoints

Base URL: `http://localhost:8081/api`

### Authentication
- POST `/auth/login`
- POST `/auth/register`
- POST `/auth/forgot-password`
- POST `/auth/reset-password`
- POST `/auth/change-password`

### Users
- GET `/users`
- GET `/users/{id}`
- PUT `/users/{id}`
- DELETE `/users/{id}`

### Products
- GET `/products`
- GET `/products/{id}`
- GET `/products/search`
- POST `/products`
- PUT `/products/{id}`
- DELETE `/products/{id}`

### Orders
- GET `/orders`
- GET `/orders/{id}`
- GET `/orders/number/{orderNumber}`
- POST `/orders`
- POST `/orders/checkout`
- PUT `/orders/{id}/status`
- POST `/orders/{id}/refund`

### Admin
- GET `/admin/users`
- GET `/admin/stats`
- GET `/admin/config`
- POST `/admin/users/{id}/role`

### Files
- GET `/files/list`
- GET `/files/download`
- GET `/files/read`
- POST `/files/upload`

### Search
- GET `/search`
- GET `/search/advanced`
- GET `/search/products`
- GET `/search/users`
- GET `/search/orders`
- POST `/search/report`

### System
- GET `/system/ping`
- GET `/system/lookup`
- GET `/system/info`
- GET `/system/read-log`
- POST `/system/diagnose`

### Crypto
- POST `/crypto/encrypt`
- POST `/crypto/decrypt`
- POST `/crypto/hash`
- POST `/crypto/generate-token`
- GET `/crypto/token-history`

### Coupons
- GET `/coupons/available`
- POST `/coupons/apply`
- POST `/coupons/validate`

### Flash Sales
- GET `/flash-sale/active`
- POST `/flash-sale/buy`
- POST `/flash-sale/reset`

### Webhooks
- POST `/webhook/test`
- GET `/webhook/fetch`

### XML
- POST `/xml/parse`
- POST `/xml/import-settings`

### Template
- GET `/template/eval`
- POST `/template/render`

### Integrity
- POST `/integrity/cart/save`
- POST `/integrity/cart/checkout`

### Logging
- GET `/logging/view/audit`
- GET `/logging/view/login-attempts`
- GET `/logging/view/alerts`

### Status
- GET `/status`
- GET `/status/health`

## Log4Shell Demo

The Log4Shell service demonstrates CVE-2021-44228.

```bash
# Test endpoints
curl "http://localhost:8083/api/log4j/search?keyword=test"
curl "http://localhost:8083/api/log4j/status"

# The attacker server runs on:
# - LDAP: localhost:1389
# - HTTP: localhost:8888
# - Callback: localhost:9999
```

## Stopping Services

```bash
docker-compose down

# Remove volumes
docker-compose down -v
```

## Resetting Data

```bash
docker-compose down -v
docker-compose up -d --build
```
