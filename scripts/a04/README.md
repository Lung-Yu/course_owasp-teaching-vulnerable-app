# OWASP A04:2021 - Insecure Design

## 概述

不安全設計 (Insecure Design) 是一個廣泛的類別，代表設計缺陷導致的安全問題。它不同於實作錯誤，而是設計階段缺乏威脅建模和安全設計原則的結果。

## CWE 關聯

| CWE | 名稱 | 本專案演示 |
|-----|------|-----------|
| CWE-799 | Improper Control of Interaction Frequency | 無限速機制 |
| CWE-840 | Business Logic Errors | 優惠券濫用 |
| CWE-841 | Improper Enforcement of Behavioral Workflow | 訂單流程繞過 |
| CWE-472 | External Control of Assumed-Immutable Web Parameter | 價格篡改 |
| CWE-602 | Client-Side Enforcement of Server-Side Security | 信任客戶端資料 |

## 漏洞場景

### 1. 缺乏限速機制 (CWE-799)

**漏洞端點:** `/api/rate-limit/*`

敏感操作沒有限速保護，允許攻擊者：
- 暴力破解 OTP
- 密碼爆破攻擊
- 發送大量密碼重設請求
- 資源耗盡攻擊 (DoS)

```python
# 漏洞代碼 - 沒有任何限速
@PostMapping("/verify-otp")
public ResponseEntity<?> verifyOtp(@RequestBody OtpRequest request) {
    // 直接驗證，沒有嘗試次數限制
    boolean valid = request.getOtp().equals("123456");
    return ResponseEntity.ok(Map.of("verified", valid));
}

# 安全代碼 - 有限速和帳戶鎖定
@PostMapping("/verify-otp")
public ResponseEntity<?> verifyOtp(@RequestBody OtpRequest request) {
    String sessionId = request.getSessionId();
    int attempts = otpAttempts.getOrDefault(sessionId, 0);
    
    if (attempts >= MAX_OTP_ATTEMPTS) {
        return ResponseEntity.status(429)
            .body(Map.of("error", "Too many attempts. Account locked."));
    }
    
    otpAttempts.put(sessionId, attempts + 1);
    // ... 驗證邏輯
}
```

### 2. 優惠券業務邏輯漏洞 (CWE-840)

**漏洞端點:** `/api/coupons/*`

優惠券系統設計缺陷：
- 無過期時間檢查
- 無使用次數限制
- 無限疊加優惠券
- 無最低消費檢查
- 暴露所有優惠券代碼

```python
# 漏洞代碼 - 沒有任何驗證
@PostMapping("/apply")
public ResponseEntity<?> applyCoupon(@RequestParam String code, 
                                      @RequestParam Long userId,
                                      @RequestParam Double cartTotal) {
    Coupon coupon = couponRepository.findByCode(code).orElse(null);
    if (coupon == null) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid coupon"));
    }
    
    // 直接應用折扣，沒有任何檢查
    Double discount = coupon.calculateDiscount(cartTotal);
    appliedCoupons.computeIfAbsent(userId, k -> new ArrayList<>()).add(coupon);
    
    return ResponseEntity.ok(Map.of("discount", discount));
}

# 安全代碼 - 完整驗證
@PostMapping("/apply")
public ResponseEntity<?> applyCoupon(@RequestParam String code,
                                      @RequestParam Long userId,
                                      @RequestParam Double cartTotal) {
    // 1. 檢查優惠券是否存在
    Coupon coupon = couponRepository.findByCode(code).orElse(null);
    if (coupon == null) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid coupon"));
    }
    
    // 2. 檢查過期時間
    if (coupon.isExpired()) {
        return ResponseEntity.badRequest().body(Map.of("error", "Coupon expired"));
    }
    
    // 3. 檢查是否已使用過
    if (couponUsageRepository.existsByCouponIdAndUserId(coupon.getId(), userId)) {
        return ResponseEntity.badRequest().body(Map.of("error", "Already used"));
    }
    
    // 4. 檢查疊加限制
    List<Coupon> userCoupons = appliedCoupons.getOrDefault(userId, new ArrayList<>());
    if (userCoupons.size() >= MAX_COUPONS_PER_ORDER) {
        return ResponseEntity.badRequest().body(Map.of("error", "Max coupons reached"));
    }
    
    // 5. 檢查最低消費
    if (cartTotal < coupon.getMinPurchase()) {
        return ResponseEntity.badRequest().body(Map.of("error", "Min purchase not met"));
    }
    
    // ... 應用折扣
}
```

### 3. 價格篡改 (CWE-472, CWE-602)

**漏洞端點:** `/api/orders/checkout`

結帳系統信任客戶端提供的價格：
- 信任 `totalAmount` 參數
- 信任 `unitPrice` 參數
- 允許負數價格
- 允許負數數量

```python
# 漏洞代碼 - 信任客戶端價格
@PostMapping("/checkout")
public ResponseEntity<?> checkout(@RequestBody CheckoutRequest request) {
    // 直接使用客戶端提供的總金額
    Order order = new Order();
    order.setTotalAmount(request.getTotalAmount());
    
    // 使用客戶端提供的單價
    for (OrderItemRequest item : request.getItems()) {
        order.addItem(item.getProductId(), item.getQuantity(), item.getUnitPrice());
    }
    
    return ResponseEntity.ok(Map.of("orderId", order.getId()));
}

# 安全代碼 - 伺服器端計算價格
@PostMapping("/checkout")
public ResponseEntity<?> checkout(@RequestBody CheckoutRequest request) {
    double calculatedTotal = 0;
    
    for (OrderItemRequest item : request.getItems()) {
        // 從資料庫獲取正確價格
        Product product = productRepository.findById(item.getProductId())
            .orElseThrow(() -> new BadRequestException("Invalid product"));
        
        // 驗證數量
        if (item.getQuantity() <= 0) {
            throw new BadRequestException("Invalid quantity");
        }
        
        calculatedTotal += product.getPrice() * item.getQuantity();
    }
    
    Order order = new Order();
    order.setTotalAmount(calculatedTotal);  // 使用伺服器計算的價格
    
    return ResponseEntity.ok(Map.of("orderId", order.getId()));
}
```

### 4. 限時特賣競態條件 (CWE-799, CWE-841)

**漏洞端點:** `/api/flash-sale/*`

限時特賣系統缺乏併發控制：
- 沒有庫存鎖定
- 沒有每人限購檢查
- 允許負數數量
- 處理延遲增加競態窗口

```python
# 漏洞代碼 - 無併發控制
@PostMapping("/buy")
public ResponseEntity<?> buyFlashSale(@RequestBody FlashSalePurchaseRequest request) {
    FlashSale sale = flashSaleRepository.findById(request.getSaleId())
        .orElseThrow(() -> new BadRequestException("Sale not found"));
    
    // 無鎖定的庫存檢查 - 競態條件！
    if (!sale.hasStock()) {
        return ResponseEntity.badRequest().body(Map.of("error", "Out of stock"));
    }
    
    // 模擬處理延遲 - 增加競態窗口
    Thread.sleep(100);
    
    // 更新庫存 - 可能已被其他請求消耗
    sale.setSoldCount(sale.getSoldCount() + request.getQuantity());
    flashSaleRepository.save(sale);
    
    return ResponseEntity.ok(Map.of("success", true));
}

# 安全代碼 - 同步控制
@PostMapping("/buy")
public synchronized ResponseEntity<?> buyFlashSale(@RequestBody FlashSalePurchaseRequest request) {
    FlashSale sale = flashSaleRepository.findById(request.getSaleId())
        .orElseThrow(() -> new BadRequestException("Sale not found"));
    
    // 驗證數量
    if (request.getQuantity() <= 0) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid quantity"));
    }
    
    // 同步塊內的庫存檢查
    if (!sale.hasStock() || sale.getSoldCount() + request.getQuantity() > sale.getStockLimit()) {
        return ResponseEntity.badRequest().body(Map.of("error", "Out of stock"));
    }
    
    // 檢查每人限購
    int userPurchases = getUserPurchaseCount(request.getUserId(), sale.getId());
    if (userPurchases >= sale.getPerUserLimit()) {
        return ResponseEntity.badRequest().body(Map.of("error", "Purchase limit exceeded"));
    }
    
    // 更新庫存
    sale.setSoldCount(sale.getSoldCount() + request.getQuantity());
    flashSaleRepository.save(sale);
    
    return ResponseEntity.ok(Map.of("success", true));
}
```

### 5. 訂單流程繞過 (CWE-841)

**漏洞端點:** `/api/orders/{id}/status`, `/api/orders/{id}/refund`

訂單狀態機設計缺陷：
- 允許任意狀態跳轉
- 跳過付款確認
- 逆向狀態轉換
- 未驗證退款條件

```
正常流程: PENDING → CONFIRMED → SHIPPED → DELIVERED
攻擊流程: PENDING → SHIPPED (跳過付款)
        或 PENDING → DELIVERED (直接交付)
        或 CONFIRMED → PENDING (逆向)
```

```python
# 漏洞代碼 - 無狀態驗證
@PutMapping("/{id}/status")
public ResponseEntity<?> updateStatus(@PathVariable Long id,
                                       @RequestBody StatusUpdateRequest request) {
    Order order = orderRepository.findById(id)
        .orElseThrow(() -> new ResourceNotFoundException("Order not found"));
    
    // 直接設置任意狀態
    order.setStatus(request.getStatus());
    orderRepository.save(order);
    
    return ResponseEntity.ok(Map.of("status", order.getStatus()));
}

# 安全代碼 - 狀態機驗證
@PutMapping("/{id}/status")
public ResponseEntity<?> updateStatus(@PathVariable Long id,
                                       @RequestBody StatusUpdateRequest request) {
    Order order = orderRepository.findById(id)
        .orElseThrow(() -> new ResourceNotFoundException("Order not found"));
    
    String currentStatus = order.getStatus();
    String newStatus = request.getStatus();
    
    // 定義允許的狀態轉換
    Map<String, List<String>> allowedTransitions = Map.of(
        "PENDING", List.of("CONFIRMED", "CANCELLED"),
        "CONFIRMED", List.of("SHIPPED", "CANCELLED"),
        "SHIPPED", List.of("DELIVERED"),
        "DELIVERED", List.of(),  // 最終狀態
        "CANCELLED", List.of()   // 最終狀態
    );
    
    List<String> allowed = allowedTransitions.getOrDefault(currentStatus, List.of());
    if (!allowed.contains(newStatus)) {
        return ResponseEntity.badRequest().body(Map.of(
            "error", "Invalid status transition",
            "currentStatus", currentStatus,
            "allowedTransitions", allowed
        ));
    }
    
    order.setStatus(newStatus);
    orderRepository.save(order);
    
    return ResponseEntity.ok(Map.of("status", order.getStatus()));
}
```

## 攻擊腳本

### 1. 限速測試
```bash
# 洪水攻擊
python3 scripts/a04/rate_limiting.py --flood

# OTP 暴力破解
python3 scripts/a04/rate_limiting.py --otp

# 登入暴力破解
python3 scripts/a04/rate_limiting.py --login

# 比較漏洞與安全版本
python3 scripts/a04/rate_limiting.py --compare
```

### 2. 價格篡改
```bash
# 總金額篡改
python3 scripts/a04/price_manipulation.py --total

# 單價篡改
python3 scripts/a04/price_manipulation.py --unit

# 負數價格
python3 scripts/a04/price_manipulation.py --negative

# 比較版本
python3 scripts/a04/price_manipulation.py --compare
```

### 3. 優惠券濫用
```bash
# 多次使用
python3 scripts/a04/coupon_abuse.py --multiple

# 無限疊加
python3 scripts/a04/coupon_abuse.py --stack

# 過期優惠券
python3 scripts/a04/coupon_abuse.py --expired

# 比較版本
python3 scripts/a04/coupon_abuse.py --compare
```

### 4. 庫存競態條件
```bash
# 競態攻擊 (20 並發)
python3 scripts/a04/inventory_race.py --race --threads 20

# 快速連續購買
python3 scripts/a04/inventory_race.py --rapid

# 分布式攻擊
python3 scripts/a04/inventory_race.py --distributed

# 比較版本
python3 scripts/a04/inventory_race.py --compare
```

### 5. 流程繞過
```bash
# 跳過付款
python3 scripts/a04/workflow_bypass.py --skip-payment

# 逆向狀態
python3 scripts/a04/workflow_bypass.py --reverse

# 退款濫用
python3 scripts/a04/workflow_bypass.py --refund

# 比較版本
python3 scripts/a04/workflow_bypass.py --compare
```

## 防護措施

### 1. 限速機制
- 敏感操作（登入、OTP、密碼重設）實施速率限制
- 失敗嘗試後帳戶鎖定
- IP 級別限速
- 資源密集型操作限制

### 2. 業務邏輯驗證
- 優惠券過期時間檢查
- 使用次數追蹤
- 疊加限制
- 最低消費驗證

### 3. 伺服器端計算
- 永不信任客戶端價格
- 從資料庫獲取產品價格
- 伺服器端計算總金額
- 驗證數量為正數

### 4. 併發控制
- 庫存操作使用鎖定
- 樂觀鎖或悲觀鎖
- 每人限購追蹤
- 時間窗口驗證

### 5. 工作流程執行
- 定義明確的狀態機
- 驗證狀態轉換
- 退款條件檢查
- 審計日誌記錄

## 設計安全原則

1. **威脅建模**: 在設計階段識別潛在威脅
2. **最小信任原則**: 永不信任客戶端資料
3. **深度防禦**: 多層驗證
4. **安全預設**: 預設拒絕，明確允許
5. **失敗安全**: 錯誤時拒絕操作

## 測試資料

### 優惠券
| 代碼 | 類型 | 折扣 | 說明 |
|------|------|------|------|
| SAVE10 | PERCENTAGE | 10% | 一般優惠券 |
| UNLIMITED | PERCENTAGE | 25% | 無限次使用 |
| STACK100 | FIXED_AMOUNT | $100 | 可疊加 |
| EXPIRED50 | PERCENTAGE | 50% | 已過期 |
| FREE100 | PERCENTAGE | 100% | 免費 |
| VIP90OFF | PERCENTAGE | 90% | VIP專屬 |
| BIGSPENDER | PERCENTAGE | 30% | 最低消費$500 |

### 限時特賣
| ID | 產品 | 原價 | 特價 | 庫存 | 每人限購 |
|----|------|------|------|------|----------|
| 1 | Product 1 | $99.99 | $49.99 | 10 | 2 |
| 2 | Product 2 | $199.99 | $99.99 | 5 | 1 |

## 參考資料

- [OWASP A04:2021 - Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
