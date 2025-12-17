package com.owasp.vulnerable.controller;

import com.owasp.common.entity.FlashSale;
import com.owasp.common.model.Product;
import com.owasp.common.repository.FlashSaleRepository;
import com.owasp.common.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 限時特賣 API
 */
@RestController
@RequestMapping("/api/flash-sale")
@RequiredArgsConstructor
@Slf4j
public class FlashSaleController {

    private final FlashSaleRepository flashSaleRepository;
    private final ProductRepository productRepository;

    // 模擬用戶購買記錄
    private final Map<String, Map<Long, Integer>> userPurchases = new HashMap<>();

    /**
     * 取得進行中的限時特賣
     */
    @GetMapping("/active")
    public ResponseEntity<?> getActiveFlashSales() {
        List<FlashSale> sales = flashSaleRepository.findByActiveTrue();
        
        List<Map<String, Object>> result = new ArrayList<>();
        for (FlashSale sale : sales) {
            if (sale.isActive()) {
                Optional<Product> productOpt = productRepository.findById(sale.getProductId());
                if (productOpt.isPresent()) {
                    Product product = productOpt.get();
                    Map<String, Object> saleInfo = new HashMap<>();
                    saleInfo.put("id", sale.getId());
                    saleInfo.put("productId", sale.getProductId());
                    saleInfo.put("productName", product.getName());
                    saleInfo.put("originalPrice", product.getPrice());
                    saleInfo.put("flashPrice", sale.getFlashPrice());
                    saleInfo.put("stockLimit", sale.getStockLimit());
                    saleInfo.put("soldCount", sale.getSoldCount());
                    saleInfo.put("remaining", sale.getStockLimit() - sale.getSoldCount());
                    saleInfo.put("perUserLimit", sale.getPerUserLimit());
                    saleInfo.put("endTime", sale.getEndTime());
                    result.add(saleInfo);
                }
            }
        }
        
        return ResponseEntity.ok(Map.of("flashSales", result));
    }

    /**
     * 購買限時特賣商品
     */
    @PostMapping("/buy")
    public ResponseEntity<?> buyFlashSale(@RequestBody Map<String, Object> request) {
        Long flashSaleId = Long.valueOf(request.get("flashSaleId").toString());
        String userId = (String) request.getOrDefault("userId", "anonymous");
        int quantity = (int) request.getOrDefault("quantity", 1);

        log.info("Flash sale purchase: saleId={}, userId={}, qty={}", flashSaleId, userId, quantity);

        Optional<FlashSale> saleOpt = flashSaleRepository.findById(flashSaleId);
        if (saleOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "限時特賣不存在"));
        }

        FlashSale sale = saleOpt.get();

        // 檢查是否在進行中
        if (!sale.isActive()) {
            return ResponseEntity.badRequest().body(Map.of("error", "限時特賣未開始或已結束"));
        }

        
        // 多個請求可能同時通過檢查
        int remaining = sale.getStockLimit() - sale.getSoldCount();
        if (remaining < quantity) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "庫存不足",
                "remaining", remaining,
                "requested", quantity
            ));
        }

        // 模擬處理延遲
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        
        sale.setSoldCount(sale.getSoldCount() + quantity);
        flashSaleRepository.save(sale);

        // 記錄用戶購買（但不驗證限制）
        userPurchases.computeIfAbsent(userId, k -> new HashMap<>())
            .merge(flashSaleId, quantity, Integer::sum);

        int userTotalPurchased = userPurchases.get(userId).get(flashSaleId);

        log.info("Flash sale purchase success: saleId={}, userId={}, qty={}, userTotal={}", 
            flashSaleId, userId, quantity, userTotalPurchased);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "購買成功");
        response.put("flashSaleId", flashSaleId);
        response.put("quantity", quantity);
        response.put("price", sale.getFlashPrice());
        response.put("totalCost", sale.getFlashPrice().multiply(java.math.BigDecimal.valueOf(quantity)));
        response.put("userTotalPurchased", userTotalPurchased);
        response.put("stockRemaining", sale.getStockLimit() - sale.getSoldCount());
        if (userTotalPurchased > sale.getPerUserLimit()) {
            response.put("warning", "您已超過每人限購數量！");
        }
        return ResponseEntity.ok(response);
    }

    /**
     * 快速連續購買 - 用於測試競爭條件
     */
    @PostMapping("/rapid-buy")
    public ResponseEntity<?> rapidBuy(@RequestBody Map<String, Object> request) {
        Long flashSaleId = Long.valueOf(request.get("flashSaleId").toString());
        String userId = (String) request.getOrDefault("userId", "bot");
        int times = (int) request.getOrDefault("times", 10);

        List<Map<String, Object>> results = new ArrayList<>();
        int successCount = 0;
        int failCount = 0;

        for (int i = 0; i < times; i++) {
            try {
                Optional<FlashSale> saleOpt = flashSaleRepository.findById(flashSaleId);
                if (saleOpt.isPresent()) {
                    FlashSale sale = saleOpt.get();
                    if (sale.getSoldCount() < sale.getStockLimit()) {
                        sale.setSoldCount(sale.getSoldCount() + 1);
                        flashSaleRepository.save(sale);
                        successCount++;
                        results.add(Map.of("attempt", i + 1, "status", "success"));
                    } else {
                        failCount++;
                        results.add(Map.of("attempt", i + 1, "status", "out_of_stock"));
                    }
                }
            } catch (Exception e) {
                failCount++;
                results.add(Map.of("attempt", i + 1, "status", "error", "message", e.getMessage()));
            }
        }

        return ResponseEntity.ok(Map.of(
            "message", "批量購買完成",
            "totalAttempts", times,
            "successCount", successCount,
            "failCount", failCount,
            "details", results
        ));
    }

    /**
     * 重設限時特賣（測試用）
     */
    @PostMapping("/reset")
    public ResponseEntity<?> resetFlashSales() {
        List<FlashSale> sales = flashSaleRepository.findAll();
        for (FlashSale sale : sales) {
            sale.setSoldCount(0);
            flashSaleRepository.save(sale);
        }
        userPurchases.clear();
        
        return ResponseEntity.ok(Map.of("message", "已重設所有限時特賣"));
    }

    /**
     * 取得用戶購買記錄
     */
    @GetMapping("/purchases/{userId}")
    public ResponseEntity<?> getUserPurchases(@PathVariable String userId) {
        Map<Long, Integer> purchases = userPurchases.getOrDefault(userId, new HashMap<>());
        return ResponseEntity.ok(Map.of(
            "userId", userId,
            "purchases", purchases
        ));
    }
}
