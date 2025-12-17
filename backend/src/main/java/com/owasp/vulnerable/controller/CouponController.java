package com.owasp.vulnerable.controller;

import com.owasp.common.entity.Coupon;
import com.owasp.common.repository.CouponRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.*;

/**
 * 優惠券 API
 */
@RestController
@RequestMapping("/api/coupons")
@RequiredArgsConstructor
@Slf4j
public class CouponController {

    private final CouponRepository couponRepository;

    // 模擬購物車（實際應存在 session 或資料庫）
    private final Map<String, List<AppliedCoupon>> appliedCoupons = new HashMap<>();

    /**
     * 套用優惠券
     */
    @PostMapping("/apply")
    public ResponseEntity<?> applyCoupon(@RequestBody Map<String, Object> request) {
        String couponCode = (String) request.get("couponCode");
        String sessionId = (String) request.getOrDefault("sessionId", "default");
        BigDecimal orderAmount = new BigDecimal(request.getOrDefault("orderAmount", "1000").toString());

        log.info("Applying coupon: {} for session: {}", couponCode, sessionId);

        // 查找優惠券
        Optional<Coupon> couponOpt = couponRepository.findByCode(couponCode);
        if (couponOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "優惠券不存在",
                "code", couponCode
            ));
        }

        Coupon coupon = couponOpt.get();

        
        // if (coupon.isExpired()) { return error; }

        
        // if (coupon.getUsedCount() >= coupon.getUsageLimit()) { return error; }

        
        // if (hasUserUsedCoupon(userId, couponId)) { return error; }

        
        // if (orderAmount.compareTo(coupon.getMinPurchase()) < 0) { return error; }

        
        List<AppliedCoupon> coupons = appliedCoupons.computeIfAbsent(sessionId, k -> new ArrayList<>());
        
        // 計算折扣
        BigDecimal discount = coupon.calculateDiscount(orderAmount);
        
        coupons.add(new AppliedCoupon(coupon.getCode(), discount));

        // 計算總折扣（可能超過訂單金額！）
        BigDecimal totalDiscount = coupons.stream()
            .map(AppliedCoupon::discount)
            .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal finalAmount = orderAmount.subtract(totalDiscount);
        
        // if (finalAmount.compareTo(BigDecimal.ZERO) < 0) finalAmount = BigDecimal.ZERO;

        log.info("Coupon applied: {} - Discount: {} - Final: {}", 
            couponCode, discount, finalAmount);

        return ResponseEntity.ok(Map.of(
            "message", "優惠券套用成功",
            "couponCode", couponCode,
            "discount", discount,
            "totalDiscount", totalDiscount,
            "originalAmount", orderAmount,
            "finalAmount", finalAmount,
            "appliedCoupons", coupons.stream().map(AppliedCoupon::code).toList(),
            "couponCount", coupons.size(),
            "warning", finalAmount.compareTo(BigDecimal.ZERO) < 0 ? "金額為負數！" : null
        ));
    }

    /**
     * 清除已套用的優惠券
     */
    @PostMapping("/clear")
    public ResponseEntity<?> clearCoupons(@RequestBody Map<String, String> request) {
        String sessionId = request.getOrDefault("sessionId", "default");
        appliedCoupons.remove(sessionId);
        return ResponseEntity.ok(Map.of("message", "已清除所有優惠券"));
    }

    /**
     * 取得可用優惠券列表
     */
    @GetMapping("/available")
    public ResponseEntity<?> getAvailableCoupons() {
        
        List<Coupon> coupons = couponRepository.findAll();
        
        List<Map<String, Object>> couponList = new ArrayList<>();
        for (Coupon c : coupons) {
            Map<String, Object> couponMap = new HashMap<>();
            couponMap.put("code", c.getCode());
            couponMap.put("description", c.getDescription());
            couponMap.put("discountType", c.getDiscountType());
            couponMap.put("discountValue", c.getDiscountValue());
            couponMap.put("minPurchase", c.getMinPurchase());
            couponMap.put("maxDiscount", c.getMaxDiscount());
            couponMap.put("usageLimit", c.getUsageLimit());
            couponMap.put("usedCount", c.getUsedCount());
            couponMap.put("stackable", c.getStackable());
            couponMap.put("startDate", c.getStartDate());
            couponMap.put("endDate", c.getEndDate());
            couponMap.put("expired", c.isExpired());
            couponList.add(couponMap);
        }
        
        return ResponseEntity.ok(Map.of("coupons", couponList));
    }

    /**
     * 生成優惠券
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generateCoupon(@RequestBody Map<String, Object> request) {
        
        String prefix = (String) request.getOrDefault("prefix", "PROMO");
        int discountPercent = (int) request.getOrDefault("discount", 10);
        
        // 使用時間戳作為序號（可預測）
        String code = prefix + "-" + System.currentTimeMillis() % 10000;
        
        Coupon coupon = Coupon.builder()
            .code(code)
            .description("自動生成優惠券")
            .discountType(Coupon.DiscountType.PERCENTAGE)
            .discountValue(BigDecimal.valueOf(discountPercent))
            .usageLimit(100)
            .usedCount(0)
            .perUserLimit(1)
            .stackable(true)
            .active(true)
            .build();
        
        couponRepository.save(coupon);
        
        log.info("Generated coupon: {}", code);
        
        return ResponseEntity.ok(Map.of(
            "message", "優惠券已生成",
            "code", code,
            "discount", discountPercent + "%"
        ));
    }

    record AppliedCoupon(String code, BigDecimal discount) {}
}
