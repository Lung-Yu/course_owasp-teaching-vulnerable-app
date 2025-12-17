package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * 優惠券實體
 */
@Entity
@Table(name = "coupons")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Coupon {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String code;

    @Column(length = 255)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "discount_type", nullable = false, length = 20)
    private DiscountType discountType;

    @Column(name = "discount_value", nullable = false)
    private BigDecimal discountValue;

    @Column(name = "min_purchase")
    private BigDecimal minPurchase;

    @Column(name = "max_discount")
    private BigDecimal maxDiscount;

    @Column(name = "usage_limit")
    private Integer usageLimit;

    @Column(name = "used_count")
    private Integer usedCount;

    @Column(name = "per_user_limit")
    private Integer perUserLimit;

    @Column(name = "stackable")
    private Boolean stackable;

    @Column(name = "start_date")
    private LocalDateTime startDate;

    @Column(name = "end_date")
    private LocalDateTime endDate;

    @Column(name = "active")
    private Boolean active;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public enum DiscountType {
        PERCENTAGE,
        FIXED_AMOUNT
    }

    /**
     * 計算折扣金額
     */
    public BigDecimal calculateDiscount(BigDecimal orderAmount) {
        BigDecimal discount;
        if (discountType == DiscountType.PERCENTAGE) {
            discount = orderAmount.multiply(discountValue).divide(BigDecimal.valueOf(100));
        } else {
            discount = discountValue;
        }
        
        // 如果有最大折扣限制
        if (maxDiscount != null && discount.compareTo(maxDiscount) > 0) {
            discount = maxDiscount;
        }
        
        return discount;
    }

    /**
     * 檢查是否過期
     */
    public boolean isExpired() {
        LocalDateTime now = LocalDateTime.now();
        return endDate != null && now.isAfter(endDate);
    }

    /**
     * 檢查是否在有效期內
     */
    public boolean isValid() {
        LocalDateTime now = LocalDateTime.now();
        boolean afterStart = startDate == null || now.isAfter(startDate);
        boolean beforeEnd = endDate == null || now.isBefore(endDate);
        return afterStart && beforeEnd && Boolean.TRUE.equals(active);
    }
}
