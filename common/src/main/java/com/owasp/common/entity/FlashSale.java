package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * 限時特賣
 */
@Entity
@Table(name = "flash_sales")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FlashSale {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "product_id")
    private Long productId;

    @Column(name = "flash_price")
    private BigDecimal flashPrice;

    @Column(name = "stock_limit")
    private Integer stockLimit;

    @Column(name = "sold_count")
    private Integer soldCount;

    @Column(name = "per_user_limit")
    private Integer perUserLimit;

    @Column(name = "start_time")
    private LocalDateTime startTime;

    @Column(name = "end_time")
    private LocalDateTime endTime;

    @Column(name = "active")
    private Boolean active;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    /**
     * 檢查是否在進行中
     */
    public boolean isActive() {
        LocalDateTime now = LocalDateTime.now();
        return Boolean.TRUE.equals(active) 
            && now.isAfter(startTime) 
            && now.isBefore(endTime);
    }

    /**
     * 檢查庫存是否足夠
     */
    public boolean hasStock(int quantity) {
        return (stockLimit - soldCount) >= quantity;
    }
}
