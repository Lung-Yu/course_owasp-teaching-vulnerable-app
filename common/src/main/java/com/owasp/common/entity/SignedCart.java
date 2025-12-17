package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 
 * A08:2021 - Software and Data Integrity Failures
 */
@Entity
@Table(name = "signed_carts")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignedCart {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "cart_data", columnDefinition = "TEXT", nullable = false)
    private String cartData;

    @Column(name = "hmac_signature", length = 64)
    private String hmacSignature;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    /**
     * 檢查購物車是否過期
     */
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(expiresAt);
    }
}
