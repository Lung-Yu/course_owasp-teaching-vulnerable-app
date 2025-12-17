package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * 交易審計追蹤
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 * 
 * 用於記錄所有交易，包含完整性雜湊鏈以防止竄改
 */
@Entity
@Table(name = "transaction_audit_trail", indexes = {
    @Index(name = "idx_transaction_audit_trail_user_id", columnList = "user_id"),
    @Index(name = "idx_transaction_audit_trail_correlation_id", columnList = "correlation_id")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionAuditTrail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 交易唯一識別碼
     */
    @Column(name = "transaction_id", length = 36, unique = true, nullable = false)
    private String transactionId;

    @Column(name = "user_id")
    private Long userId;

    /**
     * 交易類型：PURCHASE, REFUND, TRANSFER, WALLET_TOPUP
     */
    @Column(name = "transaction_type", length = 50, nullable = false)
    private String transactionType;

    @Column(precision = 10, scale = 2, nullable = false)
    private BigDecimal amount;

    @Column(length = 10)
    @Builder.Default
    private String currency = "TWD";

    @Column(name = "source_account", length = 100)
    private String sourceAccount;

    @Column(name = "destination_account", length = 100)
    private String destinationAccount;

    /**
     * 狀態：PENDING, COMPLETED, FAILED, CANCELLED
     */
    @Column(length = 20, nullable = false)
    private String status;

    /**
     * 上一筆交易的 SHA256 hash（用於完整性驗證）
     */
    @Column(name = "previous_hash", length = 64)
    private String previousHash;

    /**
     * 當前交易的 SHA256 hash
     */
    @Column(name = "current_hash", length = 64)
    private String currentHash;

    /**
     * 額外交易詳情（JSON）
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> details;

    @Column(name = "correlation_id", length = 36)
    private String correlationId;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "expires_at")
    @Builder.Default
    private LocalDateTime expiresAt = LocalDateTime.now().plusDays(90);
}
