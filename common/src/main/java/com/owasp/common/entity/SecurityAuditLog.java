package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 安全審計日誌
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 * 用於記錄所有安全相關事件
 */
@Entity
@Table(name = "security_audit_logs", indexes = {
    @Index(name = "idx_security_audit_logs_correlation_id", columnList = "correlation_id"),
    @Index(name = "idx_security_audit_logs_created_at", columnList = "created_at"),
    @Index(name = "idx_security_audit_logs_user_id", columnList = "user_id"),
    @Index(name = "idx_security_audit_logs_event_type", columnList = "event_type")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 事件類型：LOGIN, LOGOUT, ACCESS, MODIFY, DELETE, ADMIN_ACTION
     */
    @Column(name = "event_type", length = 50, nullable = false)
    private String eventType;

    /**
     * 嚴重程度：DEBUG, INFO, WARN, ERROR, CRITICAL
     */
    @Column(length = 20, nullable = false)
    private String severity;

    @Column(name = "user_id")
    private Long userId;

    @Column(length = 50)
    private String username;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    /**
     * 被存取的資源路徑
     */
    @Column(length = 255)
    private String resource;

    /**
     * 執行的動作
     */
    @Column(length = 100)
    private String action;

    /**
     * 結果：SUCCESS, FAILURE, BLOCKED
     */
    @Column(length = 20)
    private String outcome;

    /**
     * 額外的詳細資訊（JSON）
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> details;

    /**
     * 用於追蹤請求鏈的關聯 ID
     */
    @Column(name = "correlation_id", length = 36)
    private String correlationId;

    @Column(name = "session_id", length = 100)
    private String sessionId;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "expires_at")
    @Builder.Default
    private LocalDateTime expiresAt = LocalDateTime.now().plusDays(7);
}
