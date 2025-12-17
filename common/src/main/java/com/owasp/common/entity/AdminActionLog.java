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
 * 管理員操作日誌
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 * 
 * 記錄所有管理員操作，包含修改前後狀態
 */
@Entity
@Table(name = "admin_action_logs", indexes = {
    @Index(name = "idx_admin_action_logs_admin_user_id", columnList = "admin_user_id"),
    @Index(name = "idx_admin_action_logs_created_at", columnList = "created_at")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminActionLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "admin_user_id")
    private Long adminUserId;

    @Column(name = "admin_username", length = 50)
    private String adminUsername;

    /**
     * 操作類型：USER_CREATE, USER_DELETE, ROLE_CHANGE, CONFIG_UPDATE, etc.
     */
    @Column(name = "action_type", length = 50, nullable = false)
    private String actionType;

    /**
     * 目標實體：users, products, orders, etc.
     */
    @Column(name = "target_entity", length = 50)
    private String targetEntity;

    /**
     * 目標 ID
     */
    @Column(name = "target_id", length = 50)
    private String targetId;

    /**
     * 修改前狀態（JSON）
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "before_state", columnDefinition = "jsonb")
    private Map<String, Object> beforeState;

    /**
     * 修改後狀態（JSON）
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "after_state", columnDefinition = "jsonb")
    private Map<String, Object> afterState;

    /**
     * 操作原因
     */
    @Column(length = 255)
    private String reason;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "correlation_id", length = 36)
    private String correlationId;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "expires_at")
    @Builder.Default
    private LocalDateTime expiresAt = LocalDateTime.now().plusDays(365);
}
