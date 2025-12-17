package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 安全警報
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 * 
 * 用於儲存偵測到的安全威脅警報
 */
@Entity
@Table(name = "security_alerts", indexes = {
    @Index(name = "idx_security_alerts_severity", columnList = "severity"),
    @Index(name = "idx_security_alerts_acknowledged", columnList = "acknowledged"),
    @Index(name = "idx_security_alerts_created_at", columnList = "created_at")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 警報類型：BRUTE_FORCE, SQL_INJECTION, UNAUTHORIZED_ACCESS, 
     * DATA_EXFILTRATION, PRIVILEGE_ESCALATION, AFTER_HOURS_ACCESS
     */
    @Column(name = "alert_type", length = 50, nullable = false)
    private String alertType;

    /**
     * 嚴重程度：LOW, MEDIUM, HIGH, CRITICAL
     */
    @Column(length = 20, nullable = false)
    private String severity;

    @Column(length = 255, nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "affected_user_id")
    private Long affectedUserId;

    @Column(name = "affected_username", length = 50)
    private String affectedUsername;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    /**
     * 關聯的審計日誌 ID 列表
     */
    @Column(name = "related_log_ids", columnDefinition = "INTEGER[]")
    private Integer[] relatedLogIds;

    @Column(name = "correlation_id", length = 36)
    private String correlationId;

    @Column
    @Builder.Default
    private Boolean acknowledged = false;

    @Column(name = "acknowledged_by")
    private Long acknowledgedBy;

    @Column(name = "acknowledged_at")
    private LocalDateTime acknowledgedAt;

    @Column
    @Builder.Default
    private Boolean resolved = false;

    @Column(name = "resolved_by")
    private Long resolvedBy;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    @Column(name = "resolution_notes", columnDefinition = "TEXT")
    private String resolutionNotes;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "expires_at")
    @Builder.Default
    private LocalDateTime expiresAt = LocalDateTime.now().plusDays(90);
}
