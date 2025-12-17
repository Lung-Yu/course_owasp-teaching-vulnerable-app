package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 登入嘗試記錄
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 * 
 * 用於追蹤登入嘗試，支援暴力破解偵測
 */
@Entity
@Table(name = "login_attempts", indexes = {
    @Index(name = "idx_login_attempts_username", columnList = "username"),
    @Index(name = "idx_login_attempts_source_ip", columnList = "source_ip"),
    @Index(name = "idx_login_attempts_created_at", columnList = "created_at")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 50, nullable = false)
    private String username;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(nullable = false)
    private Boolean success;

    /**
     * 失敗原因：INVALID_PASSWORD, USER_NOT_FOUND, ACCOUNT_LOCKED, MFA_FAILED, etc.
     */
    @Column(name = "failure_reason", length = 100)
    private String failureReason;

    /**
     * 地理位置（可選，基於 IP 解析）
     */
    @Column(name = "geo_location", length = 100)
    private String geoLocation;

    @Column(name = "session_id", length = 100)
    private String sessionId;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "expires_at")
    @Builder.Default
    private LocalDateTime expiresAt = LocalDateTime.now().plusDays(7);
}
