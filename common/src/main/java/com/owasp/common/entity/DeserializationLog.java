package com.owasp.common.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 反序列化審計日誌
 * 
 * A08:2021 - Software and Data Integrity Failures
 */
@Entity
@Table(name = "deserialization_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeserializationLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "session_id", length = 100)
    private String sessionId;

    @Column(name = "class_name", length = 500)
    private String className;

    @Column(name = "payload_size")
    private Integer payloadSize;

    @Column(name = "payload_hash", length = 64)
    private String payloadHash;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column
    @Builder.Default
    private Boolean blocked = false;

    @Column(name = "block_reason", length = 255)
    private String blockReason;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
}
