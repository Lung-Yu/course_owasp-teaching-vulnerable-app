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
@Table(name = "software_updates")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SoftwareUpdate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "component_name", nullable = false, length = 100)
    private String componentName;

    @Column(name = "current_version", length = 20)
    private String currentVersion;

    @Column(name = "new_version", length = 20)
    private String newVersion;

    @Column(name = "update_url", length = 500)
    private String updateUrl;

    @Column(name = "sha256_hash", length = 64)
    private String sha256Hash;

    @Column(length = 1024)
    private String signature;

    @Column
    @Builder.Default
    private Boolean verified = false;

    @Column(name = "applied_at")
    private LocalDateTime appliedAt;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * 驗證更新完整性
     */
    public boolean verifyIntegrity(String actualHash) {
        if (sha256Hash == null || actualHash == null) {
            return false;
        }
        return sha256Hash.equalsIgnoreCase(actualHash);
    }
}
