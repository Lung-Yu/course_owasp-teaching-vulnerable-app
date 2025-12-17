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
@Table(name = "plugins")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Plugin {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 100)
    private String name;

    @Column(nullable = false, length = 20)
    private String version;

    @Column(length = 500)
    private String description;

    @Column(name = "download_url", length = 500)
    private String downloadUrl;

    @Column(name = "sha256_hash", length = 64)
    private String sha256Hash;

    @Column(length = 1024)
    private String signature;

    @Column(length = 100)
    private String publisher;

    @Column
    @Builder.Default
    private Boolean verified = false;

    @Column(name = "installed_at")
    @Builder.Default
    private LocalDateTime installedAt = LocalDateTime.now();

    @Column
    @Builder.Default
    private Boolean active = true;

    /**
     * 驗證插件完整性
     * @param actualHash 實際下載的檔案 hash
     * @return 是否匹配
     */
    public boolean verifyIntegrity(String actualHash) {
        if (sha256Hash == null || actualHash == null) {
            return false;
        }
        return sha256Hash.equalsIgnoreCase(actualHash);
    }
}
