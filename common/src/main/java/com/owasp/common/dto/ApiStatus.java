package com.owasp.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * API 狀態回應 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiStatus {
    private String application;
    private String version;
    private String mode;           // "vulnerable" 或 "secure"
    private String modeLabel;
    private String description;
    private Map<String, Boolean> vulnerabilities;
}
