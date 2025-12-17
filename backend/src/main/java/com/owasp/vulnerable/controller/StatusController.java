package com.owasp.vulnerable.controller;

import com.owasp.common.dto.ApiStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * 系統狀態 API
 */
@RestController
@RequestMapping("/api/status")
public class StatusController {

    @Value("${app.mode}")
    private String mode;

    @Value("${app.mode-label}")
    private String modeLabel;

    @Value("${app.description}")
    private String description;

    @GetMapping
    public ResponseEntity<ApiStatus> getStatus() {
        Map<String, Boolean> vulnerabilities = new HashMap<>();
        vulnerabilities.put("sqlInjection", true);
        vulnerabilities.put("xss", true);
        vulnerabilities.put("brokenAuth", true);
        vulnerabilities.put("sensitiveDataExposure", true);
        vulnerabilities.put("brokenAccessControl", true);
        vulnerabilities.put("securityMisconfiguration", true);
        vulnerabilities.put("csrfDisabled", true);

        ApiStatus status = ApiStatus.builder()
                .version("1.0.0")
                .mode(mode)
                .modeLabel(modeLabel)
                .description(description)
                .vulnerabilities(vulnerabilities)
                .build();

        return ResponseEntity.ok(status);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> health = new HashMap<>();
        health.put("status", "UP");
        health.put("mode", mode);
        health.put("modeLabel", modeLabel);
        return ResponseEntity.ok(health);
    }
}
