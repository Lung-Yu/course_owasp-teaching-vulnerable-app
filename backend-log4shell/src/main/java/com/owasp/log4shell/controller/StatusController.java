package com.owasp.log4shell.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * 健康檢查 Controller
 */
@RestController
@CrossOrigin(origins = "*")
public class StatusController {

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "backend-log4shell");
        response.put("vulnerable", true);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/status")
    public ResponseEntity<?> status() {
        Map<String, Object> response = new HashMap<>();
        response.put("version", "vulnerable");
        response.put("service", "Log4Shell Demo");
        response.put("log4j_version", "2.14.1");
        return ResponseEntity.ok(response);
    }
}
