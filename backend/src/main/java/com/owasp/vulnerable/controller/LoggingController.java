package com.owasp.vulnerable.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.owasp.common.entity.LoginAttempt;
import com.owasp.common.entity.SecurityAlert;
import com.owasp.common.entity.SecurityAuditLog;
import com.owasp.common.repository.LoginAttemptRepository;
import com.owasp.common.repository.SecurityAlertRepository;
import com.owasp.common.repository.SecurityAuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 日誌 API
 */
@RestController
@RequestMapping("/api/logging")
@RequiredArgsConstructor
@Slf4j
public class LoggingController {

    private final SecurityAuditLogRepository auditLogRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final SecurityAlertRepository alertRepository;
    private final ObjectMapper objectMapper;

    // ==================== Insufficient Logging ====================

    /**
     * 
     * 問題：
     * 1. 失敗的登入嘗試沒有被記錄
     * 3. 沒有來源 IP 記錄
     */
    @PostMapping("/demo/login")
    public ResponseEntity<?> vulnerableLogin(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");
        
        
        if ("admin".equals(username) && "admin123".equals(password)) {
            log.info("User logged in: {}", username);
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "登入成功"
            ));
        }
        
        
        
        return ResponseEntity.status(401).body(Map.of(
            "status", "error",
            "message", "帳號或密碼錯誤"
        ));
    }

    /**
     */
    @PostMapping("/demo/sensitive-action")
    public ResponseEntity<?> sensitiveActionNoAudit(
            @RequestBody Map<String, Object> actionData,
            HttpServletRequest request) {
        
        String action = (String) actionData.get("action");
        String targetUser = (String) actionData.get("targetUser");
        
        
        // 例如：修改用戶權限、刪除資料等
        
        if ("DELETE_USER".equals(action)) {
            // 實際刪除用戶的邏輯...
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "用戶已刪除: " + targetUser
            ));
        }
        
        if ("CHANGE_ROLE".equals(action)) {
            String newRole = (String) actionData.get("newRole");
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "角色已變更為: " + newRole
            ));
        }
        
        return ResponseEntity.badRequest().body(Map.of(
            "error", "未知操作"
        ));
    }

    /**
     * 
     * 
     */
    @PostMapping("/demo/search")
    public ResponseEntity<?> vulnerableSearch(@RequestBody Map<String, String> searchData) {
        String query = searchData.get("query");
        String username = searchData.get("username");
        
        
        log.info("User {} searched for: {}", username, query);
        
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "query", query,
            "results", List.of()
        ));
    }

    /**
     */
    @GetMapping("/demo/user-agent")
    public ResponseEntity<?> logUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        
        
        log.info("Request from User-Agent: {}", userAgent);
        
        return ResponseEntity.ok(Map.of(
            "userAgent", userAgent
        ));
    }

    // ==================== Omission of Security-relevant Information ====================

    /**
     * 
     * 問題：
     * 1. 沒有記錄來源 IP
     * 2. 沒有 correlation ID
     * 3. 沒有時間戳（依賴日誌框架）
     * 4. 沒有用戶識別資訊
     */
    @PostMapping("/demo/data-access")
    public ResponseEntity<?> accessDataIncomplete(
            @RequestBody Map<String, Object> accessRequest,
            HttpServletRequest request) {
        
        String resourceId = (String) accessRequest.get("resourceId");
        
        
        log.info("Data accessed: {}", resourceId);
        
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "data", Map.of("id", resourceId, "content", "sensitive data")
        ));
    }

    /**
     * 
     * 
     */
    @PostMapping("/demo/register")
    public ResponseEntity<?> registerWithSensitiveLog(@RequestBody Map<String, String> userData) {
        String username = userData.get("username");
        String password = userData.get("password");
        String email = userData.get("email");
        String creditCard = userData.get("creditCard");
        
        
        log.debug("User registration - username: {}, password: {}, email: {}, creditCard: {}",
                username, password, email, creditCard);
        
        
        try {
            String requestJson = objectMapper.writeValueAsString(userData);
            log.info("Registration request: {}", requestJson);
        } catch (Exception e) {
            log.error("Failed to serialize request", e);
        }
        
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "註冊成功"
        ));
    }

    /**
     */
    @GetMapping("/demo/api-call")
    public ResponseEntity<?> apiCallWithTokenLogged(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-API-Key", required = false) String apiKey) {
        
        
        log.info("API call with Authorization: {}", authHeader);
        log.info("API call with X-API-Key: {}", apiKey);
        
        return ResponseEntity.ok(Map.of(
            "status", "success"
        ));
    }

    // ==================== Logging of Excessive Data ====================

    /**
     */
    @PostMapping("/demo/process")
    public ResponseEntity<?> processWithExcessiveLogging(
            @RequestBody Map<String, Object> requestData,
            HttpServletRequest request) {
        
        
        try {
            String fullRequest = objectMapper.writeValueAsString(requestData);
            log.debug("Full request body: {}", fullRequest);
        } catch (Exception e) {
            // ignore
        }
        
        
        log.debug("=== All Request Headers ===");
        request.getHeaderNames().asIterator().forEachRemaining(headerName -> {
            log.debug("Header {}: {}", headerName, request.getHeader(headerName));
        });
        
        
        log.debug("Session ID: {}", request.getSession().getId());
        
        
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                log.debug("Cookie {}: {}", cookie.getName(), cookie.getValue());
            }
        }
        
        return ResponseEntity.ok(Map.of(
            "status", "processed"
        ));
    }

    // ==================== 無認證的日誌檢視 API ====================

    /**
     */
    @GetMapping("/view/audit")
    public ResponseEntity<?> viewAuditLogs(
            @RequestParam(defaultValue = "100") int limit) {
        
        
        List<SecurityAuditLog> logs = auditLogRepository.findAll()
                .stream()
                .limit(limit)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(Map.of(
            "logs", logs,
            "count", logs.size()
        ));
    }

    /**
     */
    @GetMapping("/view/login-attempts")
    public ResponseEntity<?> viewLoginAttempts(
            @RequestParam(required = false) String username) {
        
        List<LoginAttempt> attempts;
        if (username != null) {
            attempts = loginAttemptRepository.findByUsername(username);
        } else {
            attempts = loginAttemptRepository.findAll();
        }
        
        return ResponseEntity.ok(Map.of(
            "attempts", attempts,
            "count", attempts.size()
        ));
    }

    /**
     */
    @GetMapping("/view/alerts")
    public ResponseEntity<?> viewAlerts() {
        List<SecurityAlert> alerts = alertRepository.findAll();
        
        return ResponseEntity.ok(Map.of(
            "alerts", alerts,
            "unacknowledged", alertRepository.countByAcknowledgedFalse(),
            "unresolved", alertRepository.countByResolvedFalse()
        ));
    }

    /**
     */
    @GetMapping("/view/file")
    public ResponseEntity<?> viewLogFile(
            @RequestParam(defaultValue = "vulnerable-app.log") String filename,
            @RequestParam(defaultValue = "100") int lines) {
        
        try {
            
            String logPath = "/app/logs/" + filename;
            
            
            List<String> logLines = Files.readAllLines(Paths.get(logPath))
                    .stream()
                    .skip(Math.max(0, Files.readAllLines(Paths.get(logPath)).size() - lines))
                    .collect(Collectors.toList());
            
            return ResponseEntity.ok(Map.of(
                "filename", filename,
                "lines", logLines,
                "lineCount", logLines.size()
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of(
                "error", "無法讀取日誌檔案: " + e.getMessage(),
                "filename", filename
            ));
        }
    }

    /**
     */
    @GetMapping("/alerts/poll")
    public ResponseEntity<?> pollAlerts(
            @RequestParam(defaultValue = "0") long lastAlertId) {
        
        List<SecurityAlert> newAlerts = alertRepository.findByAcknowledgedFalseOrderByCreatedAtDesc()
                .stream()
                .filter(a -> a.getId() > lastAlertId)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(Map.of(
            "alerts", newAlerts,
            "count", newAlerts.size(),
            "timestamp", LocalDateTime.now()
        ));
    }

    // ==================== 測試用：產生日誌條目 ====================

    /**
     * 用於測試：產生各種日誌條目
     */
    @PostMapping("/test/generate")
    public ResponseEntity<?> generateTestLogs(@RequestBody Map<String, Object> config) {
        int count = (int) config.getOrDefault("count", 10);
        String type = (String) config.getOrDefault("type", "INFO");
        
        for (int i = 0; i < count; i++) {
            switch (type.toUpperCase()) {
                case "ERROR":
                    log.error("Test error log entry #{}", i);
                    break;
                case "WARN":
                    log.warn("Test warning log entry #{}", i);
                    break;
                case "DEBUG":
                    log.debug("Test debug log entry #{}", i);
                    break;
                default:
                    log.info("Test info log entry #{}", i);
            }
        }
        
        return ResponseEntity.ok(Map.of(
            "generated", count,
            "type", type
        ));
    }

    /**
     * 用於測試：模擬失敗登入（不記錄）
     */
    @PostMapping("/test/brute-force")
    public ResponseEntity<?> simulateBruteForce(@RequestBody Map<String, Object> config) {
        int attempts = (int) config.getOrDefault("attempts", 100);
        String username = (String) config.getOrDefault("username", "admin");
        
        int failed = 0;
        for (int i = 0; i < attempts; i++) {
            
            // 登入嘗試
            failed++;
        }
        
        return ResponseEntity.ok(Map.of(
            "username", username,
            "attempts", attempts,
            "failed", failed,
            "logged", 0
        ));
    }
}
