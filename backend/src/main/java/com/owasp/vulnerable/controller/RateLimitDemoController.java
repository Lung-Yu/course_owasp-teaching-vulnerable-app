package com.owasp.vulnerable.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 速率限制示範 API
 */
@RestController
@RequestMapping("/api/rate-limit")
@Slf4j
public class RateLimitDemoController {

    private final AtomicInteger requestCount = new AtomicInteger(0);

    /**
     * 敏感操作端點
     */
    @PostMapping("/sensitive-action")
    public ResponseEntity<?> sensitiveAction(@RequestBody Map<String, String> request) {
        int count = requestCount.incrementAndGet();
        
        log.info("Sensitive action #{} executed", count);
        
        return ResponseEntity.ok(Map.of(
            "message", "操作成功",
            "requestNumber", count,
            "timestamp", System.currentTimeMillis()
        ));
    }

    /**
     * 密碼重設請求
     * 可被濫用發送大量重設郵件
     */
    @PostMapping("/password-reset")
    public ResponseEntity<?> passwordReset(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        int count = requestCount.incrementAndGet();
        
        
        
        
        log.info("Password reset #{} requested for: {}", count, email);
        
        return ResponseEntity.ok(Map.of(
            "message", "密碼重設郵件已發送",
            "email", email,
            "requestNumber", count
        ));
    }

    /**
     * OTP 驗證
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> request) {
        String otp = request.get("otp");
        int count = requestCount.incrementAndGet();
        
        
        
        // 模擬 OTP 驗證（實際 OTP 為 123456）
        boolean valid = "123456".equals(otp);
        
        log.info("OTP verification #{}: {} - {}", count, otp, valid ? "SUCCESS" : "FAILED");
        
        if (valid) {
            return ResponseEntity.ok(Map.of(
                "message", "OTP 驗證成功",
                "verified", true,
                "attempts", count
            ));
        } else {
            return ResponseEntity.badRequest().body(Map.of(
                "message", "OTP 驗證失敗",
                "verified", false,
                "attempts", count
            ));
        }
    }

    /**
     * 登入嘗試
     */
    @PostMapping("/login-attempt")
    public ResponseEntity<?> loginAttempt(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        int count = requestCount.incrementAndGet();
        
        
        
        
        // 模擬登入驗證
        boolean valid = "admin".equals(username) && "admin123".equals(password);
        
        log.info("Login attempt #{}: {} - {}", count, username, valid ? "SUCCESS" : "FAILED");
        
        if (valid) {
            return ResponseEntity.ok(Map.of(
                "message", "登入成功",
                "username", username,
                "attempts", count
            ));
        } else {
            return ResponseEntity.status(401).body(Map.of(
                "message", "登入失敗",
                "attempts", count
            ));
        }
    }

    /**
     * 資源密集型操作
     */
    @GetMapping("/expensive-operation")
    public ResponseEntity<?> expensiveOperation(@RequestParam(defaultValue = "1000") int iterations) {
        int count = requestCount.incrementAndGet();
        
        
        
        
        long start = System.currentTimeMillis();
        
        // 模擬耗資源操作
        double result = 0;
        for (int i = 0; i < iterations; i++) {
            result += Math.sqrt(i) * Math.sin(i);
        }
        
        long duration = System.currentTimeMillis() - start;
        
        log.info("Expensive operation #{} completed in {}ms", count, duration);
        
        return ResponseEntity.ok(Map.of(
            "message", "操作完成",
            "iterations", iterations,
            "duration_ms", duration,
            "requestNumber", count
        ));
    }

    /**
     * 取得請求統計
     */
    @GetMapping("/stats")
    public ResponseEntity<?> getStats() {
        return ResponseEntity.ok(Map.of(
            "totalRequests", requestCount.get(),
            "message", "無速率限制 - 可接受無限請求"
        ));
    }

    /**
     * 重設計數器
     */
    @PostMapping("/reset-stats")
    public ResponseEntity<?> resetStats() {
        int previous = requestCount.getAndSet(0);
        return ResponseEntity.ok(Map.of(
            "message", "統計已重設",
            "previousCount", previous
        ));
    }
}
