package com.owasp.vulnerable.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.Map;

/**
 * 錯誤處理測試 API
 */
@RestController
@RequestMapping("/api/error")
public class ErrorController {

    /**
     * 觸發 NullPointerException
     */
    @GetMapping("/null")
    public ResponseEntity<?> triggerNullPointer() {
        String str = null;
        
        return ResponseEntity.ok(Map.of("length", str.length()));
    }

    /**
     * 觸發 ArrayIndexOutOfBoundsException
     */
    @GetMapping("/array")
    public ResponseEntity<?> triggerArrayOutOfBounds() {
        int[] arr = new int[5];
        
        return ResponseEntity.ok(Map.of("value", arr[100]));
    }

    /**
     * 觸發 NumberFormatException
     */
    @GetMapping("/parse")
    public ResponseEntity<?> triggerNumberFormat(@RequestParam(defaultValue = "abc") String number) {
        
        int parsed = Integer.parseInt(number);
        return ResponseEntity.ok(Map.of("parsed", parsed));
    }

    /**
     * 觸發 SQL 相關異常
     */
    @GetMapping("/sql")
    public ResponseEntity<?> triggerSqlError() throws SQLException {
        
        throw new SQLException(
            "ERROR: relation \"secret_admin_table\" does not exist\n" +
            "  Position: 15\n" +
            "  SQL: SELECT * FROM secret_admin_table WHERE password = 'admin123'"
        );
    }

    /**
     * 觸發帶有敏感資訊的異常
     */
    @GetMapping("/sensitive")
    public ResponseEntity<?> triggerSensitiveError() {
        
        throw new RuntimeException(
            "Failed to connect to database: " +
            "jdbc:postgresql://10.0.0.5:5432/production_db " +
            "with user 'db_admin' and password 'Pr0d_P@ssw0rd!'"
        );
    }

    /**
     * 觸發深層巢狀異常
     */
    @GetMapping("/nested")
    public ResponseEntity<?> triggerNestedError() {
        try {
            level1();
        } catch (Exception e) {
            throw new RuntimeException("Service layer error", e);
        }
        return ResponseEntity.ok("ok");
    }

    private void level1() {
        try {
            level2();
        } catch (Exception e) {
            throw new RuntimeException("Business logic error in UserService.processPayment()", e);
        }
    }

    private void level2() {
        try {
            level3();
        } catch (Exception e) {
            throw new RuntimeException("Data access error in PaymentRepository.findById()", e);
        }
    }

    private void level3() {
        throw new RuntimeException("Connection timeout to payment gateway at https://api.payment.internal:8443");
    }

    /**
     * 觸發帶有配置資訊的異常
     */
    @GetMapping("/config")
    public ResponseEntity<?> triggerConfigError() {
        throw new IllegalStateException(
            "Configuration error: Missing required property 'aws.secret.key'. " +
            "Current AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, " +
            "AWS_REGION=us-east-1, " +
            "Please check /app/config/secrets.yml"
        );
    }

    /**
     * 列出可用的錯誤觸發端點
     */
    @GetMapping("/list")
    public ResponseEntity<?> listEndpoints() {
        return ResponseEntity.ok(Map.of(
            "endpoints", Map.of(
                "/api/error/null", "觸發 NullPointerException",
                "/api/error/array", "觸發 ArrayIndexOutOfBoundsException",
                "/api/error/parse?number=abc", "觸發 NumberFormatException",
                "/api/error/sql", "觸發 SQLException（暴露資料庫結構）",
                "/api/error/sensitive", "觸發包含敏感資訊的異常",
                "/api/error/nested", "觸發深層巢狀異常（暴露程式結構）",
                "/api/error/config", "觸發配置相關異常（暴露配置路徑）"
            ),
            "warning", "這些端點會暴露敏感的 stack trace 資訊"
        ));
    }
}
