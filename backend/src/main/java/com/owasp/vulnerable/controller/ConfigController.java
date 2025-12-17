package com.owasp.vulnerable.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 設定 API
 */
@RestController
@RequestMapping("/api/debug")
@Slf4j
public class ConfigController {

    @Value("${spring.datasource.url:jdbc:postgresql://localhost:5432/owasp_demo}")
    private String dbUrl;

    @Value("${spring.datasource.username:postgres}")
    private String dbUsername;

    @Value("${spring.datasource.password:postgres}")
    private String dbPassword;

    @Value("${jwt.secret:weak-secret-key-for-demo}")
    private String jwtSecret;

    
    private static final String DES_KEY = "12345678";
    private static final String AES_KEY = "1234567890123456";

    /**
     * 取得系統設定
     */
    @GetMapping("/config")
    public ResponseEntity<?> getConfig() {
        Map<String, Object> config = new HashMap<>();
        
        
        config.put("database", Map.of(
            "url", dbUrl,
            "username", dbUsername,
            "password", dbPassword,  
            "type", "PostgreSQL"
        ));
        
        
        config.put("jwt", Map.of(
            "secret", jwtSecret,  
            "algorithm", "HS256",
            "expiration", "86400000"
        ));
        
        
        config.put("encryption", Map.of(
            "des_key", DES_KEY,  
            "aes_key", AES_KEY,  
            "algorithm", "DES/ECB/PKCS5Padding"
        ));
        
        
        config.put("api_keys", Map.of(
            "stripe", "sk_test_EXAMPLE_KEY_DO_NOT_USE",
            "sendgrid", "SG.EXAMPLE_KEY_DO_NOT_USE",
            "aws_access_key", "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_key", "wJalrXUtnFEMI/EXAMPLE/bPxRfiCYEXAMPLEKEY"
        ));
        
        // 系統資訊
        config.put("system", Map.of(
            "java_version", System.getProperty("java.version"),
            "os", System.getProperty("os.name"),
            "user", System.getProperty("user.name"),
            "home", System.getProperty("user.home")
        ));
        
        log.warn("敏感設定被存取！");
        
        return ResponseEntity.ok(config);
    }

    /**
     * 取得環境變數
     */
    @GetMapping("/env")
    public ResponseEntity<?> getEnvironment() {
        Map<String, String> env = new HashMap<>(System.getenv());
        
        // 過濾一些太長的值
        env.replaceAll((k, v) -> v.length() > 500 ? v.substring(0, 500) + "..." : v);
        
        return ResponseEntity.ok(Map.of(
            "environment", env,
            "count", env.size()
        ));
    }

    /**
     * 取得系統屬性
     */
    @GetMapping("/properties")
    public ResponseEntity<?> getProperties() {
        Map<String, String> props = new HashMap<>();
        System.getProperties().forEach((k, v) -> props.put(k.toString(), v.toString()));
        
        return ResponseEntity.ok(Map.of(
            "properties", props,
            "count", props.size()
        ));
    }

    /**
     * 健康檢查（含詳細資訊）
     */
    @GetMapping("/health")
    public ResponseEntity<?> health() {
        Runtime runtime = Runtime.getRuntime();
        
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "memory", Map.of(
                "total", runtime.totalMemory(),
                "free", runtime.freeMemory(),
                "max", runtime.maxMemory()
            ),
            "processors", runtime.availableProcessors(),
            "database", Map.of(
                "url", dbUrl,  
                "status", "connected"
            )
        ));
    }
}
