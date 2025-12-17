package com.owasp.vulnerable.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.owasp.common.entity.DeserializationLog;
import com.owasp.common.entity.Plugin;
import com.owasp.common.entity.SignedCart;
import com.owasp.common.model.User;
import com.owasp.common.repository.DeserializationLogRepository;
import com.owasp.common.repository.PluginRepository;
import com.owasp.common.repository.SignedCartRepository;
import com.owasp.common.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;

/**
 * 
 */
@RestController
@RequestMapping("/api/integrity")
@RequiredArgsConstructor
@Slf4j
public class IntegrityController {

    private final UserRepository userRepository;
    private final PluginRepository pluginRepository;
    private final SignedCartRepository signedCartRepository;
    private final DeserializationLogRepository deserializationLogRepository;
    private final ObjectMapper objectMapper;


    /**
     * 
     * 直接反序列化客戶端傳來的 Java 序列化資料
     */
    @PostMapping(value = "/deserialize", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<?> deserializeObject(
            @RequestBody byte[] data,
            HttpServletRequest request) {
        
        log.info("Received serialized data, size: {} bytes", data.length);
        
        String sessionId = request.getSession().getId();
        String sourceIp = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        
        try {
            
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // 這裡會觸發 gadget chain 執行任意程式碼
            Object obj = ois.readObject();
            ois.close();
            
            // 記錄成功的反序列化
            DeserializationLog logEntry = DeserializationLog.builder()
                    .sessionId(sessionId)
                    .className(obj != null ? obj.getClass().getName() : "null")
                    .sourceIp(sourceIp)
                    .userAgent(userAgent)
                    .blocked(false)
                    .build();
            deserializationLogRepository.save(logEntry);
            
            log.info("Successfully deserialized object of type: {}", 
                    obj != null ? obj.getClass().getName() : "null");
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "objectType", obj != null ? obj.getClass().getName() : "null",
                "message", "Object deserialized successfully"
            ));
            
        } catch (Exception e) {
            log.error("Deserialization failed: {}", e.getMessage());
            
            DeserializationLog logEntry = DeserializationLog.builder()
                    .sessionId(sessionId)
                    .className("UNKNOWN")
                    .sourceIp(sourceIp)
                    .userAgent(userAgent)
                    .blocked(false)
                    .blockReason("Exception: " + e.getMessage())
                    .build();
            deserializationLogRepository.save(logEntry);
            
            return ResponseEntity.badRequest().body(Map.of(
                "status", "error",
                "error", e.getMessage()
            ));
        }
    }

    /**
     */
    @PostMapping("/deserialize/base64")
    public ResponseEntity<?> deserializeBase64(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {
        
        String base64Data = request.get("data");
        if (base64Data == null || base64Data.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Missing 'data' field"
            ));
        }
        
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            return deserializeObject(data, httpRequest);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid Base64 data"
            ));
        }
    }


    /**
     * 
     * 結帳時直接信任客戶端傳來的購物車資料
     */
    @PostMapping("/cart/checkout")
    public ResponseEntity<?> checkout(@RequestBody Map<String, Object> cartData) {
        
        log.info("Processing checkout with cart data: {}", cartData);
        
        
        try {
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) cartData.get("items");
            
            if (items == null || items.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Cart is empty"
                ));
            }
            
            BigDecimal total = BigDecimal.ZERO;
            List<Map<String, Object>> processedItems = new ArrayList<>();
            
            for (Map<String, Object> item : items) {
                
                String productName = (String) item.get("name");
                int quantity = ((Number) item.get("quantity")).intValue();
                BigDecimal price = new BigDecimal(item.get("price").toString());
                
                BigDecimal itemTotal = price.multiply(BigDecimal.valueOf(quantity));
                total = total.add(itemTotal);
                
                processedItems.add(Map.of(
                    "name", productName,
                    "quantity", quantity,
                    "price", price,
                    "subtotal", itemTotal
                ));
            }
            
            
            if (cartData.containsKey("discount")) {
                BigDecimal discount = new BigDecimal(cartData.get("discount").toString());
                total = total.subtract(discount);
                if (total.compareTo(BigDecimal.ZERO) < 0) {
                    total = BigDecimal.ZERO;
                }
            }
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "orderId", UUID.randomUUID().toString(),
                "items", processedItems,
                "total", total,
                "message", "Order placed successfully"
            ));
            
        } catch (Exception e) {
            log.error("Checkout failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid cart data: " + e.getMessage()
            ));
        }
    }

    /**
     * 儲存購物車（無簽名）
     */
    @PostMapping("/cart/save")
    public ResponseEntity<?> saveCart(
            @RequestBody Map<String, Object> cartData,
            @RequestHeader(value = "X-User-Id", required = false) Long userId) {
        
        if (userId == null) {
            userId = 1L; // 預設使用者
        }
        
        try {
            String cartJson = objectMapper.writeValueAsString(cartData);
            
            
            SignedCart cart = SignedCart.builder()
                    .userId(userId)
                    .cartData(cartJson)
                    .hmacSignature(null) // 不簽名
                    .expiresAt(LocalDateTime.now().plusHours(24))
                    .build();
            
            signedCartRepository.save(cart);
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "cartId", cart.getId(),
                "message", "Cart saved"
            ));
            
        } catch (JsonProcessingException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid cart data"
            ));
        }
    }


    /**
     * 
     * 使用 BeanUtils.copyProperties 複製所有欄位
     */
    @PutMapping("/profile/{userId}")
    public ResponseEntity<?> updateProfile(
            @PathVariable Long userId,
            @RequestBody Map<String, Object> profileData) {
        
        log.info("Updating profile for user {}: {}", userId, profileData);
        
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        User user = userOpt.get();
        
        
        
        profileData.forEach((key, value) -> {
            try {
                java.lang.reflect.Field field = User.class.getDeclaredField(key);
                field.setAccessible(true);
                
                // 型別轉換
                if (field.getType() == BigDecimal.class && value != null) {
                    value = new BigDecimal(value.toString());
                } else if (field.getType() == Boolean.class && value != null) {
                    value = Boolean.valueOf(value.toString());
                } else if (field.getType() == User.Role.class && value != null) {
                    
                    value = User.Role.valueOf(value.toString().toUpperCase());
                }
                
                field.set(user, value);
                log.info("Set field {} to {}", key, value);
            } catch (NoSuchFieldException e) {
                log.debug("Field {} not found, skipping", key);
            } catch (Exception e) {
                log.warn("Failed to set field {}: {}", key, e.getMessage());
            }
        });
        
        userRepository.save(user);
        
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "Profile updated",
            "user", Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "role", user.getRole().toString(),
                "enabled", user.getEnabled()
            )
        ));
    }

    /**
     */
    @PostMapping("/profile/update")
    public ResponseEntity<?> updateProfileBean(@RequestBody UserUpdateDTO updateDTO) {
        
        Long userId = updateDTO.getId();
        if (userId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "User ID required"));
        }
        
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        User user = userOpt.get();
        
        
        // 如果 DTO 包含 role 欄位，也會被複製
        BeanUtils.copyProperties(updateDTO, user);
        
        userRepository.save(user);
        
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "Profile updated via BeanUtils"
        ));
    }

    // DTO for Mass Assignment demo
    @lombok.Data
    public static class UserUpdateDTO {
        private Long id;
        private String username;
        private String email;
        private String fullName;
        private String phone;
        
        private User.Role role;
        private Boolean enabled;
    }


    /**
     * 
     * 安裝插件時不驗證 SHA256 hash
     */
    @PostMapping("/plugins/install")
    public ResponseEntity<?> installPlugin(@RequestBody Map<String, String> request) {
        
        String pluginName = request.get("name");
        String downloadUrl = request.get("url");
        
        if (pluginName == null || downloadUrl == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Plugin name and URL required"
            ));
        }
        
        log.info("Installing plugin: {} from {}", pluginName, downloadUrl);
        
        try {
            
            // 模擬下載（實際環境中會下載檔案）
            log.info("Downloading plugin from: {}", downloadUrl);
            
            
            Plugin plugin = Plugin.builder()
                    .name(pluginName)
                    .version(request.getOrDefault("version", "1.0.0"))
                    .description(request.get("description"))
                    .downloadUrl(downloadUrl)
                    .sha256Hash(null) 
                    .verified(false)
                    .publisher(request.get("publisher"))
                    .active(true)
                    .build();
            
            pluginRepository.save(plugin);
            
            // 模擬執行插件的初始化腳本
            String initScript = request.get("initScript");
            if (initScript != null) {
                log.warn("Executing init script: {}", initScript);
                executeInitScript(initScript);
            }
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "pluginId", plugin.getId(),
                "message", "Plugin installed successfully (without verification)"
            ));
            
        } catch (Exception e) {
            log.error("Plugin installation failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Installation failed: " + e.getMessage()
            ));
        }
    }

    /**
     */
    private void executeInitScript(String script) {
        log.warn("Simulating script execution: {}", script);
    }

    /**
     * 列出已安裝的插件
     */
    @GetMapping("/plugins")
    public ResponseEntity<?> listPlugins() {
        List<Plugin> plugins = pluginRepository.findAll();
        return ResponseEntity.ok(Map.of(
            "plugins", plugins,
            "count", plugins.size()
        ));
    }


    /**
     * 
     * Cookie 儲存會話資料
     */
    @PostMapping("/session/create")
    public ResponseEntity<?> createSession(
            @RequestBody Map<String, Object> sessionData,
            HttpServletResponse response) {
        
        try {
            
            String sessionJson = objectMapper.writeValueAsString(sessionData);
            String encodedSession = Base64.getEncoder().encodeToString(
                    sessionJson.getBytes(StandardCharsets.UTF_8));
            
            Cookie sessionCookie = new Cookie("user_session", encodedSession);
            sessionCookie.setPath("/");
            sessionCookie.setMaxAge(3600); // 1 小時
            sessionCookie.setHttpOnly(false); 
            response.addCookie(sessionCookie);
            
            log.info("Created session cookie: {}", encodedSession);
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Session created",
                "sessionData", encodedSession
            ));
            
        } catch (JsonProcessingException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid session data"
            ));
        }
    }

    /**
     */
    @GetMapping("/session/validate")
    public ResponseEntity<?> validateSession(
            @CookieValue(value = "user_session", required = false) String sessionCookie) {
        
        if (sessionCookie == null || sessionCookie.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "No session cookie found"
            ));
        }
        
        try {
            
            String sessionJson = new String(
                    Base64.getDecoder().decode(sessionCookie),
                    StandardCharsets.UTF_8);
            
            @SuppressWarnings("unchecked")
            Map<String, Object> sessionData = objectMapper.readValue(sessionJson, Map.class);
            
            log.info("Session validated: {}", sessionData);
            
            
            String role = (String) sessionData.getOrDefault("role", "user");
            boolean isAdmin = "admin".equalsIgnoreCase(role);
            
            return ResponseEntity.ok(Map.of(
                "status", "valid",
                "sessionData", sessionData,
                "isAdmin", isAdmin,
                "message", "Session is valid"
            ));
            
        } catch (Exception e) {
            log.error("Session validation failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid session: " + e.getMessage()
            ));
        }
    }

    /**
     */
    @PostMapping("/session/admin-action")
    public ResponseEntity<?> adminAction(
            @CookieValue(value = "user_session", required = false) String sessionCookie,
            @RequestBody Map<String, Object> actionData) {
        
        if (sessionCookie == null) {
            return ResponseEntity.status(401).body(Map.of(
                "error", "Authentication required"
            ));
        }
        
        try {
            String sessionJson = new String(
                    Base64.getDecoder().decode(sessionCookie),
                    StandardCharsets.UTF_8);
            
            @SuppressWarnings("unchecked")
            Map<String, Object> sessionData = objectMapper.readValue(sessionJson, Map.class);
            
            
            String role = (String) sessionData.getOrDefault("role", "user");
            
            if (!"admin".equalsIgnoreCase(role)) {
                return ResponseEntity.status(403).body(Map.of(
                    "error", "Admin privileges required"
                ));
            }
            
            // 執行管理員操作
            String action = (String) actionData.get("action");
            log.warn("Admin action executed: {} by session user: {}", 
                    action, sessionData.get("username"));
            
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "action", action,
                "executedBy", sessionData.get("username"),
                "message", "Admin action completed"
            ));
            
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid session"
            ));
        }
    }

    // ==================== 輔助方法 ====================

    private String calculateSha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * 取得反序列化日誌
     */
    @GetMapping("/logs/deserialization")
    public ResponseEntity<?> getDeserializationLogs() {
        List<DeserializationLog> logs = deserializationLogRepository.findAll();
        return ResponseEntity.ok(Map.of(
            "logs", logs,
            "totalAttempts", logs.size(),
            "blockedCount", deserializationLogRepository.countByBlockedTrue()
        ));
    }
}
