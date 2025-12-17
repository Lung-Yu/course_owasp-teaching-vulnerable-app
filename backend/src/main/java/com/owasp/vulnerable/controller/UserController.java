package com.owasp.vulnerable.controller;

import com.owasp.common.dto.UserDTO;
import com.owasp.common.model.User;
import com.owasp.common.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * 使用者 API
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    
    
    private static final String DES_KEY = "12345678";
    
    
    private static final Map<Long, Map<String, String>> USER_SENSITIVE_DATA = new HashMap<>();
    
    static {
        // 初始化測試資料
        // admin 的資料
        USER_SENSITIVE_DATA.put(1L, Map.of(
            "creditCard", "4111111111111111",
            "cvv", "123",
            "ssn", "123-45-6789",
            "passwordHash", "0192023a7bbd73250516f069df18b500"  // MD5 of "admin123"
        ));
        // user 的資料
        USER_SENSITIVE_DATA.put(2L, Map.of(
            "creditCard", "5500000000000004",
            "cvv", "456",
            "ssn", "987-65-4321",
            "passwordHash", "6ad14ba9986e3615423dfca256d04e3f"  // MD5 of "user123"
        ));
        // alice 的資料
        USER_SENSITIVE_DATA.put(3L, Map.of(
            "creditCard", "340000000000009",
            "cvv", "789",
            "ssn", "456-78-9012",
            "passwordHash", "5d41402abc4b2a76b9719d911017c592"  // MD5 of "hello"
        ));
    }

    /**
     * 取得所有使用者
     */
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        
        return ResponseEntity.ok(userRepository.findAll());
    }

    /**
     * 取得使用者詳情
     * 
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        
        return userRepository.findById(id)
                .map(user -> {
                    
                    return ResponseEntity.ok(user);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 更新使用者
     * 
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody UserDTO dto) {
        return userRepository.findById(id)
                .map(user -> {
                    
                    user.setEmail(dto.getEmail());
                    user.setFullName(dto.getFullName());
                    user.setPhone(dto.getPhone());
                    
                    
                    if (dto.getRole() != null) {
                        user.setRole(User.Role.valueOf(dto.getRole()));
                    }
                    
                    userRepository.save(user);
                    return ResponseEntity.ok(Map.of("message", "使用者更新成功"));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 刪除使用者
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
            return ResponseEntity.ok(Map.of("message", "使用者刪除成功"));
        }
        return ResponseEntity.notFound().build();
    }

    /**
     * 取得使用者完整資料（含敏感資訊）
     */
    @GetMapping("/{id}/sensitive")
    public ResponseEntity<?> getUserSensitiveData(@PathVariable Long id) {
        return userRepository.findById(id)
                .map(user -> {
                    Map<String, Object> response = new HashMap<>();
                    response.put("id", user.getId());
                    response.put("username", user.getUsername());
                    response.put("email", user.getEmail());
                    response.put("role", user.getRole());
                    
                    
                    Map<String, String> sensitive = USER_SENSITIVE_DATA.get(id);
                    if (sensitive != null) {
                        
                        response.put("passwordHash", sensitive.get("passwordHash"));
                        response.put("hashAlgorithm", "MD5");
                        
                        
                        try {
                            String encryptedCC = encryptDES(sensitive.get("creditCard"));
                            response.put("creditCardEncrypted", encryptedCC);
                            response.put("encryptionAlgorithm", "DES/ECB");
                        } catch (Exception e) {
                            response.put("creditCard", sensitive.get("creditCard"));  // 加密失敗就給明文
                        }
                        
                        response.put("cvv", sensitive.get("cvv"));  
                        response.put("ssn", sensitive.get("ssn"));  
                    }
                    
                    return ResponseEntity.ok(response);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 匯出所有使用者（含敏感資料）
     */
    @GetMapping("/export")
    public ResponseEntity<?> exportUsers() {
        List<Map<String, Object>> exportData = new ArrayList<>();
        
        for (User user : userRepository.findAll()) {
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getId());
            userData.put("username", user.getUsername());
            userData.put("email", user.getEmail());
            userData.put("role", user.getRole());
            userData.put("password", user.getPassword());  
            
            Map<String, String> sensitive = USER_SENSITIVE_DATA.get(user.getId());
            if (sensitive != null) {
                userData.put("passwordHash_md5", sensitive.get("passwordHash"));
                userData.put("creditCard", sensitive.get("creditCard"));  
                userData.put("ssn", sensitive.get("ssn"));
            }
            
            exportData.add(userData);
        }
        
        return ResponseEntity.ok(Map.of(
            "users", exportData,
            "exportedAt", new Date().toString(),
            "warning", "此匯出包含敏感資料，請妥善保管"
        ));
    }

    // ========== 內部方法 ==========

    /**
     */
    private String encryptDES(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
