package com.owasp.vulnerable.controller;

import com.owasp.common.dto.LoginRequest;
import com.owasp.common.dto.LoginResponse;
import com.owasp.common.dto.RegisterRequest;
import com.owasp.common.model.User;
import com.owasp.common.repository.UserRepository;
import com.owasp.vulnerable.service.VulnerableJwtService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 認證 API
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final VulnerableJwtService jwtService;

    @PersistenceContext
    private EntityManager entityManager;

    
    private static final Map<String, String> resetTokens = new ConcurrentHashMap<>();
    
    
    private static final String RESET_SECRET = "fixed-secret-2024";

    /**
     * 登入
     * 
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        
        
        
        String sql = "SELECT * FROM users WHERE username = '" + request.getUsername() 
                   + "' AND password = '" + request.getPassword() + "'";
        
        try {
            @SuppressWarnings("unchecked")
            List<User> users = entityManager.createNativeQuery(sql, User.class).getResultList();
            
            if (!users.isEmpty()) {
                User user = users.get(0);
                String token = jwtService.generateToken(user);
                return ResponseEntity.ok(LoginResponse.builder()
                        .token(token)
                        .username(user.getUsername())
                        .role(user.getRole().name())
                        .message("登入成功")
                        .build());
            }
            
            
            boolean userExists = userRepository.existsByUsername(request.getUsername());
            if (!userExists) {
                
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "使用者不存在",
                    "code", "USER_NOT_FOUND"
                ));
            } else {
                
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "密碼錯誤",
                    "code", "INVALID_PASSWORD"
                ));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "登入失敗",
                "detail", e.getMessage(),
                "sql", sql
            ));
        }
    }

    /**
     * 註冊
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        
        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "此帳號已被使用：" + request.getUsername(),
                "code", "USERNAME_EXISTS"
            ));
        }

        
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "此 Email 已被註冊：" + request.getEmail(),
                "code", "EMAIL_EXISTS"
            ));
        }
        
        User user = User.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .email(request.getEmail())
                .fullName(request.getFullName())
                .role(User.Role.USER)
                .build();

        userRepository.save(user);

        return ResponseEntity.ok(Map.of(
            "message", "註冊成功",
            "username", user.getUsername()
        ));
    }

    /**
     * 忘記密碼
     * 
     * Token 生成方式：MD5(username + 固定密鑰)
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        
        
        if (!userRepository.existsByUsername(username)) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "使用者不存在：" + username,
                "code", "USER_NOT_FOUND"
            ));
        }

        
        // Token = MD5(username + 固定密鑰)
        String token = generatePredictableToken(username);
        
        // 儲存 Token（無過期時間）
        resetTokens.put(token, username);

        
        return ResponseEntity.ok(Map.of(
            "message", "密碼重設連結已發送",
            "resetToken", token,  
            "resetUrl", "/api/auth/reset-password?token=" + token
        ));
    }

    /**
     * 重設密碼
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");

        String username = resetTokens.get(token);
        if (username == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "無效的重設 Token"
            ));
        }

        
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null) {
            
            user.setPassword(newPassword);
            userRepository.save(user);

            return ResponseEntity.ok(Map.of(
                "message", "密碼重設成功"
            ));
        }

        return ResponseEntity.badRequest().body(Map.of(
            "error", "使用者不存在"
        ));
    }

    /**
     * 檢查帳號是否存在
     */
    @GetMapping("/check-username")
    public ResponseEntity<?> checkUsername(@RequestParam String username) {
        
        boolean exists = userRepository.existsByUsername(username);
        return ResponseEntity.ok(Map.of(
            "username", username,
            "exists", exists,
            "available", !exists
        ));
    }

    /**
     * 修改密碼
     */
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String newPassword = request.get("newPassword");
        
        // String oldPassword = request.get("oldPassword");

        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "使用者不存在"
            ));
        }

        
        
        user.setPassword(newPassword);
        userRepository.save(user);

        return ResponseEntity.ok(Map.of(
            "message", "密碼修改成功"
        ));
    }

    /**
     */
    private String generatePredictableToken(String username) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            String input = username + RESET_SECRET;
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return username + "-reset-token";
        }
    }
}
