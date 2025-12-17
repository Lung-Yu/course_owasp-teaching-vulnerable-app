package com.owasp.vulnerable.controller;

import com.owasp.common.dto.UserDTO;
import com.owasp.common.model.User;
import com.owasp.common.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 管理員 API
 */
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserRepository userRepository;

    // 模擬系統設定（實際應該在資料庫或設定檔）
    private static final Map<String, Object> systemConfig = new HashMap<>();
    
    static {
        systemConfig.put("database.host", "postgres");
        systemConfig.put("database.password", "postgres123");
        systemConfig.put("api.secret", "super-secret-api-key-12345");
        systemConfig.put("admin.emails", List.of("admin@example.com"));
        systemConfig.put("debug.mode", true);
    }

    /**
     * 取得所有使用者（含敏感資料）
     * 
     */
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        
        
        return ResponseEntity.ok(userRepository.findAll());
    }

    /**
     * 修改使用者角色
     * 
     */
    @PostMapping("/users/{id}/role")
    public ResponseEntity<?> changeUserRole(@PathVariable Long id, 
                                            @RequestParam String role) {
        
        return userRepository.findById(id)
                .map(user -> {
                    user.setRole(User.Role.valueOf(role));
                    userRepository.save(user);
                    return ResponseEntity.ok(Map.of(
                        "message", "角色更新成功",
                        "userId", id,
                        "newRole", role
                    ));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 取得系統設定
     * 
     */
    @GetMapping("/config")
    public ResponseEntity<?> getSystemConfig() {
        
        return ResponseEntity.ok(systemConfig);
    }

    /**
     * 修改系統設定
     */
    @PostMapping("/config")
    public ResponseEntity<?> updateSystemConfig(@RequestBody Map<String, Object> config) {
        
        systemConfig.putAll(config);
        return ResponseEntity.ok(Map.of(
            "message", "設定更新成功",
            "config", systemConfig
        ));
    }

    /**
     * 匯出使用者資料
     */
    @GetMapping("/export/users")
    public ResponseEntity<?> exportUsers() {
        
        List<Map<String, Object>> exportData = userRepository.findAll().stream()
                .map(user -> {
                    Map<String, Object> data = new HashMap<>();
                    data.put("id", user.getId());
                    data.put("username", user.getUsername());
                    data.put("email", user.getEmail());
                    data.put("password", user.getPassword()); 
                    data.put("role", user.getRole().name());
                    data.put("phone", user.getPhone());
                    return data;
                })
                .collect(Collectors.toList());

        return ResponseEntity.ok(Map.of(
            "total", exportData.size(),
            "users", exportData
        ));
    }

    /**
     * 停用使用者
     */
    @PostMapping("/users/{id}/disable")
    public ResponseEntity<?> disableUser(@PathVariable Long id) {
        
        return userRepository.findById(id)
                .map(user -> {
                    user.setEnabled(false);
                    userRepository.save(user);
                    return ResponseEntity.ok(Map.of(
                        "message", "使用者已停用",
                        "userId", id
                    ));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 系統統計
     */
    @GetMapping("/stats")
    public ResponseEntity<?> getStats() {
        
        long totalUsers = userRepository.count();
        long adminCount = userRepository.findAll().stream()
                .filter(u -> u.getRole() == User.Role.ADMIN)
                .count();

        return ResponseEntity.ok(Map.of(
            "totalUsers", totalUsers,
            "adminCount", adminCount,
            "userCount", totalUsers - adminCount,
            "systemConfig", systemConfig 
        ));
    }
}
