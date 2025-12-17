package com.owasp.common.repository;

import com.owasp.common.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 使用者資料存取層
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email);
    
    boolean existsByUsername(String username);
    
    boolean existsByEmail(String email);
    
    // ✅ 安全：用於 SearchController 的參數化查詢方法
    List<User> findByUsernameContainingIgnoreCase(String username);
    
    List<User> findByFullNameContainingIgnoreCase(String fullName);
}
