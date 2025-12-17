package com.owasp.common.repository;

import com.owasp.common.model.Order;
import com.owasp.common.model.Order.Status;
import com.owasp.common.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 訂單資料存取層
 */
@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
    
    List<Order> findByUser(User user);
    
    List<Order> findByUserId(Long userId);
    
    Optional<Order> findByOrderNumber(String orderNumber);
    
    List<Order> findByStatus(Status status);
    
    // ✅ 安全：用於 SearchController 的參數化查詢方法
    List<Order> findByUserIdAndStatus(Long userId, Status status);
}
