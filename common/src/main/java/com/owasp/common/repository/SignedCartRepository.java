package com.owasp.common.repository;

import com.owasp.common.entity.SignedCart;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * 簽名購物車 Repository
 */
@Repository
public interface SignedCartRepository extends JpaRepository<SignedCart, Long> {

    Optional<SignedCart> findTopByUserIdOrderByCreatedAtDesc(Long userId);

    List<SignedCart> findByUserId(Long userId);

    @Query("SELECT c FROM SignedCart c WHERE c.expiresAt IS NOT NULL AND c.expiresAt < :now")
    List<SignedCart> findExpiredCarts(LocalDateTime now);

    void deleteByUserId(Long userId);
}
