package com.owasp.common.repository;

import com.owasp.common.entity.CouponUsage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CouponUsageRepository extends JpaRepository<CouponUsage, Long> {
    List<CouponUsage> findByCouponIdAndUserId(Long couponId, Long userId);
    int countByCouponIdAndUserId(Long couponId, Long userId);
    int countByCouponId(Long couponId);
}
