package com.owasp.common.repository;

import com.owasp.common.entity.FlashSale;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FlashSaleRepository extends JpaRepository<FlashSale, Long> {
    Optional<FlashSale> findByProductIdAndActiveTrue(Long productId);
    List<FlashSale> findByActiveTrue();
}
