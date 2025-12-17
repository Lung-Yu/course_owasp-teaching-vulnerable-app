package com.owasp.common.repository;

import com.owasp.common.entity.TransactionAuditTrail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * 交易審計追蹤 Repository
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 */
@Repository
public interface TransactionAuditTrailRepository extends JpaRepository<TransactionAuditTrail, Long> {

    Optional<TransactionAuditTrail> findByTransactionId(String transactionId);

    List<TransactionAuditTrail> findByUserId(Long userId);

    List<TransactionAuditTrail> findByTransactionType(String transactionType);

    List<TransactionAuditTrail> findByStatus(String status);

    List<TransactionAuditTrail> findByCorrelationId(String correlationId);

    List<TransactionAuditTrail> findByCreatedAtAfter(LocalDateTime since);

    List<TransactionAuditTrail> findByUserIdAndCreatedAtAfter(Long userId, LocalDateTime since);

    /**
     * 取得最後一筆交易（用於計算 hash chain）
     */
    @Query("SELECT t FROM TransactionAuditTrail t ORDER BY t.id DESC LIMIT 1")
    Optional<TransactionAuditTrail> findLastTransaction();

    /**
     * 取得使用者最後一筆交易
     */
    @Query("SELECT t FROM TransactionAuditTrail t WHERE t.userId = :userId ORDER BY t.id DESC LIMIT 1")
    Optional<TransactionAuditTrail> findLastTransactionByUserId(@Param("userId") Long userId);

    /**
     * 取得高額交易（用於警報）
     */
    @Query("SELECT t FROM TransactionAuditTrail t WHERE t.amount >= :threshold AND t.createdAt > :since")
    List<TransactionAuditTrail> findHighValueTransactions(
            @Param("threshold") BigDecimal threshold,
            @Param("since") LocalDateTime since);

    /**
     * 驗證 hash chain 完整性
     */
    @Query("SELECT t FROM TransactionAuditTrail t WHERE t.previousHash = :previousHash")
    Optional<TransactionAuditTrail> findByPreviousHash(@Param("previousHash") String previousHash);

    @Query("SELECT SUM(t.amount) FROM TransactionAuditTrail t WHERE t.userId = :userId AND t.transactionType = :type AND t.createdAt > :since")
    BigDecimal sumAmountByUserIdAndTypeSince(
            @Param("userId") Long userId,
            @Param("type") String type,
            @Param("since") LocalDateTime since);

    long countByStatus(String status);
}
