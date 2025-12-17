package com.owasp.common.repository;

import com.owasp.common.entity.SecurityAlert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 安全警報 Repository
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 */
@Repository
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

    List<SecurityAlert> findByAlertType(String alertType);

    List<SecurityAlert> findBySeverity(String severity);

    List<SecurityAlert> findByAcknowledged(Boolean acknowledged);

    List<SecurityAlert> findByResolved(Boolean resolved);

    List<SecurityAlert> findByAffectedUserId(Long affectedUserId);

    List<SecurityAlert> findBySourceIp(String sourceIp);

    List<SecurityAlert> findByCorrelationId(String correlationId);

    List<SecurityAlert> findByCreatedAtAfter(LocalDateTime since);

    /**
     * 取得未確認的警報（用於輪詢）
     */
    List<SecurityAlert> findByAcknowledgedFalseOrderByCreatedAtDesc();

    /**
     * 取得未解決的警報
     */
    List<SecurityAlert> findByResolvedFalseOrderBySeverityDescCreatedAtDesc();

    /**
     * 取得特定嚴重程度以上的未確認警報
     */
    @Query("SELECT a FROM SecurityAlert a WHERE a.acknowledged = false AND a.severity IN :severities ORDER BY a.createdAt DESC")
    List<SecurityAlert> findUnacknowledgedBySeverities(@Param("severities") List<String> severities);

    /**
     * 分頁取得警報
     */
    Page<SecurityAlert> findByAcknowledged(Boolean acknowledged, Pageable pageable);

    Page<SecurityAlert> findBySeverityIn(List<String> severities, Pageable pageable);

    /**
     * 統計各類型警報數量
     */
    @Query("SELECT a.alertType, COUNT(a) FROM SecurityAlert a WHERE a.createdAt > :since GROUP BY a.alertType")
    List<Object[]> countByAlertTypeSince(@Param("since") LocalDateTime since);

    /**
     * 統計各嚴重程度警報數量
     */
    @Query("SELECT a.severity, COUNT(a) FROM SecurityAlert a WHERE a.createdAt > :since GROUP BY a.severity")
    List<Object[]> countBySeveritySince(@Param("since") LocalDateTime since);

    long countByAcknowledgedFalse();

    long countByResolvedFalse();

    long countBySeverityAndAcknowledgedFalse(String severity);

    @Query("DELETE FROM SecurityAlert a WHERE a.expiresAt < :now")
    void deleteExpiredAlerts(@Param("now") LocalDateTime now);
}
