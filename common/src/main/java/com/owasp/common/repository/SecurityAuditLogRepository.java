package com.owasp.common.repository;

import com.owasp.common.entity.SecurityAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 安全審計日誌 Repository
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 */
@Repository
public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, Long> {

    List<SecurityAuditLog> findByCorrelationId(String correlationId);

    List<SecurityAuditLog> findByUserId(Long userId);

    List<SecurityAuditLog> findByUsername(String username);

    List<SecurityAuditLog> findByEventType(String eventType);

    List<SecurityAuditLog> findBySeverity(String severity);

    List<SecurityAuditLog> findBySourceIp(String sourceIp);

    List<SecurityAuditLog> findByCreatedAtAfter(LocalDateTime since);

    List<SecurityAuditLog> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    Page<SecurityAuditLog> findByEventType(String eventType, Pageable pageable);

    Page<SecurityAuditLog> findBySeverityIn(List<String> severities, Pageable pageable);

    @Query("SELECT s FROM SecurityAuditLog s WHERE s.eventType = :eventType AND s.outcome = :outcome AND s.createdAt > :since")
    List<SecurityAuditLog> findRecentByEventTypeAndOutcome(
            @Param("eventType") String eventType,
            @Param("outcome") String outcome,
            @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(s) FROM SecurityAuditLog s WHERE s.sourceIp = :sourceIp AND s.eventType = 'LOGIN' AND s.outcome = 'FAILURE' AND s.createdAt > :since")
    long countFailedLoginsByIpSince(@Param("sourceIp") String sourceIp, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(s) FROM SecurityAuditLog s WHERE s.username = :username AND s.eventType = 'LOGIN' AND s.outcome = 'FAILURE' AND s.createdAt > :since")
    long countFailedLoginsByUsernameSince(@Param("username") String username, @Param("since") LocalDateTime since);

    long countByEventType(String eventType);

    long countBySeverity(String severity);

    @Query("DELETE FROM SecurityAuditLog s WHERE s.expiresAt < :now")
    void deleteExpiredLogs(@Param("now") LocalDateTime now);
}
