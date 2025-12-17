package com.owasp.common.repository;

import com.owasp.common.entity.AdminActionLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 管理員操作日誌 Repository
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 */
@Repository
public interface AdminActionLogRepository extends JpaRepository<AdminActionLog, Long> {

    List<AdminActionLog> findByAdminUserId(Long adminUserId);

    List<AdminActionLog> findByAdminUsername(String adminUsername);

    List<AdminActionLog> findByActionType(String actionType);

    List<AdminActionLog> findByTargetEntity(String targetEntity);

    List<AdminActionLog> findByTargetEntityAndTargetId(String targetEntity, String targetId);

    List<AdminActionLog> findByCorrelationId(String correlationId);

    List<AdminActionLog> findByCreatedAtAfter(LocalDateTime since);

    Page<AdminActionLog> findByAdminUserId(Long adminUserId, Pageable pageable);

    Page<AdminActionLog> findByActionType(String actionType, Pageable pageable);

    /**
     * 取得非工作時間的管理員操作（可疑活動偵測）
     * 假設工作時間為 9:00-18:00
     */
    @Query("SELECT a FROM AdminActionLog a WHERE a.createdAt > :since AND (EXTRACT(HOUR FROM a.createdAt) < 9 OR EXTRACT(HOUR FROM a.createdAt) >= 18)")
    List<AdminActionLog> findAfterHoursActions(@Param("since") LocalDateTime since);

    /**
     * 取得敏感操作（如角色變更、使用者刪除）
     */
    @Query("SELECT a FROM AdminActionLog a WHERE a.actionType IN :sensitiveActions AND a.createdAt > :since")
    List<AdminActionLog> findSensitiveActions(
            @Param("sensitiveActions") List<String> sensitiveActions,
            @Param("since") LocalDateTime since);

    /**
     * 統計各管理員的操作次數
     */
    @Query("SELECT a.adminUsername, COUNT(a) FROM AdminActionLog a WHERE a.createdAt > :since GROUP BY a.adminUsername")
    List<Object[]> countActionsByAdmin(@Param("since") LocalDateTime since);

    long countByActionType(String actionType);

    @Query("DELETE FROM AdminActionLog a WHERE a.expiresAt < :now")
    void deleteExpiredLogs(@Param("now") LocalDateTime now);
}
