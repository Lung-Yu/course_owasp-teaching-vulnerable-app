package com.owasp.common.repository;

import com.owasp.common.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 登入嘗試記錄 Repository
 * 
 * A09:2021 - Security Logging and Monitoring Failures
 */
@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    List<LoginAttempt> findByUsername(String username);

    List<LoginAttempt> findBySourceIp(String sourceIp);

    List<LoginAttempt> findBySuccess(Boolean success);

    List<LoginAttempt> findByCreatedAtAfter(LocalDateTime since);

    List<LoginAttempt> findByUsernameAndCreatedAtAfter(String username, LocalDateTime since);

    List<LoginAttempt> findBySourceIpAndCreatedAtAfter(String sourceIp, LocalDateTime since);

    /**
     * 計算指定使用者在時間範圍內的失敗登入次數
     */
    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.username = :username AND l.success = false AND l.createdAt > :since")
    long countFailedAttemptsByUsernameSince(@Param("username") String username, @Param("since") LocalDateTime since);

    /**
     * 計算指定 IP 在時間範圍內的失敗登入次數
     */
    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.sourceIp = :sourceIp AND l.success = false AND l.createdAt > :since")
    long countFailedAttemptsByIpSince(@Param("sourceIp") String sourceIp, @Param("since") LocalDateTime since);

    /**
     * 取得指定時間範圍內的所有失敗登入
     */
    @Query("SELECT l FROM LoginAttempt l WHERE l.success = false AND l.createdAt > :since ORDER BY l.createdAt DESC")
    List<LoginAttempt> findRecentFailedAttempts(@Param("since") LocalDateTime since);

    /**
     * 取得可疑的 IP（多次失敗登入）
     */
    @Query("SELECT l.sourceIp, COUNT(l) as failCount FROM LoginAttempt l WHERE l.success = false AND l.createdAt > :since GROUP BY l.sourceIp HAVING COUNT(l) >= :threshold")
    List<Object[]> findSuspiciousIps(@Param("since") LocalDateTime since, @Param("threshold") long threshold);

    long countBySuccessTrue();

    long countBySuccessFalse();

    @Query("DELETE FROM LoginAttempt l WHERE l.expiresAt < :now")
    void deleteExpiredAttempts(@Param("now") LocalDateTime now);
}
