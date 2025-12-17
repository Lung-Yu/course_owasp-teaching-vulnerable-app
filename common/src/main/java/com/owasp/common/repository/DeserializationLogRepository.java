package com.owasp.common.repository;

import com.owasp.common.entity.DeserializationLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 反序列化審計日誌 Repository
 */
@Repository
public interface DeserializationLogRepository extends JpaRepository<DeserializationLog, Long> {

    List<DeserializationLog> findBySessionId(String sessionId);

    List<DeserializationLog> findByBlockedTrue();

    List<DeserializationLog> findByBlockedFalse();

    List<DeserializationLog> findBySourceIp(String sourceIp);

    List<DeserializationLog> findByCreatedAtAfter(LocalDateTime since);

    long countByBlockedTrue();

    long countByBlockedFalse();
}
