package com.owasp.common.repository;

import com.owasp.common.entity.SoftwareUpdate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 軟體更新 Repository
 */
@Repository
public interface SoftwareUpdateRepository extends JpaRepository<SoftwareUpdate, Long> {

    List<SoftwareUpdate> findByComponentName(String componentName);

    Optional<SoftwareUpdate> findTopByComponentNameOrderByCreatedAtDesc(String componentName);

    List<SoftwareUpdate> findByVerifiedTrue();

    List<SoftwareUpdate> findByVerifiedFalse();

    List<SoftwareUpdate> findByAppliedAtIsNull();

    List<SoftwareUpdate> findByAppliedAtIsNotNull();
}
