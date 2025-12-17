package com.owasp.common.repository;

import com.owasp.common.entity.Plugin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 插件 Repository
 */
@Repository
public interface PluginRepository extends JpaRepository<Plugin, Long> {

    Optional<Plugin> findByName(String name);

    List<Plugin> findByActiveTrue();

    List<Plugin> findByVerifiedTrue();

    List<Plugin> findByVerifiedFalse();

    boolean existsByName(String name);
}
